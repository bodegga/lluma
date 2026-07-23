//! Host side of the reverse tunnel (spec §Track 1): dial an OUTBOUND WebSocket
//! to the broker, authenticate, then serve `Job` frames the broker pushes down
//! it — no inbound port, so a NAT-bound host can contribute.
//!
//! The job loop reuses [`crate::serve_sealed`], so tunnel serving and dial-in
//! serving share one crypto path (open with aad = spend_id → upstream → seal to
//! the client session key). Jobs run concurrently (one task each), responses go
//! back over a single writer task, correlated by `request_id`.
//!
//! Transport: `wss://` in production (TLS via `rustls-tls-webpki-roots`); the
//! broker verifies the host's identity in the handshake, and the host trusts the
//! broker via WebPKI against the bootstrap-signed hostname (item C). `ws://` is
//! for the loopback test only.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use lluma_core::proto::v1::TunnelFrame;
use lluma_core::wire::{AccountSecretKey, HostSecretKey};

use crate::Upstream;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Everything needed to dial and authenticate the tunnel.
pub struct TunnelConfig {
    /// `ws(s)://<broker>/v1/host/tunnel`.
    pub url: String,
    /// This host's Ed25519 public key (the registry `host_account`).
    pub host_account: [u8; 32],
    /// This host's Ed25519 account secret key (signs the auth challenge).
    pub account_sk: AccountSecretKey,
    /// The broker's registry public key, bound into the auth signature. The host
    /// knows this from the signed bootstrap.
    pub broker_key_id: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub enum TunnelError {
    /// Could not establish the WebSocket connection.
    Connect,
    /// Handshake failed (bad/again unexpected frame, or auth rejected).
    Auth,
    /// A protocol/framing error on an established connection.
    Protocol,
    /// Local signing failure.
    Sign,
}

const WRITER_QUEUE: usize = 64;
/// Bound the whole auth handshake so a stalled peer can't park the host (I4).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// If no frame arrives within this window the connection is treated as dead and
/// the host reconnects. The broker pings every 20 s, so inbound silence past
/// ~2 intervals is a reliable death signal (review I4).
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Cap inbound frames (defense in depth; the broker is authenticated in prod).
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Serve a SINGLE tunnel connection: dial, authenticate, then process `Job`
/// frames until the socket closes or errors. Returns `Ok(())` on a clean close.
/// Tests call this directly; the long-running host wraps it in [`run`].
pub async fn serve_once(
    cfg: &TunnelConfig,
    host_sk: Arc<HostSecretKey>,
    upstream: Arc<dyn Upstream>,
) -> Result<(), TunnelError> {
    // Cap inbound message size (review M4); the broker never sends larger.
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..Default::default()
    };
    let (mut ws, _resp) = tokio_tungstenite::connect_async_with_config(&cfg.url, Some(ws_config), false)
        .await
        .map_err(|_| TunnelError::Connect)?;

    // Handshake: Hello → Challenge → Auth → AuthOk, bounded so a stalled peer
    // can't park the host forever (review I4).
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        ws_send(&mut ws, &TunnelFrame::Hello { v: 1, host_account: cfg.host_account }).await?;
        let challenge = match ws_recv(&mut ws).await? {
            TunnelFrame::Challenge { v: 1, challenge } => challenge,
            _ => return Err(TunnelError::Auth),
        };
        let sig = lluma_crypto::account::tunnel_auth_sign(
            &cfg.account_sk,
            &challenge,
            &cfg.host_account,
            &cfg.broker_key_id,
        )
        .map_err(|_| TunnelError::Sign)?;
        ws_send(&mut ws, &TunnelFrame::Auth { v: 1, sig: sig.0 }).await?;
        match ws_recv(&mut ws).await? {
            TunnelFrame::AuthOk { v: 1 } => Ok(()),
            _ => Err(TunnelError::Auth),
        }
    })
    .await
    .map_err(|_| TunnelError::Auth)??;

    // Split: a single writer task owns the sink; job workers and ping-pong feed
    // it through a bounded channel so concurrent responses can't interleave on
    // the wire.
    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<WsMessage>(WRITER_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    loop {
        // Idle read timeout: inbound silence past the broker's ping cadence means
        // a silently-dead path — break so `run()` reconnects (review I4).
        let msg = match tokio::time::timeout(READ_IDLE_TIMEOUT, stream.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => break, // closed, errored, or idle-timed-out
        };
        match msg {
            // Serve a Job (ignore unknown / wrong-direction / bad-version frames).
            WsMessage::Text(t) => {
                if let Ok(TunnelFrame::Job { v: 1, request_id, spend_id, sealed }) =
                    serde_json::from_str::<TunnelFrame>(t.as_str())
                {
                    let host_sk = host_sk.clone();
                    let upstream = upstream.clone();
                    let out_tx = out_tx.clone();
                    // One task per job so a slow model doesn't stall the socket.
                    tokio::spawn(async move {
                        let frame = match crate::serve_sealed(
                            &host_sk,
                            &spend_id,
                            &sealed,
                            upstream.as_ref(),
                        )
                        .await
                        {
                            Ok(resp) => TunnelFrame::Done {
                                v: 1,
                                request_id,
                                preamble: resp.preamble,
                                chunk: resp.chunk,
                            },
                            Err(_) => TunnelFrame::Fail { v: 1, request_id },
                        };
                        if let Ok(text) = serde_json::to_string(&frame) {
                            let _ = out_tx.send(WsMessage::text(text)).await;
                        }
                    });
                }
            }
            // Reply to pings so the broker's liveness check passes.
            WsMessage::Ping(p) => {
                let _ = out_tx.send(WsMessage::Pong(p)).await;
            }
            WsMessage::Close(_) => break,
            _ => {}
        }
    }

    writer.abort();
    Ok(())
}

/// Long-running host tunnel: reconnect forever with a capped, jittered backoff.
/// Never returns (the host bin spawns/awaits it).
pub async fn run(cfg: TunnelConfig, host_sk: Arc<HostSecretKey>, upstream: Arc<dyn Upstream>) {
    let mut backoff_s: u64 = 1;
    loop {
        // A clean close ⇒ reconnect promptly; an error ⇒ keep the current backoff.
        if serve_once(&cfg, host_sk.clone(), upstream.clone()).await.is_ok() {
            backoff_s = 1;
        }
        // Jitter (0–999 ms) so a broker restart doesn't cause a thundering herd.
        let jitter = (rand_core::RngCore::next_u32(&mut rand_core::OsRng) % 1000) as u64;
        tokio::time::sleep(Duration::from_millis(backoff_s * 1000 + jitter)).await;
        backoff_s = (backoff_s * 2).min(30);
    }
}

async fn ws_send(ws: &mut Ws, frame: &TunnelFrame) -> Result<(), TunnelError> {
    let s = serde_json::to_string(frame).map_err(|_| TunnelError::Protocol)?;
    ws.send(WsMessage::text(s)).await.map_err(|_| TunnelError::Protocol)
}

/// Receive the next JSON frame, skipping ping/pong. Non-text / close / error
/// yields `Protocol`.
async fn ws_recv(ws: &mut Ws) -> Result<TunnelFrame, TunnelError> {
    loop {
        match ws.next().await {
            Some(Ok(WsMessage::Text(t))) => {
                return serde_json::from_str(t.as_str()).map_err(|_| TunnelError::Protocol)
            }
            Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
            _ => return Err(TunnelError::Protocol),
        }
    }
}
