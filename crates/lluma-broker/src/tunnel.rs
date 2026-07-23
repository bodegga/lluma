//! Reverse-tunnel WebSocket server (spec §Track 1). A NAT-bound host holds an
//! OUTBOUND WebSocket to the broker; the broker pushes exec `Job` frames down it
//! and reads sealed `Done`/`Fail` responses back, correlated by `request_id`.
//! The host never accepts an inbound connection.
//!
//! Controller-authored (security-critical). Crypto-architect must-haves, folded
//! in verbatim:
//!  1. **TLS is the deployment's job** (Caddy terminates wss → this ws endpoint).
//!     Plain ws is hijackable after auth, so this must ONLY be exposed behind TLS
//!     (item C); the code speaks ws.
//!  2. **Auth handshake:** `Hello{host_account}` → broker `Challenge{32B OsRng,
//!     single-use, 5 s}` → host `Auth{sig}` where `sig = Ed25519(account_sk,
//!     TUNNEL_AUTH_DOMAIN ‖ challenge ‖ host_account ‖ broker_key_id)`.
//!     `host_account` IS the Ed25519 public key (registry convention), so it
//!     doubles as the verify key. **Uniform failure — the handshake never
//!     consults the registry, so it leaks no registration-status oracle.**
//!     Socket replacement happens ONLY after a successful auth.
//!  3. **Liveness + in-flight capacity are checked BEFORE the spend txn** (see
//!     `reserve_tunnel`): a dead/at-capacity socket yields `no_host` without
//!     burning a token. No automatic retry (dial-in parity).
//!  4. **Bounds:** 5 s pre-auth deadline; ≤1 KiB handshake frames; frame length
//!     caps before parse; one socket per account (atomic generation swap, old
//!     socket's in-flight jobs fail immediately); global socket cap; per-socket
//!     in-flight cap → `no_host` before spend; 30 s per-request timeout; ws ping
//!     20 s, drop after 2 missed; bounded send queue.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use rand_core::RngCore;
use tokio::sync::{mpsc, oneshot, Semaphore};

use lluma_core::proto::v1::{ExecResponse, TunnelFrame};
use lluma_core::wire::{AccountPublicKey, ReceiptSignature, SealedRequest, SpendId};

use crate::error::BrokerError;
use crate::service::BrokerState;
use crate::store::{Store, HOSTS};

/// Reserved `ingress_addr` a tunnel-mode host registers instead of a public
/// address (`.invalid` is RFC 2606-reserved, so it can never resolve/dial). When
/// a host with this sentinel has no live socket, exec returns `no_host` BEFORE
/// spending rather than burning a token dialing a bogus address (review I1).
pub const TUNNEL_SENTINEL_ADDR: &str = "https://tunnel.invalid";

/// The ws endpoint path (served on the ingress listener, behind TLS in prod).
pub const TUNNEL_PATH: &str = "/v1/host/tunnel";

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const MAX_HANDSHAKE_BYTES: usize = 1024;
/// Job/Done carry a base64 `sealed`/`chunk` up to `MAX_SEALED_LEN` (1 MiB) plus
/// preamble/framing → cap the on-wire text frame at ~2 MiB before parsing.
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const MAX_MISSED_PONGS: u8 = 2;
const MAX_INFLIGHT_PER_SOCKET: usize = 16;
const MAX_SOCKETS: usize = 4096;
const SEND_QUEUE: usize = 64;
/// Concurrency cap on unauthenticated handshakes in flight (review I2). Bounds
/// how many connections can be buffering/parsing pre-auth at once; per-IP rate
/// limiting is delegated to the fronting proxy (item C, in the deploy runbook).
const MAX_PREAUTH_HANDSHAKES: usize = 256;

/// One live host socket. The reader loop delivers `Done`/`Fail` to the matching
/// `pending` oneshot; the writer task drains `job_rx` and emits pings.
pub struct HostSocket {
    generation: u64,
    job_tx: mpsc::Sender<Message>,
    pending: Mutex<HashMap<u64, oneshot::Sender<ExecResponse>>>,
    inflight: AtomicUsize,
    next_request_id: AtomicU64,
}

impl HostSocket {
    /// Reserve one in-flight slot iff below the per-socket cap (atomic CAS loop).
    fn try_reserve(&self) -> bool {
        let mut cur = self.inflight.load(Ordering::Acquire);
        loop {
            if cur >= MAX_INFLIGHT_PER_SOCKET {
                return false;
            }
            match self.inflight.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self) {
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }

    /// Fail every outstanding request (socket died / was replaced): dropping the
    /// senders resolves each waiter's `rx` to `Err`, so `dispatch` returns a
    /// gateway error rather than hanging until timeout.
    fn fail_all_pending(&self) {
        if let Ok(mut p) = self.pending.lock() {
            p.clear();
        }
    }
}

/// Per-account live-socket directory.
pub struct TunnelRegistry {
    sockets: Mutex<HashMap<[u8; 32], Arc<HostSocket>>>,
    next_generation: AtomicU64,
    /// Bounds concurrent unauthenticated handshakes (review I2).
    handshake_permits: Semaphore,
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sockets: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(0),
            handshake_permits: Semaphore::new(MAX_PREAUTH_HANDSHAKES),
        })
    }

    fn next_generation(&self) -> u64 {
        self.next_generation.fetch_add(1, Ordering::Relaxed)
    }

    fn get(&self, account: &[u8; 32]) -> Option<Arc<HostSocket>> {
        self.sockets.lock().ok()?.get(account).cloned()
    }

    /// Insert (replacing any existing socket for this account). Enforces the
    /// global socket cap for NEW accounts. Returns the replaced socket, if any,
    /// so the caller can fail its in-flight jobs.
    fn insert(
        &self,
        account: [u8; 32],
        sock: Arc<HostSocket>,
    ) -> Result<Option<Arc<HostSocket>>, ()> {
        let mut m = self.sockets.lock().map_err(|_| ())?;
        if !m.contains_key(&account) && m.len() >= MAX_SOCKETS {
            return Err(());
        }
        Ok(m.insert(account, sock))
    }

    /// Remove the account's socket iff it is still the given generation (so a
    /// reconnect that already replaced us is not clobbered on our teardown).
    fn remove_if_current(&self, account: &[u8; 32], generation: u64) {
        if let Ok(mut m) = self.sockets.lock() {
            if m.get(account).map(|s| s.generation) == Some(generation) {
                m.remove(account);
            }
        }
    }

    /// Number of live host sockets (observability + tests). Shipped (not
    /// `#[cfg(test)]`) so integration tests in `tests/` can observe it.
    pub fn socket_count(&self) -> usize {
        self.sockets.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Outcome of trying to route an exec to a tunnel, decided BEFORE any spend.
pub enum Reservation {
    /// No live tunnel socket for this account — the caller should dial-in.
    NoSocket,
    /// A live socket exists but is at its in-flight cap — return `no_host`
    /// WITHOUT spending (do not dial the vestigial address of a tunnel host).
    AtCapacity,
    /// A slot is reserved; hold this guard across the spend + dispatch.
    Reserved(InflightGuard),
}

/// RAII in-flight reservation: releases the slot on drop, so every exec exit
/// path (spend failure, timeout, success) frees capacity exactly once.
pub struct InflightGuard(Arc<HostSocket>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Try to reserve tunnel capacity for `account` (must-have 3: before the spend).
pub fn reserve_tunnel(reg: &TunnelRegistry, account: &[u8; 32]) -> Reservation {
    match reg.get(account) {
        None => Reservation::NoSocket,
        Some(sock) => {
            // A socket whose writer channel is closed is effectively dead; treat
            // it as absent so the caller falls back to dial-in rather than
            // spending into a corpse.
            if sock.job_tx.is_closed() {
                return Reservation::NoSocket;
            }
            if sock.try_reserve() {
                Reservation::Reserved(InflightGuard(sock))
            } else {
                Reservation::AtCapacity
            }
        }
    }
}

/// Push a `Job` down the reserved socket and await its sealed response, bounded
/// by `REQUEST_TIMEOUT`. The reservation is released when `guard` drops.
pub async fn dispatch(
    guard: &InflightGuard,
    spend_id: SpendId,
    sealed: SealedRequest,
) -> Result<ExecResponse, ()> {
    let sock = &guard.0;
    let request_id = sock.next_request_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel::<ExecResponse>();
    {
        let mut p = sock.pending.lock().map_err(|_| ())?;
        p.insert(request_id, tx);
    }
    let job = TunnelFrame::Job { v: 1, request_id, spend_id, sealed };
    let text = serde_json::to_string(&job).map_err(|_| ())?;
    if sock.job_tx.send(Message::Text(text)).await.is_err() {
        if let Ok(mut p) = sock.pending.lock() {
            p.remove(&request_id);
        }
        return Err(());
    }
    match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
        Ok(Ok(resp)) => Ok(resp),
        _ => {
            // Timeout or the socket dropped the sender — drop the pending entry.
            if let Ok(mut p) = sock.pending.lock() {
                p.remove(&request_id);
            }
            Err(())
        }
    }
}

/// axum handler: upgrade the request and run the per-socket lifecycle.
pub async fn tunnel_ws(ws: WebSocketUpgrade, State(st): State<BrokerState>) -> Response {
    ws.max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, st))
}

async fn handle_socket(mut socket: WebSocket, st: BrokerState) {
    // Bound concurrent unauthenticated handshakes (review I2). The permit is held
    // only for the (deadline-bounded) handshake, then released before serving.
    let permit = match st.tunnels.handshake_permits.acquire().await {
        Ok(p) => p,
        Err(_) => return,
    };
    // Auth + authorization under a hard deadline (must-have 2 + 4; review C1).
    let host_account =
        match tokio::time::timeout(HANDSHAKE_DEADLINE, handshake(&mut socket, &st)).await {
            Ok(Some(acct)) => acct,
            _ => return, // uniform failure: just close, no distinguishing response
        };
    drop(permit); // authenticated — free the pre-auth slot

    let (job_tx, mut job_rx) = mpsc::channel::<Message>(SEND_QUEUE);
    let generation = st.tunnels.next_generation();
    let sock = Arc::new(HostSocket {
        generation,
        job_tx,
        pending: Mutex::new(HashMap::new()),
        inflight: AtomicUsize::new(0),
        next_request_id: AtomicU64::new(0),
    });
    // Register BEFORE confirming (review M2): one socket per account; a replaced
    // socket's in-flight jobs fail at once. A cap-full insert closes WITHOUT an
    // AuthOk, so the host reads it as a rejection rather than a clean close.
    match st.tunnels.insert(host_account, sock.clone()) {
        Ok(Some(old)) => old.fail_all_pending(),
        Ok(None) => {}
        Err(()) => return, // global socket cap reached — drop this connection
    }
    // Only now confirm the handshake to the host.
    if send_frame(&mut socket, &TunnelFrame::AuthOk { v: 1 }).await.is_none() {
        st.tunnels.remove_if_current(&host_account, generation);
        sock.fail_all_pending();
        return;
    }
    tracing::info!("tunnel socket registered ({} live)", st.tunnels.socket_count());

    let (mut ws_sink, mut ws_stream) = socket.split();
    let missed = Arc::new(AtomicU8::new(0));

    // Writer task: forward queued Job frames and emit periodic pings. A ping tick
    // that finds MAX_MISSED_PONGS unacknowledged tears the socket down.
    let missed_w = missed.clone();
    let mut writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                frame = job_rx.recv() => match frame {
                    Some(msg) => {
                        if ws_sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    // Drop only after MAX_MISSED_PONGS unanswered pings (review I3).
                    if missed_w.fetch_add(1, Ordering::AcqRel) >= MAX_MISSED_PONGS {
                        break;
                    }
                    if ws_sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_sink.close().await;
    });

    // Reader loop: deliver Done/Fail to waiters; any inbound frame clears the
    // missed-pong counter (proof of life). Also stop if the writer task ended
    // (missed-pong teardown) so the reader can't zombie on a half-dead socket
    // (review M1).
    loop {
        let msg = tokio::select! {
            m = ws_stream.next() => match m {
                Some(Ok(m)) => m,
                _ => break,
            },
            _ = &mut writer => break,
        };
        missed.store(0, Ordering::Release);
        match msg {
            Message::Text(s) => {
                if s.len() > MAX_FRAME_BYTES {
                    break;
                }
                match serde_json::from_str::<TunnelFrame>(&s) {
                    Ok(TunnelFrame::Done { v: 1, request_id, preamble, chunk }) => {
                        // Enforce the response size bound before delivering (M3):
                        // an oversize/empty chunk is treated as a failure.
                        let resp = ExecResponse { preamble, chunk };
                        deliver(&sock, request_id, resp.validate().is_ok().then_some(resp));
                    }
                    Ok(TunnelFrame::Fail { v: 1, request_id }) => {
                        deliver(&sock, request_id, None);
                    }
                    // Unknown / wrong-direction / bad-version frames are ignored.
                    _ => {}
                }
            }
            Message::Close(_) => break,
            // Ping/Pong/Binary: liveness only (Binary is unused by our protocol).
            _ => {}
        }
    }

    // Teardown: stop the writer, unregister (iff still ours), fail outstanding.
    writer.abort();
    st.tunnels.remove_if_current(&host_account, generation);
    sock.fail_all_pending();
}

/// Resolve `request_id` to its waiter and hand it the outcome. `Some` = a sealed
/// `Done`; `None` = a `Fail` (waiter gets `Err` because the sender is dropped).
fn deliver(sock: &HostSocket, request_id: u64, resp: Option<ExecResponse>) {
    let tx = sock.pending.lock().ok().and_then(|mut p| p.remove(&request_id));
    if let (Some(tx), Some(resp)) = (tx, resp) {
        let _ = tx.send(resp);
    }
    // For `Fail` (resp = None) we simply drop the sender ⇒ waiter sees Err.
}

/// Run the auth handshake. Returns the bound `host_account` (its Ed25519 public
/// key) on success. Every failure returns `None` with no distinguishing reply.
async fn handshake(socket: &mut WebSocket, st: &BrokerState) -> Option<[u8; 32]> {
    let host_account = match recv_frame(socket, MAX_HANDSHAKE_BYTES).await? {
        TunnelFrame::Hello { v: 1, host_account } => host_account,
        _ => return None,
    };
    let mut challenge = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut challenge);
    send_frame(socket, &TunnelFrame::Challenge { v: 1, challenge }).await?;
    let sig = match recv_frame(socket, MAX_HANDSHAKE_BYTES).await? {
        TunnelFrame::Auth { v: 1, sig } => sig,
        _ => return None,
    };
    // host_account IS the verify key. broker_key_id = the broker's registry pk.
    let pk = AccountPublicKey(host_account.to_vec());
    let sig = ReceiptSignature(sig);
    lluma_crypto::account::tunnel_auth_verify(
        &pk,
        &challenge,
        &host_account,
        &st.registry_pk,
        &sig,
    )
    .ok()?;
    // Authorization (review C1): the account must already be registered
    // (registration is PoW-gated), else close uniformly. This check is POST-auth,
    // so it leaks no registration-status oracle — only the key owner, who already
    // knows their own status, can reach this branch. Bounds socket-table
    // squatting to the cost of a registration PoW per account.
    if !account_registered(&st.store, &host_account) {
        return None;
    }
    // NOTE: `AuthOk` is sent by the caller AFTER a successful socket insert (M2),
    // so a cap-full connection is closed rather than falsely confirmed.
    Some(host_account)
}

/// True if `account` has a registry entry (registration is PoW-gated). Fails
/// closed (treats a storage error as "not registered").
fn account_registered(store: &Store, account: &[u8; 32]) -> bool {
    store
        .with_read(|r| {
            let t = r.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            Ok(t.get(&account[..]).map_err(|_| BrokerError::Storage)?.is_some())
        })
        .unwrap_or(false)
}

/// Receive one JSON text frame ≤ `max` bytes, skipping ping/pong. Any protocol
/// error, oversize frame, non-text frame, or close yields `None`.
async fn recv_frame(socket: &mut WebSocket, max: usize) -> Option<TunnelFrame> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(s))) => {
                if s.len() > max {
                    return None;
                }
                return serde_json::from_str(&s).ok();
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            _ => return None,
        }
    }
}

async fn send_frame(socket: &mut WebSocket, frame: &TunnelFrame) -> Option<()> {
    let text = serde_json::to_string(frame).ok()?;
    socket.send(Message::Text(text)).await.ok()
}
