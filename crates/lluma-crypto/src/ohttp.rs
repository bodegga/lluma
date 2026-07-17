//! Oblivious HTTP (RFC 9458) encapsulation — the "outer" relay hop. A client
//! encapsulates a request to the gateway's public OHTTP key config; the
//! gateway decapsulates with its secret, and the single-chunk sealed response
//! carries a 1-byte finality flag INSIDE the AEAD-authenticated plaintext (same
//! discipline as `e2e.rs`) so a dropped/truncated final chunk can never be read
//! as complete and a tampered flag fails the tag check rather than silently
//! succeeding. Single-chunk MVP per spec §4; multi-chunk (chunked-OHTTP draft)
//! is deferred.
//!
//! API note (ohttp 0.5.4): `KeyConfig::encode()` is a *public-only* encoding and
//! `KeyConfig::decode()` drops the private key, so the gateway secret cannot
//! round-trip through encode/decode. There is also no `private_key_bytes` API.
//! We therefore deterministically derive the KEM keypair from a random IKM via
//! `KeyConfig::derive` (HPKE `DeriveKeyPair`) and store the IKM as the gateway
//! secret; `ohttp_decapsulate` re-derives the identical keypair. The public
//! `OhttpKeyConfig` carries only the client-facing encoded config.
use crate::error::{CryptoError, Result};
use lluma_core::wire::{EncapsulatedRequest, GatewaySecretKey, OhttpKeyConfig};
use ohttp::{
    hpke::{Aead as OAead, Kdf as OKdf, Kem as OKem},
    ClientRequest, KeyConfig, Server as OhttpServer, SymmetricSuite,
};

/// The client's side of an OHTTP response. Holds the one-shot
/// `ohttp::ClientResponse` produced by `ohttp_encapsulate` and consumed by the
/// first `ohttp_open_chunk`.
pub struct ClientResponseContext {
    inner: Option<ohttp::ClientResponse>,
}

/// The gateway's side of an OHTTP response. Holds the one-shot
/// `ohttp::ServerResponse` produced by `ohttp_decapsulate` and consumed by the
/// first `ohttp_seal_chunk`.
pub struct ServerResponseContext {
    inner: Option<ohttp::ServerResponse>,
}

/// Bytes of input keying material used to deterministically derive the
/// gateway KEM keypair via HPKE `DeriveKeyPair`. The IKM IS the gateway secret:
/// whoever holds it can derive the private key and decapsulate.
const IKM_LEN: usize = 32;

/// Maps an `ohttp` library error onto `CryptoError`: AEAD/HPKE authentication
/// failures (tamper, wrong key) become `AuthFailed`; short input becomes
/// `Truncated`; everything else is surfaced as `Ohttp(_)`.
fn map_ohttp_err(e: ohttp::Error) -> CryptoError {
    match e {
        ohttp::Error::Truncated => CryptoError::Truncated,
        ohttp::Error::Aead(_) | ohttp::Error::Hpke(_) => CryptoError::AuthFailed,
        other => CryptoError::Ohttp(other.to_string()),
    }
}

/// Generate an OHTTP key pair for the gateway. The secret returned in
/// `GatewaySecretKey` is `key_id || ikm`; the public `OhttpKeyConfig` is the
/// client-facing encoded key config (RFC 9458 `application/ohttp-keys`).
///
/// The `ohttp` crate exposes no way to serialize a `KeyConfig` *with* its
/// private key (`encode()` is public-only and `decode()` drops the secret,
/// which would make `Server::new` panic). So the KEM keypair is deterministically
/// derived from a random IKM (`KeyConfig::derive`, HPKE `DeriveKeyPair`) and the
/// IKM is stored; `ohttp_decapsulate` re-derives the identical keypair.
pub fn ohttp_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    key_id: u8,
) -> Result<(GatewaySecretKey, OhttpKeyConfig)> {
    let suite = SymmetricSuite::new(OKdf::HkdfSha256, OAead::ChaCha20Poly1305);
    let mut ikm = vec![0u8; IKM_LEN];
    rng.fill_bytes(&mut ikm);

    let cfg = KeyConfig::derive(key_id, OKem::X25519Sha256, vec![suite], &ikm)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let public = cfg
        .encode()
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;

    let mut secret = Vec::with_capacity(1 + IKM_LEN);
    secret.push(key_id);
    secret.extend_from_slice(&ikm);
    Ok((GatewaySecretKey(secret), OhttpKeyConfig(public)))
}

/// Encapsulate a request to the gateway's public key config. Returns the binary
/// capsule (ready to POST to the relay) and a `ClientResponseContext` for
/// opening the eventual sealed response.
///
/// Note: the `ohttp` crate draws the HPKE encapsulation randomness from its own
/// internal `thread_rng`, so the caller-provided `rng` is unused here; it is
/// retained in the signature for API stability and forward-compat with a
/// multi-chunk/forked variant.
pub fn ohttp_encapsulate(
    _rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    cfg: &OhttpKeyConfig,
    request: &[u8],
) -> Result<(EncapsulatedRequest, ClientResponseContext)> {
    let client = ClientRequest::from_encoded_config(&cfg.0)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let (capsule, response_ctx) = client
        .encapsulate(request)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    Ok((
        EncapsulatedRequest(capsule),
        ClientResponseContext {
            inner: Some(response_ctx),
        },
    ))
}

/// Decapsulate a request capsule at the gateway. Re-derives the gateway KEM
/// keypair from the IKM stored in `GatewaySecretKey` (`key_id || ikm`), builds
/// the `ohttp::Server`, and opens the capsule. Any tamper, wrong key, or
/// truncation fails closed (`AuthFailed`/`Truncated`), never partially decrypts.
pub fn ohttp_decapsulate(
    sk: &GatewaySecretKey,
    capsule: &EncapsulatedRequest,
) -> Result<(Vec<u8>, ServerResponseContext)> {
    let bytes = sk.as_ref();
    if bytes.len() < 1 + IKM_LEN {
        return Err(CryptoError::Truncated);
    }
    let key_id = bytes[0];
    let ikm = &bytes[1..1 + IKM_LEN];

    let suite = SymmetricSuite::new(OKdf::HkdfSha256, OAead::ChaCha20Poly1305);
    let cfg = KeyConfig::derive(key_id, OKem::X25519Sha256, vec![suite], ikm)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let server = OhttpServer::new(cfg).map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let (inner, server_response) = server
        .decapsulate(capsule.as_ref())
        .map_err(map_ohttp_err)?;
    Ok((
        inner,
        ServerResponseContext {
            inner: Some(server_response),
        },
    ))
}

/// Seal one response chunk for the single-chunk MVP. The 1-byte finality flag
/// (`last`) is placed as the FIRST byte of the OHTTP response plaintext, so
/// `ohttp`'s own AEAD authenticates it end-to-end: flipping it (e.g. to forge
/// completion on a truncated stream) fails the tag check on open rather than
/// silently succeeding. This consumes the one-shot `ServerResponseContext`.
pub fn ohttp_seal_chunk(
    ctx: &mut ServerResponseContext,
    chunk: &[u8],
    last: bool,
) -> Result<Vec<u8>> {
    let sr = ctx
        .inner
        .take()
        .ok_or_else(|| CryptoError::Ohttp("response already sealed".into()))?;
    let mut framed = Vec::with_capacity(chunk.len() + 1);
    framed.push(last as u8);
    framed.extend_from_slice(chunk);
    sr.encapsulate(&framed).map_err(map_ohttp_err)
}

/// Open one response chunk, returning the plaintext and the authenticated
/// finality flag. A tampered or truncated response fails closed
/// (`AuthFailed`/`Truncated`); an empty decoded body (no finality byte) is
/// `Truncated`. This consumes the one-shot `ClientResponseContext`.
pub fn ohttp_open_chunk(ctx: &mut ClientResponseContext, chunk: &[u8]) -> Result<(Vec<u8>, bool)> {
    let cr = ctx
        .inner
        .take()
        .ok_or_else(|| CryptoError::Ohttp("response already opened".into()))?;
    let framed = cr.decapsulate(chunk).map_err(map_ohttp_err)?;
    if framed.is_empty() {
        return Err(CryptoError::Truncated);
    }
    Ok((framed[1..].to_vec(), framed[0] == 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn encapsulate_decapsulate_round_trip() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, _cctx) =
            ohttp_encapsulate(&mut rng, &cfg, b"inner ciphertext bytes").unwrap();
        let (inner, _sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        assert_eq!(inner, b"inner ciphertext bytes");
    }

    #[test]
    fn response_single_chunk_round_trip() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, mut cctx) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let (_inner, mut sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        let sealed = ohttp_seal_chunk(&mut sctx, b"response body", true).unwrap();
        let (pt, is_final) = ohttp_open_chunk(&mut cctx, &sealed).unwrap();
        assert_eq!(pt, b"response body");
        assert!(is_final);
    }

    #[test]
    fn dropped_final_chunk_never_reads_complete() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, mut cctx) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let (_inner, mut sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        let sealed = ohttp_seal_chunk(&mut sctx, b"body", false).unwrap(); // not final
        let (_pt, is_final) = ohttp_open_chunk(&mut cctx, &sealed).unwrap();
        assert!(
            !is_final,
            "must not report completion without a final chunk (CVE-2026-48480 class)"
        );
    }

    #[test]
    fn tampered_capsule_fails() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (mut capsule, _c) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let n = capsule.0.len();
        capsule.0[n - 1] ^= 0xff;
        assert!(ohttp_decapsulate(&sk, &capsule).is_err());
    }
}
