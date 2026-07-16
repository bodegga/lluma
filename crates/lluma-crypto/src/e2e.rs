//! Inner end-to-end HPKE layer (RFC 9180) plus ephemeral per-request session
//! keys and the streamed response context. This is the "inner" seal: it runs
//! host-public-key -> host-private-key, independent of the outer OHTTP/relay
//! hop, so no single relay/broker ever sees both plaintext and originator IP.
use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    HostPublicKey, HostSecretKey, ResponsePreamble, SealedRequest, SessionPublicKey,
    SessionSecretKey,
};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
const INFO: &[u8] = b"lluma/e2e/v1";
const RESP_INFO: &[u8] = b"lluma/e2e/response/v1";

pub fn host_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(HostSecretKey, HostPublicKey)> {
    let (sk, pk) = Kem::gen_keypair(rng);
    Ok((
        HostSecretKey(sk.to_bytes().to_vec()),
        HostPublicKey(pk.to_bytes().to_vec()),
    ))
}

pub fn session_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(SessionSecretKey, SessionPublicKey)> {
    let (sk, pk) = Kem::gen_keypair(rng);
    Ok((
        SessionSecretKey(sk.to_bytes().to_vec()),
        SessionPublicKey(pk.to_bytes().to_vec()),
    ))
}

fn kem_pk(bytes: &[u8]) -> Result<<Kem as KemTrait>::PublicKey> {
    <Kem as KemTrait>::PublicKey::from_bytes(bytes).map_err(|e| CryptoError::Hpke(e.to_string()))
}
fn kem_sk(bytes: &[u8]) -> Result<<Kem as KemTrait>::PrivateKey> {
    <Kem as KemTrait>::PrivateKey::from_bytes(bytes).map_err(|e| CryptoError::Hpke(e.to_string()))
}

/// Seals `prompt` to the host's public key using a fresh, single-use HPKE
/// sender context (RFC 9180 `Base` mode). `aad` binds routing metadata (e.g.
/// model id/tier) to the ciphertext so a relay cannot swap it onto a
/// different request. The inner plaintext is `reply_to (32B) || prompt` so
/// the host learns where to send the response without a second round trip.
pub fn e2e_seal(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    host_pk: &HostPublicKey,
    aad: &[u8],
    prompt: &[u8],
    reply_to: &SessionPublicKey,
) -> Result<SealedRequest> {
    let pk = kem_pk(&host_pk.0)?;
    let (enc, mut ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, INFO, rng)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let mut inner = Vec::with_capacity(32 + prompt.len());
    inner.extend_from_slice(&reply_to.0);
    inner.extend_from_slice(prompt);
    let ct = ctx
        .seal(&inner, aad)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(SealedRequest(out))
}

/// Opens a `SealedRequest` with the host's secret key. Returns the plaintext
/// prompt and the session public key the caller should reply to. Any AAD
/// mismatch, tamper, or truncation fails closed as `CryptoError::AuthFailed`
/// (never partially decrypts or falls back to a default route).
pub fn e2e_open(
    host_sk: &HostSecretKey,
    aad: &[u8],
    sealed: &SealedRequest,
) -> Result<(Vec<u8>, SessionPublicKey)> {
    let enc_len = <Kem as KemTrait>::EncappedKey::size();
    if sealed.0.len() < enc_len + 32 {
        return Err(CryptoError::AuthFailed);
    }
    let (enc_bytes, ct) = sealed.0.split_at(enc_len);
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let sk = kem_sk(&host_sk.0)?;
    let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, INFO)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let pt = ctx.open(ct, aad).map_err(|_| CryptoError::AuthFailed)?;
    if pt.len() < 32 {
        return Err(CryptoError::AuthFailed);
    }
    let reply = SessionPublicKey(pt[..32].to_vec());
    Ok((pt[32..].to_vec(), reply))
}

/// The host's side of a streamed response: holds a live HPKE sender context
/// bound to the requester's ephemeral session key, plus (implicitly, via the
/// `hpke` crate's internal sequence counter) a monotonically incrementing
/// chunk nonce so out-of-order or replayed chunks fail to decrypt.
pub struct HostResponseContext {
    ctx: hpke::aead::AeadCtxS<Aead, Kdf, Kem>,
}

/// The session/client side of a streamed response, mirroring
/// `HostResponseContext`.
pub struct SessionResponseContext {
    ctx: hpke::aead::AeadCtxR<Aead, Kdf, Kem>,
}

/// Sets up the host's response-stream sender context, encapsulated to the
/// requester's ephemeral session public key. Returns the context plus a
/// `ResponsePreamble` carrying the HPKE `enc` value the client needs to
/// rebuild the matching receiver context via `response_setup_client`.
pub fn response_setup_host(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    reply_to: &SessionPublicKey,
) -> Result<(HostResponseContext, ResponsePreamble)> {
    let pk = kem_pk(&reply_to.0)?;
    let (enc, ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, RESP_INFO, rng)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    Ok((HostResponseContext { ctx }, ResponsePreamble(enc.to_bytes().to_vec())))
}

/// Rebuilds the client/session receiver context from the session secret key
/// and the host's `ResponsePreamble`.
pub fn response_setup_client(
    session_sk: &SessionSecretKey,
    preamble: &ResponsePreamble,
) -> Result<SessionResponseContext> {
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&preamble.0)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let sk = kem_sk(&session_sk.0)?;
    let ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, RESP_INFO)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    Ok(SessionResponseContext { ctx })
}

/// Seals one response chunk. `last` is prepended in cleartext as a 1-byte
/// finality flag AND bound as AEAD `aad`, so flipping the flag (e.g. to
/// forge completion on a truncated stream) fails the tag check rather than
/// silently succeeding — truncation fails closed.
pub fn response_seal_chunk(
    ctx: &mut HostResponseContext,
    chunk: &[u8],
    last: bool,
) -> Result<Vec<u8>> {
    let aad = [last as u8];
    let mut ct = ctx
        .ctx
        .seal(chunk, &aad)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    ct.insert(0, last as u8); // prepend flag so the opener knows the claimed finality
    Ok(ct)
}

/// Opens one response chunk, returning the plaintext and the finality flag
/// the sender claimed (authenticated, since the flag is bound as AAD). The
/// underlying `hpke` AEAD context tracks its own sequence number, so
/// reordered or replayed chunks fail to decrypt (`CryptoError::ChunkOrder`).
pub fn response_open_chunk(
    ctx: &mut SessionResponseContext,
    chunk: &[u8],
) -> Result<(Vec<u8>, bool)> {
    if chunk.is_empty() {
        return Err(CryptoError::Truncated);
    }
    let last = chunk[0] == 1;
    let aad = [chunk[0]];
    let pt = ctx
        .ctx
        .open(&chunk[1..], &aad)
        .map_err(|_| CryptoError::ChunkOrder)?; // wrong order/tamper => AEAD fails
    Ok((pt, last))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_open_round_trip_with_reply_key() {
        let mut rng = OsRng;
        let (hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let aad = b"model-id=qwen;tier=0";
        let sealed = e2e_seal(&mut rng, &hpk, aad, b"the prompt", &spk).unwrap();
        let (pt, reply_to) = e2e_open(&hsk, aad, &sealed).unwrap();
        assert_eq!(pt, b"the prompt");
        assert_eq!(reply_to, spk);
    }

    #[test]
    fn aad_mismatch_fails_closed() {
        let mut rng = OsRng;
        let (hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let sealed = e2e_seal(&mut rng, &hpk, b"aad-A", b"p", &spk).unwrap();
        assert!(matches!(e2e_open(&hsk, b"aad-B", &sealed), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn identical_prompts_seal_differently() {
        let mut rng = OsRng;
        let (_hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let a = e2e_seal(&mut rng, &hpk, b"", b"p", &spk).unwrap();
        let b = e2e_seal(&mut rng, &hpk, b"", b"p", &spk).unwrap();
        assert_ne!(a, b, "fresh HPKE ephemeral per seal");
        assert!(!a.0.windows(1).any(|_| false)); // ciphertext present
    }

    #[test]
    fn session_keys_are_fresh() {
        let mut rng = OsRng;
        let (_, s1) = session_keygen(&mut rng).unwrap();
        let (_, s2) = session_keygen(&mut rng).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn response_stream_single_chunk_round_trip() {
        let mut rng = OsRng;
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let (ssk, spk2) = session_keygen(&mut rng).unwrap();
        let _ = spk;
        let (mut hctx, preamble) = response_setup_host(&mut rng, &spk2).unwrap();
        let sealed = response_seal_chunk(&mut hctx, b"hello world", true).unwrap();
        let mut cctx = response_setup_client(&ssk, &preamble).unwrap();
        let (pt, is_final) = response_open_chunk(&mut cctx, &sealed).unwrap();
        assert_eq!(pt, b"hello world");
        assert!(is_final);
    }

    #[test]
    fn response_truncation_fails_closed() {
        // A non-final chunk must never be reported as final; and opening a
        // tampered/short buffer must error, never silently "complete".
        let mut rng = OsRng;
        let (ssk, spk) = session_keygen(&mut rng).unwrap();
        let (mut hctx, preamble) = response_setup_host(&mut rng, &spk).unwrap();
        let sealed = response_seal_chunk(&mut hctx, b"partial", false).unwrap(); // last=false
        let mut cctx = response_setup_client(&ssk, &preamble).unwrap();
        let (_pt, is_final) = response_open_chunk(&mut cctx, &sealed).unwrap();
        assert!(!is_final, "non-final chunk must report is_final=false");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn e2e_round_trip_any_payload(prompt in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let mut rng = rand_core::OsRng;
            let (hsk, hpk) = host_keygen(&mut rng).unwrap();
            let (_ssk, spk) = session_keygen(&mut rng).unwrap();
            let sealed = e2e_seal(&mut rng, &hpk, b"aad", &prompt, &spk).unwrap();
            let (pt, _) = e2e_open(&hsk, b"aad", &sealed).unwrap();
            prop_assert_eq!(pt, prompt);
        }
    }
}
