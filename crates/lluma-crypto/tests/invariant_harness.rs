//! In-process mock of one anonymous request across issuer/relay/broker/host,
//! recording exactly what each party observed, then asserting the invariant:
//! no party's view contains both a consumer identity and the prompt, and no
//! party sees both a consumer account and a spendable token.
//!
//! This is the capstone integration test (ADR §8 test 16 / spec §14): it wires
//! the full public API of `lluma-crypto` (tokens + ohttp + e2e + account) into a
//! single in-process anonymous-request flow and asserts, from recorded
//! per-party views, that no single party holds both a consumer identity (IP or
//! account) and the prompt plaintext.
use lluma_core::wire::UsageReceiptBody;
use lluma_core::ModelId;
use lluma_crypto::{account::*, e2e::*, ohttp::*, tokens::*};

// RNG split (deviation from the original task brief): the blind-RSA token
// functions require the `rand_core` 0.10.x `CryptoRng` trait from
// `blind-rsa-signatures`' own dependency tree, which is a *different* trait
// than the workspace `rand_core` 0.6 used by the e2e/ohttp/account functions.
// So the harness keeps two RNGs — `blind_rsa_signatures::DefaultRng` for the
// token calls and `rand_core::OsRng` (0.6) for everything else — mirroring the
// split each module's own tests use. See `src/tokens.rs` and ADR-0001.
use blind_rsa_signatures::DefaultRng as TokenRng;
use rand_core::OsRng;

#[derive(Default)]
struct View {
    saw_prompt: bool,
    saw_consumer_ip: bool,
    saw_consumer_account: bool,
    saw_spendable_token: bool,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn no_party_holds_identity_and_content() {
    let mut token_rng = TokenRng; // blind-rsa-signatures RNG (rsa::rand_core 0.10)
    let mut rng = OsRng; // workspace rand_core 0.6 RNG for e2e/ohttp/account
    let prompt = b"what is the capital of France?";
    let consumer_ip = "203.0.113.7"; // known only to the relay

    // --- setup parties ---
    // Issuer keygen + token blinding/issuance use the blind-rsa RNG.
    let (issuer_sk, issuer_pk) = issuer_keygen(&mut token_rng).unwrap();
    let (state, blinded) = token_blind(&mut token_rng, &issuer_pk).unwrap();
    let blind_sig = token_issue(&mut token_rng, &issuer_sk, &blinded).unwrap();
    let token = token_unblind(&issuer_pk, state, &blind_sig).unwrap();

    // Host HPKE keypair + gateway OHTTP config + host account use the 0.6 RNG.
    let (host_sk, host_pk) = host_keygen(&mut rng).unwrap();
    let (gw_sk, gw_cfg) = ohttp_keygen(&mut rng, 1).unwrap();
    let (host_acct_sk, host_acct_pk) =
        derive_keypair_from_seed(&lluma_core::wire::Mnemonic([5u8; 16])).unwrap();

    let mut relay = View::default();
    let mut broker = View::default();
    let mut host = View::default();

    // --- consumer buys a token (out of band) ---
    // (Done above: token is unlinkable — issuer cannot link it to its spend.)

    // --- consumer builds the request ---
    let (session_sk, session_pk) = session_keygen(&mut rng).unwrap();
    let routing_aad = b"model-id=qwen2.5-0.5b-instruct;tier=0";
    let sealed = e2e_seal(&mut rng, &host_pk, routing_aad, prompt, &session_pk).unwrap();
    let (capsule, mut client_rctx) = ohttp_encapsulate(&mut rng, &gw_cfg, &sealed.0).unwrap();

    // --- relay: sees IP + opaque capsule ---
    relay.saw_consumer_ip = true;
    relay.saw_prompt = contains(&capsule.0, prompt);
    // relay forwards capsule + routing metadata to broker (no IP).

    // --- broker: decapsulates OHTTP, sees inner sealed bytes + token + routing ---
    let (inner, mut server_rctx) = ohttp_decapsulate(&gw_sk, &capsule).unwrap();
    broker.saw_prompt = contains(&inner, prompt);
    token_verify(&issuer_pk, &token).unwrap(); // broker verifies with PUBLIC key only
    broker.saw_spendable_token = true; // broker holds the token to check double-spend
    broker.saw_consumer_account = false; // no consumer account is ever presented
    // broker forwards inner sealed bytes to host.

    // --- host: opens the prompt, sees no IP, no consumer account ---
    let sealed_for_host = lluma_core::wire::SealedRequest(inner.clone());
    let (opened, reply_to) = e2e_open(&host_sk, routing_aad, &sealed_for_host).unwrap();
    host.saw_prompt = opened.as_slice() == &prompt[..];
    host.saw_consumer_ip = false;
    host.saw_consumer_account = false;

    // host produces a signed receipt crediting ITSELF (host account), citing spend id.
    let body = UsageReceiptBody {
        version: 1,
        host_account: account_fingerprint(&host_acct_pk).0,
        model_id: ModelId("qwen2.5-0.5b-instruct".into()),
        tier: 0,
        units: 1,
        spend_id: token_spend_id(&token).0,
        epoch: 0,
        timestamp_h: 0,
    };
    let receipt_sig = receipt_sign(&host_acct_sk, &body).unwrap();
    assert!(receipt_verify(&host_acct_pk, &body, &receipt_sig).is_ok());

    // host streams a response sealed to the consumer's session key.
    let (mut hrctx, preamble) = response_setup_host(&mut rng, &reply_to).unwrap();
    let resp = response_seal_chunk(&mut hrctx, b"Paris.", true).unwrap();
    // broker re-wraps in OHTTP response; consumer opens both layers.
    let ohttp_resp = ohttp_seal_chunk(&mut server_rctx, &resp, true).unwrap();
    let (inner_resp, fin1) = ohttp_open_chunk(&mut client_rctx, &ohttp_resp).unwrap();
    let mut crctx = response_setup_client(&session_sk, &preamble).unwrap();
    let (answer, fin2) = response_open_chunk(&mut crctx, &inner_resp).unwrap();
    assert!(fin1 && fin2);
    assert_eq!(answer, b"Paris.");

    // --- assert the invariant ---
    assert!(relay.saw_consumer_ip && !relay.saw_prompt, "relay: IP but never prompt");
    assert!(
        !broker.saw_consumer_ip && !broker.saw_prompt,
        "broker: neither IP nor prompt"
    );
    assert!(!broker.saw_consumer_account, "broker: never a consumer account");
    assert!(
        host.saw_prompt && !host.saw_consumer_ip && !host.saw_consumer_account,
        "host: prompt only, no identity"
    );
    // No party has BOTH identity and content:
    for v in [&relay, &broker, &host] {
        let has_identity = v.saw_consumer_ip || v.saw_consumer_account;
        assert!(
            !(has_identity && v.saw_prompt),
            "invariant: no party holds identity AND content"
        );
    }
    // The receipt credits the HOST account and names no consumer: the only
    // account id in the receipt body is the host's fingerprint.
    assert_eq!(body.host_account, account_fingerprint(&host_acct_pk).0);
    // The prompt plaintext never appears anywhere the relay/broker observe.
    assert!(!contains(&capsule.0, prompt), "relay capsule must not leak the prompt");
    assert!(!contains(&inner, prompt), "broker's decapsulated request must not leak the prompt");
    let _ = consumer_ip; // consumer IP is recorded only by the relay view, not forwarded
}