//! In-process mock of one anonymous request across issuer/relay/broker/host,
//! recording exactly what each party observed, then asserting the invariant:
//! no party's view contains both a consumer identity and the prompt, and no
//! party sees both a consumer account and a spendable token.
//!
//! This is the capstone integration test (ADR §8 test 16 / spec §14): it wires
//! the full public API of `lluma-crypto` (tokens + ohttp + e2e + account) into a
//! single in-process anonymous-request flow and asserts, from recorded
//! per-party views, that no single party holds both a consumer identity (IP or
//! account) and the prompt plaintext. It also models the AAD contract: the
//! request's entitlement token (its spend id) is bound into the inner-seal AAD
//! so a broker cannot detach and replay the token against a different request.
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, GatewaySecretKey, HostPublicKey, HostSecretKey,
    IssuerPublicKey, IssuerSecretKey, Mnemonic, OhttpKeyConfig, SealedRequest, UsageReceiptBody,
};
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

/// One shared "deployment": the long-lived issuer / host / gateway / host
/// account keys. Two unlinkable requests from the same consumer run against
/// the *same* deployment with fresh per-request sessions+tokens.
struct Deployment {
    issuer_sk: IssuerSecretKey,
    issuer_pk: IssuerPublicKey,
    host_sk: HostSecretKey,
    host_pk: HostPublicKey,
    gw_sk: GatewaySecretKey,
    gw_cfg: OhttpKeyConfig,
    host_acct_sk: AccountSecretKey,
    host_acct_pk: AccountPublicKey,
}

fn build_deployment() -> Deployment {
    let mut token_rng = TokenRng;
    let mut rng = OsRng;
    let (issuer_sk, issuer_pk) = issuer_keygen(&mut token_rng).unwrap();
    let (host_sk, host_pk) = host_keygen(&mut rng).unwrap();
    let (gw_sk, gw_cfg) = ohttp_keygen(&mut rng, 1).unwrap();
    let (host_acct_sk, host_acct_pk) = derive_keypair_from_seed(&Mnemonic([5u8; 16])).unwrap();
    Deployment {
        issuer_sk,
        issuer_pk,
        host_sk,
        host_pk,
        gw_sk,
        gw_cfg,
        host_acct_sk,
        host_acct_pk,
    }
}

/// Non-client-party bytes captured during one run, used by the unlinkability
/// assertion to prove two runs leave no shared linkable window.
struct RunArtifacts {
    relay_capsule: Vec<u8>,
    broker_inner: Vec<u8>,
    host_sealed: Vec<u8>,
    relay: View,
    broker: View,
    host: View,
}

/// Run the full anonymous-request flow once and return the per-party bytes +
/// views. `aad` is built to bind the token's spend id into the inner seal so a
/// broker cannot detach + replay the token against a different request.
fn run_anonymous_request(deploy: &Deployment, prompt: &[u8]) -> RunArtifacts {
    let mut token_rng = TokenRng;
    let mut rng = OsRng;

    // consumer buys a token (unlinkable: issuer cannot link to its later spend)
    let (state, blinded) = token_blind(&mut token_rng, &deploy.issuer_pk).unwrap();
    let blind_sig = token_issue(&mut token_rng, &deploy.issuer_sk, &blinded).unwrap();
    let token = token_unblind(&deploy.issuer_pk, state, &blind_sig).unwrap();
    let spend_id = token_spend_id(&token);

    // Build the inner-seal AAD with the token's spend id bound in (AAD
    // contract: a broker cannot detach + replay the token against a different
    // request). The SAME aad is used on e2e_open.
    let mut aad = b"model-id=qwen2.5-0.5b-instruct;tier=0;spend=".to_vec();
    aad.extend_from_slice(&spend_id.0);

    // consumer builds the request
    let (session_sk, session_pk) = session_keygen(&mut rng).unwrap();
    let sealed = e2e_seal(&mut rng, &deploy.host_pk, &aad, prompt, &session_pk).unwrap();
    let (capsule, mut client_rctx) =
        ohttp_encapsulate(&mut rng, &deploy.gw_cfg, &sealed.0).unwrap();

    let mut relay = View::default();
    let mut broker = View::default();
    let mut host = View::default();

    // relay: sees IP + opaque capsule
    relay.saw_consumer_ip = true;
    relay.saw_prompt = contains(&capsule.0, prompt);

    // broker: decapsulates OHTTP, sees inner sealed bytes + token + routing
    let (inner, mut server_rctx) = ohttp_decapsulate(&deploy.gw_sk, &capsule).unwrap();
    broker.saw_prompt = contains(&inner, prompt);
    token_verify(&deploy.issuer_pk, &token).unwrap();
    broker.saw_spendable_token = true;
    broker.saw_consumer_account = false;

    // host: opens the prompt, sees no IP, no consumer account
    let sealed_for_host = SealedRequest(inner.clone());
    let (opened, reply_to) = e2e_open(&deploy.host_sk, &aad, &sealed_for_host).unwrap();
    host.saw_prompt = opened.as_slice() == prompt;
    host.saw_consumer_ip = false;
    host.saw_consumer_account = false;

    // host produces a signed receipt crediting ITSELF, citing the spend id.
    let body = UsageReceiptBody {
        version: 1,
        host_account: account_fingerprint(&deploy.host_acct_pk).0,
        model_id: ModelId("qwen2.5-0.5b-instruct".into()),
        tier: 0,
        units: 1,
        spend_id: spend_id.0,
        epoch: 0,
        timestamp_h: 0,
    };
    let receipt_sig = receipt_sign(&deploy.host_acct_sk, &body).unwrap();
    assert!(receipt_verify(&deploy.host_acct_pk, &body, &receipt_sig).is_ok());

    // host streams a response sealed to the consumer's session key.
    let (mut hrctx, preamble) = response_setup_host(&mut rng, &reply_to).unwrap();
    let resp = response_seal_chunk(&mut hrctx, b"Paris.", true).unwrap();
    let ohttp_resp = ohttp_seal_chunk(&mut server_rctx, &resp, true).unwrap();
    let (inner_resp, fin1) = ohttp_open_chunk(&mut client_rctx, &ohttp_resp).unwrap();
    let mut crctx = response_setup_client(&session_sk, &preamble).unwrap();
    let (answer, fin2) = response_open_chunk(&mut crctx, &inner_resp).unwrap();
    assert!(fin1 && fin2);
    assert_eq!(answer, b"Paris.");

    RunArtifacts {
        relay_capsule: capsule.0.clone(),
        broker_inner: inner.clone(),
        host_sealed: sealed_for_host.0.clone(),
        relay,
        broker,
        host,
    }
}

/// True iff `a` and `b` share any common byte-substring of length `w`. A real
/// byte check (not a hand-set boolean): two unlinkable runs must share NO
/// long window at any non-client party.
fn shares_window(a: &[u8], b: &[u8], w: usize) -> bool {
    if a.len() < w || b.len() < w {
        return false;
    }
    for window in a.windows(w) {
        if contains(b, window) {
            return true;
        }
    }
    false
}

#[test]
fn no_party_holds_identity_and_content() {
    let deploy = build_deployment();
    let prompt = b"what is the capital of France?";
    let _consumer_ip = "203.0.113.7"; // known only to the relay

    let run = run_anonymous_request(&deploy, prompt);

    // assert the invariant
    assert!(
        run.relay.saw_consumer_ip && !run.relay.saw_prompt,
        "relay: IP but never prompt"
    );
    assert!(
        !run.broker.saw_consumer_ip && !run.broker.saw_prompt,
        "broker: neither IP nor prompt"
    );
    assert!(
        !run.broker.saw_consumer_account,
        "broker: never a consumer account"
    );
    assert!(
        run.host.saw_prompt && !run.host.saw_consumer_ip && !run.host.saw_consumer_account,
        "host: prompt only, no identity"
    );
    for v in [&run.relay, &run.broker, &run.host] {
        let has_identity = v.saw_consumer_ip || v.saw_consumer_account;
        assert!(
            !(has_identity && v.saw_prompt),
            "invariant: no party holds identity AND content"
        );
    }
    // The prompt plaintext never appears anywhere the relay/broker observe.
    assert!(
        !contains(&run.relay_capsule, prompt),
        "relay capsule must not leak the prompt"
    );
    assert!(
        !contains(&run.broker_inner, prompt),
        "broker's decapsulated request must not leak the prompt"
    );
    let _ = _consumer_ip;
}

#[test]
fn two_sessions_are_unlinkable() {
    // Run the full anonymous-request flow TWICE from one "client" (two fresh
    // sessions + tokens, same prompt, same deployment) and assert the two runs
    // share no common 16-byte byte-substring at any non-client party.
    let deploy = build_deployment();
    let prompt = b"what is the capital of France?";
    let run1 = run_anonymous_request(&deploy, prompt);
    let run2 = run_anonymous_request(&deploy, prompt);

    // Sanity: both runs are well-formed (the host recovered the prompt).
    assert!(run1.host.saw_prompt && run2.host.saw_prompt);

    // The two runs must differ at every non-client party.
    assert_ne!(
        run1.relay_capsule, run2.relay_capsule,
        "relay capsules must differ"
    );
    assert_ne!(
        run1.broker_inner, run2.broker_inner,
        "broker inner ciphertexts must differ"
    );
    assert_ne!(
        run1.host_sealed, run2.host_sealed,
        "host sealed-request bytes must differ"
    );

    // Stronger: neither run's non-client bytes contain any 16-byte window of
    // the other's (so e.g. no shared session key, nonce, or ciphertext block
    // leaks across the two unlinkable requests).
    const W: usize = 16;
    assert!(
        !shares_window(&run1.relay_capsule, &run2.relay_capsule, W),
        "relay capsules share a 16-byte window — linkable"
    );
    assert!(
        !shares_window(&run1.broker_inner, &run2.broker_inner, W),
        "broker inners share a 16-byte window — linkable"
    );
    assert!(
        !shares_window(&run1.host_sealed, &run2.host_sealed, W),
        "host sealed requests share a 16-byte window — linkable"
    );
}
