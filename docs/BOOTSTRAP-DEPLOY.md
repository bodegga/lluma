# Signed-bootstrap auto-connect — deploy runbook

Turns on zero-config, verified auto-connect for the desktop app. Additive and
backward-compatible: absent env vars ⇒ prior behavior. Production topology and
hosts: see [`INFRA.md`](INFRA.md).

## LIVE (deployed 2026-07-21)

- **Pinned registry public key** (bake into the app as `LLUMA_REGISTRY_PK_B64`):
  `rMOAQi7L8f8R4bW6tNWm8QN5fYIh3RDXWU1WL6aopPw=`
- **Gateway key** persisted at `/var/lib/lluma/gateway_kc.sk` (stable across restarts;
  `LLUMA_GATEWAY_KC_SK_FILE`, gateway unit gained `ReadWritePaths=/var/lib/lluma`).
- **Signed bootstrap** at `/etc/lluma/bootstrap.bin` (259 B), served at
  `https://relay.n.lluma.bodegga.net/v1/bootstrap` (`LLUMA_BOOTSTRAP_FILE`).
- **Verified live:** `bootstrap_smoke` fetches + verifies the blob against the pinned key
  AND completes an OHTTP key-config round-trip through the deployed gateway key
  (epoch 1, issuer key-id `ad9c7bc7…873748cf` pinned). Wrong pinned key is rejected.
- The registry key now signs both the snapshot and the bootstrap (distinct domains).

The steps below are the reproducible procedure (already executed for the values above).

- **Broker/gateway box (DigitalOcean):** `159.65.35.137` — repo at `/opt/lluma`,
  cargo at `/root/.cargo/bin/cargo`, keys in `/etc/lluma/keys/`. Also the Linux
  **build host** for the relay binary.
- **Relay box (Vultr):** `64.177.112.245` — binary at `/usr/local/bin/lluma-relay`,
  env `/etc/lluma/relay.env`, Caddy TLS-fronts `relay.n.lluma.bodegga.net`.

## 0. Prereqs
- `git push origin main` is done (boxes pull from `origin/main`).
- Configs/binaries backed up (`*.bak.<ts>` on both boxes).

## 1. Build on the broker box
```bash
ssh root@159.65.35.137
export PATH=$HOME/.cargo/bin:$PATH
cd /opt/lluma && git fetch origin && git checkout main && git pull
cargo build --release -p lluma-relay -p lluma-gateway -p lluma-keygen
# binaries in /opt/lluma/target/release/: lluma-relay, lluma-gateway, lluma-bootstrap, lluma-keygen
```

## 2. Persist the gateway OHTTP key (stable key-config across restarts)
```bash
# point the gateway at a persisted key file; it generates+persists on first start
grep -q LLUMA_GATEWAY_KC_SK_FILE /etc/lluma/gateway.env || \
  echo 'LLUMA_GATEWAY_KC_SK_FILE=/etc/lluma/keys/gateway_kc.sk' >> /etc/lluma/gateway.env
install -m755 /opt/lluma/target/release/lluma-gateway /usr/local/bin/lluma-gateway
systemctl restart lluma-gateway
# capture the STABLE key-config (base64):
GWKC=$(journalctl -u lluma-gateway --no-pager | grep -oE 'key_config \(base64[^:]*: .*' | tail -1 | sed 's/.*: //')
echo "$GWKC"
```

## 3. Registry pubkey (pin) + issuer key-id
```bash
PK=$(/opt/lluma/target/release/lluma-bootstrap pubkey /etc/lluma/keys/registry.sk)   # LLUMA_REGISTRY_PK_B64
KID=<issuer key_id hex>   # from INFRA.md / broker startup log (BLAKE3 of issuer pubkey)
echo "pin this in the app: $PK"
```

## 4. Sign the bootstrap
```bash
/opt/lluma/target/release/lluma-bootstrap sign \
  --registry-sk /etc/lluma/keys/registry.sk \
  --relay https://relay.n.lluma.bodegga.net \
  --gateway-kc-b64 "$GWKC" \
  --issuer-key-id-hex "$KID" \
  --out /tmp/bootstrap.bin
# self-checks the signature; prints the registry pubkey again.
```

## 5. Deploy to the relay box
```bash
scp /opt/lluma/target/release/lluma-relay root@64.177.112.245:/tmp/lluma-relay.new
scp /tmp/bootstrap.bin                    root@64.177.112.245:/etc/lluma/bootstrap.bin
ssh root@64.177.112.245 '
  install -m755 /tmp/lluma-relay.new /usr/local/bin/lluma-relay
  grep -q LLUMA_BOOTSTRAP_FILE /etc/lluma/relay.env || \
    echo "LLUMA_BOOTSTRAP_FILE=/etc/lluma/bootstrap.bin" >> /etc/lluma/relay.env
  chown lluma:lluma /etc/lluma/bootstrap.bin; chmod 644 /etc/lluma/bootstrap.bin
  systemctl restart lluma-relay
'
```

## 6. Verify (live)
```bash
# blob is served:
curl -s https://relay.n.lluma.bodegga.net/v1/bootstrap | head -c 80; echo
# client verifies it against the pinned pubkey (from repo root, any machine):
LLUMA_RELAY_URL=https://relay.n.lluma.bodegga.net LLUMA_REGISTRY_PK_B64=$PK \
  cargo run -q -p lluma-client --example bootstrap_smoke
```

## 7. Ship the app
Build the desktop release with the anchor pinned:
```powershell
$env:LLUMA_REGISTRY_PK_B64 = "<PK>"
cd apps\lluma-desktop\src-tauri; cargo build --release
```
Distribute `target/release/lluma-desktop.exe`. First launch auto-connects.

## Rollback
```bash
# relay:
ssh root@64.177.112.245 'install -m755 /usr/local/bin/lluma-relay.bak.<ts> /usr/local/bin/lluma-relay; \
  sed -i /LLUMA_BOOTSTRAP_FILE/d /etc/lluma/relay.env; systemctl restart lluma-relay'
# gateway (revert to ephemeral key):
ssh root@159.65.35.137 'sed -i /LLUMA_GATEWAY_KC_SK_FILE/d /etc/lluma/gateway.env; \
  cp /etc/lluma/gateway.env.bak.<ts> /etc/lluma/gateway.env; systemctl restart lluma-gateway'
```

## Notes / follow-ups
- No bootstrap expiry in v1: a relay can only serve an OLD *validly-signed* blob (stale
  gateway key ⇒ auto-connect simply fails; it cannot substitute a key). Add `issued_at`
  monotonic/expiry checking if bootstrap contents rotate frequently.
- Rotating the gateway key later ⇒ re-run steps 2/4/5 (re-sign with the new key-config).
- The registry key now signs both snapshots and bootstraps (distinct domains); keep it offline-backed.
