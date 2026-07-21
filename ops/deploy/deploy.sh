#!/usr/bin/env bash
# Lluma production deploy — the commands that produced the live MVP network
# (Vultr relay + DigitalOcean gateway/broker origin). REVIEW before running; it
# provisions real, billable infrastructure. Idempotency is partial — re-running
# creates new droplets unless you set the *_IP vars to reuse existing ones.
#
# Prereqs on the operator machine:
#   - doctl authenticated (DigitalOcean)
#   - ~/.lluma-deploy.env  with VULTR_API_KEY  (chmod 600)
#   - ~/.lluma-keys-prod/  from `cargo run -p lluma-keygen -- ~/.lluma-keys-prod`
#   - an SSH keypair whose public key is registered on BOTH DO and Vultr
set -euo pipefail

: "${LLUMA_DEPLOY_ENV:=$HOME/.lluma-deploy.env}"
: "${LLUMA_KEYDIR:=$HOME/.lluma-keys-prod}"
: "${DO_SSH_KEY_ID:?set DO_SSH_KEY_ID (doctl compute ssh-key list)}"
: "${VULTR_SSH_KEY_ID:?set VULTR_SSH_KEY_ID (Vultr ssh-keys)}"
set -a; . "$LLUMA_DEPLOY_ENV"; set +a
V() { curl -s -H "Authorization: Bearer $VULTR_API_KEY" "$@"; }
REPO=https://github.com/bodegga/lluma.git

echo "== 1. Provision VPS-B (DigitalOcean: gateway + co-located broker origin) =="
BROKER_IP="${BROKER_IP:-$(doctl compute droplet create lluma-broker \
  --image ubuntu-24-04-x64 --size s-2vcpu-4gb --region nyc3 \
  --ssh-keys "$DO_SSH_KEY_ID" --tag-name lluma --wait \
  --format PublicIPv4 --no-header)}"
echo "broker: $BROKER_IP"
ssh -o StrictHostKeyChecking=accept-new "root@$BROKER_IP" bash -s <<EOF
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential git curl pkg-config libssl-dev ufw >/dev/null
[ -d \$HOME/.rustup ] || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null 2>&1
. \$HOME/.cargo/env
rm -rf /opt/lluma && git clone --depth 1 $REPO /opt/lluma
cd /opt/lluma && cargo build --release -p lluma-gateway -p lluma-broker
install -m755 target/release/lluma-broker target/release/lluma-gateway /usr/local/bin/
cp ops/deploy/systemd/lluma-broker.service ops/deploy/systemd/lluma-gateway.service /etc/systemd/system/
id lluma >/dev/null 2>&1 || useradd --system --home /var/lib/lluma --shell /usr/sbin/nologin lluma
mkdir -p /var/lib/lluma /etc/lluma/keys && chown lluma:lluma /var/lib/lluma
EOF
# Ship key material (0600) and lock dir perms so the lluma group can traverse+read.
scp "$LLUMA_KEYDIR"/{issuer_sk.der,issuer_pk.der,registry.sk,epoch_salt.bin} "root@$BROKER_IP:/etc/lluma/keys/"
ssh "root@$BROKER_IP" bash -s <<'EOF'
set -e
chown root:lluma /etc/lluma /etc/lluma/keys /etc/lluma/keys/*
chmod 750 /etc/lluma /etc/lluma/keys; chmod 640 /etc/lluma/keys/*
ADMIN=$(openssl rand -hex 24)
cat > /etc/lluma/broker.env <<E
LLUMA_DB_PATH=/var/lib/lluma/broker.redb
LLUMA_ADMIN_SECRET=$ADMIN
LLUMA_ISSUER_SK_DER_FILE=/etc/lluma/keys/issuer_sk.der
LLUMA_ISSUER_PK_DER_FILE=/etc/lluma/keys/issuer_pk.der
LLUMA_REGISTRY_SK_FILE=/etc/lluma/keys/registry.sk
LLUMA_EPOCH_SALT_FILE=/etc/lluma/keys/epoch_salt.bin
LLUMA_EPOCH=1
LLUMA_POW_DIFFICULTY=20
LLUMA_CORE_BIND=127.0.0.1:8080
LLUMA_INGRESS_BIND=0.0.0.0:8081
E
cat > /etc/lluma/gateway.env <<E
LLUMA_GATEWAY_BIND=0.0.0.0:8782
LLUMA_GATEWAY_ORIGIN=http://127.0.0.1:8080
LLUMA_GATEWAY_PREFIXES=/v1/key-config,/v1/issue,/v1/register,/v1/exec,/v1/snapshot
LLUMA_GATEWAY_KEY_ID=1
E
chmod 640 /etc/lluma/*.env; chown root:lluma /etc/lluma/*.env
systemctl daemon-reload
systemctl enable --now lluma-broker; sleep 2; systemctl enable --now lluma-gateway
EOF

echo "== 2. Provision VPS-A (Vultr: relay) — build relay on VPS-B, copy the binary =="
RELAY_ID="${RELAY_ID:-$(V -X POST -H 'Content-Type: application/json' https://api.vultr.com/v2/instances \
  -d "{\"region\":\"ord\",\"plan\":\"vc2-1c-1gb\",\"os_id\":2284,\"label\":\"lluma-relay\",\"hostname\":\"lluma-relay\",\"sshkey_id\":[\"$VULTR_SSH_KEY_ID\"],\"tag\":\"lluma\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["instance"]["id"])')}"
until RELAY_IP=$(V "https://api.vultr.com/v2/instances/$RELAY_ID" | python3 -c 'import sys,json;i=json.load(sys.stdin)["instance"];print(i["main_ip"] if i["status"]=="active" and i["main_ip"]!="0.0.0.0" else "")') && [ -n "$RELAY_IP" ]; do sleep 5; done
echo "relay: $RELAY_IP"
ssh -o StrictHostKeyChecking=accept-new "root@$BROKER_IP" '. $HOME/.cargo/env; cd /opt/lluma && cargo build --release -p lluma-relay'
scp "root@$BROKER_IP:/opt/lluma/target/release/lluma-relay" /tmp/lluma-relay
scp /tmp/lluma-relay "root@$RELAY_IP:/usr/local/bin/lluma-relay"
ssh -o StrictHostKeyChecking=accept-new "root@$RELAY_IP" bash -s <<EOF
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq ca-certificates libssl3 ufw >/dev/null
id lluma >/dev/null 2>&1 || useradd --system --home /var/lib/lluma --shell /usr/sbin/nologin lluma
chmod 755 /usr/local/bin/lluma-relay; mkdir -p /etc/lluma
cat > /etc/lluma/relay.env <<E
LLUMA_RELAY_BIND=0.0.0.0:8780
LLUMA_RELAY_GATEWAY=http://$BROKER_IP:8782
LLUMA_RELAY_MAX_BODY=1048576
LLUMA_RELAY_RL_CAPACITY=1000
LLUMA_RELAY_RL_REFILL=100
E
cat > /etc/systemd/system/lluma-relay.service <<'E'
[Unit]
Description=Lluma relay
After=network-online.target
[Service]
Type=simple
User=lluma
EnvironmentFile=/etc/lluma/relay.env
ExecStart=/usr/local/bin/lluma-relay
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
E
systemctl daemon-reload && systemctl enable --now lluma-relay
ufw allow OpenSSH >/dev/null; ufw allow 8780/tcp >/dev/null; ufw --force enable >/dev/null
EOF

echo "== 3. Firewall VPS-B (gateway reachable only from the relay) =="
ssh "root@$BROKER_IP" "ufw allow OpenSSH >/dev/null; ufw allow 8081/tcp >/dev/null; \
  ufw allow from $RELAY_IP to any port 8782 proto tcp >/dev/null; ufw --force enable >/dev/null"

echo "== DONE. relay=$RELAY_IP  broker/gateway=$BROKER_IP =="
echo "Next: register serving host(s); DNS-delegate n.lluma.bodegga.net to DO for TLS;"
echo "smoke: cargo run -p lluma-client --example live_smoke  (see its header + docs/INFRA.md)"
