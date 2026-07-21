#!/usr/bin/env bash
# Generate the random key material the broker needs (registry Ed25519 secret +
# global PoW epoch salt). Run on VPS-B; back the output up offline.
#
# NOTE: this does NOT generate the issuer RSA-BSSA key pair — that DER pair comes
# from the issuer key-generation path (see the crypto design spec). It also does
# NOT deploy anything; it only writes files you then reference from broker.env.
set -euo pipefail

DIR="${1:-./lluma-keys}"
mkdir -p "$DIR"
chmod 700 "$DIR"

# 32 random bytes each — an Ed25519 secret scalar seed and the epoch salt.
head -c 32 /dev/urandom > "$DIR/registry.sk"
head -c 32 /dev/urandom > "$DIR/epoch_salt.bin"
chmod 600 "$DIR/registry.sk" "$DIR/epoch_salt.bin"

echo "wrote:"
echo "  $DIR/registry.sk      (32 bytes — LLUMA_REGISTRY_SK_FILE)"
echo "  $DIR/epoch_salt.bin   (32 bytes — LLUMA_EPOCH_SALT_FILE)"
echo
echo "Still required (not generated here):"
echo "  issuer_sk.der / issuer_pk.der  — from the issuer key-generation path"
echo
echo "The salt is non-zero (the broker refuses an all-zero salt in prod)."
