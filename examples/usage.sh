#!/usr/bin/env bash
set -e
python -m src.cli_keygen --out-dir ~/.pqkeys --id myuser
mkdir -p secure_store public_keys
# The CLI wrote public_keys/myuser.pub; encrypt a file
echo "super secret data" > secret.txt
python -m src.cli_encrypt --in secret.txt --outname secret.txt --pubkey-file public_keys/myuser.pub --outdir secure_store
git add public_keys/myuser.pub secure_store/secret.txt.enc secure_store/secret.txt.meta.json || true
git commit -m "Add encrypted secret example" || true
# Decrypt locally (use the private key stored in ~/.pqkeys)
python -m src.cli_decrypt --enc secure_store/secret.txt.enc --meta secure_store/secret.txt.meta.json --privkey-file ~/.pqkeys/myuser.priv --out secret-decrypted.txt
cat secret-decrypted.txt