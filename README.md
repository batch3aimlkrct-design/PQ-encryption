```markdown
# Lightweight Post-Quantum Confidential Storage (GitHub as storage)

This project is a proof-of-concept: a lightweight hybrid encryption scheme that uses a post-quantum KEM (CRYSTALS-Kyber family via liboqs / pyoqs) to protect a symmetric key and ChaCha20-Poly1305 for efficient authenticated symmetric encryption of file contents. Instead of using a cloud object store, encrypted blobs and metadata are stored in a GitHub repository (or any git remote). The repository acts as the untrusted storage: only encrypted data is pushed to it; private keys remain local.

This repository contains everything needed to build, test, and run the demo locally or in CI, including scripts, packaging, tests, a Dockerfile, and CI workflow to build liboqs/pyoqs.

WARNING: This is a demonstration. For production, use audited libraries and hardened key storage (HSMs / OS keyrings), secure key rotation policies, and professional review.

Highlights
- Hybrid design: PQC KEM (Kyber family via liboqs/pyoqs) for key establishment + ChaCha20-Poly1305 for bulk encryption.
- CLI tools to: generate a KEM keypair, encrypt a file and write encrypted blob + JSON metadata, decrypt a stored blob locally.
- GitHub used as storage backend — commit only encrypted blobs and metadata.
- CI workflow builds liboqs from source and installs pyoqs so tests run against a real PQC implementation.

Repository layout (key files)
- pyproject.toml — package metadata + console script entry points
- requirements.txt — runtime + dev deps
- src/kem_chacha.py — core KEM + AE code
- src/key_manager.py — helpers to store private keys securely (local only)
- src/cli_keygen.py — generate keys and save them safely (private kept local)
- src/cli_encrypt.py — encrypt file -> .enc + .meta.json
- src/cli_decrypt.py — decrypt file using local private key
- tests/ — pytest tests (unit + optional integration)
- .github/workflows/ci.yml — CI that builds liboqs and runs tests
- Dockerfile — reproducible environment
- examples/usage.sh — end-to-end usage example
- LICENSE, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, CHANGELOG.md

Quick start (recommended)
1) Create virtualenv and install dev deps:
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

2) Generate a KEM keypair:
   python -m src.cli_keygen --out-dir ~/.pqkeys --id myuser

   The private key will be saved in ~/.pqkeys/myuser.priv (file perm 600). The public key will be written to public_keys/myuser.pub — commit only the public key and encrypted artifacts.

3) Encrypt a file:
   python -m src.cli_encrypt --in secret.txt --outname secret.txt --pubkey-file public_keys/myuser.pub --outdir secure_store

4) Commit secure_store/*.enc and secure_store/*.meta.json to your repo and push.

5) Decrypt locally:
   python -m src.cli_decrypt --enc secure_store/secret.txt.enc --meta secure_store/secret.txt.meta.json --privkey-file ~/.pqkeys/myuser.priv --out secret-decrypted.txt

CI and reproducibility
- The GitHub Actions CI builds liboqs from source and installs pyoqs so tests run on a real PQC implementation. The Dockerfile reproduces a similar build.

Security notes
- Never commit private keys to the repository.
- Use OS keyrings/HSMs for real deployments.
- The metadata stored in the repo identifies KEM algorithm, encapsulation (base64), AE info, nonce and tag. This is necessary for decryption but reveals some metadata; design accordingly.
- Use the Kyber variant that meets your security requirements (Kyber512, Kyber768, Kyber1024).

If you'd like, I can:
- Add native integrations with the OS keyring (GNOME Keyring / macOS Keychain / Windows DPAPI).
- Add a GitHub Action which periodically rotates a public key and re-encrypts artifacts (requires secrets / a runner with the private key).
- Provide a small demo repo template that uses this as a submodule for storing encrypted artifacts.

```