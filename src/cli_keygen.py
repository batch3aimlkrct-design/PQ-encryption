#!/usr/bin/env python3
"""
CLI to generate a KEM keypair and save private key locally and public key for repo.
"""
import argparse
from pathlib import Path
from src.kem_chacha import generate_kem_keypair
from src.key_manager import save_privkey_secure, save_pubkey, DEFAULT_KEY_DIR

def main():
    parser = argparse.ArgumentParser(description="Generate a KEM keypair.")
    parser.add_argument("--out-dir", default=str(DEFAULT_KEY_DIR), help="Directory to store private key (local only)")
    parser.add_argument("--id", required=True, help="Key identifier (basename for files)")
    parser.add_argument("--pub-out", default="public_keys", help="Directory to write public key for committing")
    parser.add_argument("--kem", default=None, help="Optional KEM algorithm override")
    args = parser.parse_args()

    kem_alg = args.kem if args.kem else None
    pub_b64, priv_b64 = generate_kem_keypair(kem_alg if kem_alg else None)
    priv_path = Path(args.out_dir) / f"{args.id}.priv"
    pub_path = Path(args.pub_out) / f"{args.id}.pub"
    save_privkey_secure(str(priv_path), priv_b64)
    save_pubkey(str(pub_path), pub_b64)
    print("Saved private key (keep private):", priv_path)
    print("Saved public key (commit to repo):", pub_path)

if __name__ == "__main__":
    main()