#!/usr/bin/env python3
"""
Command-line encrypt a file using a recipient public key and store encrypted blob + metadata.
"""
import argparse
from pathlib import Path
from src.kem_chacha import encrypt_bytes_with_pub, write_encrypted_file
from src.key_manager import load_pubkey

def main():
    parser = argparse.ArgumentParser(description="Encrypt a file to be stored on GitHub (encrypted).")
    parser.add_argument("--in", dest="infile", required=True, help="Input plaintext file path")
    parser.add_argument("--outname", required=True, help="Output artifact base name (no extension)")
    parser.add_argument("--pubkey-file", required=True, help="Recipient public key file (base64)")
    parser.add_argument("--outdir", default="secure_store", help="Directory to write .enc and .meta.json")
    parser.add_argument("--kem", default=None, help="Override KEM algorithm (optional)")
    args = parser.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        raise SystemExit("Input file not found: " + str(infile))

    pubkey_b64 = load_pubkey(args.pubkey_file)
    plaintext = infile.read_bytes()
    kem_alg = args.kem if args.kem else None
    ct, meta = encrypt_bytes_with_pub(plaintext, pubkey_b64, kem_alg if kem_alg else None)
    enc_path, meta_path = write_encrypted_file(args.outdir, args.outname, ct, meta)
    print("Wrote encrypted blob:", enc_path)
    print("Wrote metadata:", meta_path)
    print("Commit and push these files to your repository to store them on GitHub.")

if __name__ == "__main__":
    main()