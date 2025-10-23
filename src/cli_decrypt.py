#!/usr/bin/env python3
"""
Command-line decrypt an encrypted blob produced by cli_encrypt.
"""
import argparse
from pathlib import Path
from src.kem_chacha import read_encrypted_blob, decrypt_bytes_with_priv
from src.key_manager import load_privkey

def main():
    parser = argparse.ArgumentParser(description="Decrypt a stored encrypted blob using your private KEM key.")
    parser.add_argument("--enc", required=True, help="Encrypted blob path (.enc)")
    parser.add_argument("--meta", required=True, help="Metadata JSON path (.meta.json)")
    parser.add_argument("--privkey-file", required=True, help="Your private KEM key file (base64)")
    parser.add_argument("--out", required=True, help="Output plaintext file path")
    args = parser.parse_args()

    priv_b64 = load_privkey(args.privkey_file)
    ct, meta = read_encrypted_blob(args.enc, args.meta)
    plaintext = decrypt_bytes_with_priv(ct, meta, priv_b64)
    Path(args.out).write_bytes(plaintext)
    print("Decrypted and wrote:", args.out)

if __name__ == "__main__":
    main()