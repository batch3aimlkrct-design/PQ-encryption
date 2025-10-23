#!/usr/bin/env python3
"""
Lightweight hybrid: PQ KEM (Kyber512 default) + ChaCha20-Poly1305.

Provides:
- generate_kem_keypair()
- encapsulate_to_public_key()
- decapsulate()
- encrypt_bytes_with_pub()
- decrypt_bytes_with_priv()
- write/read helpers
"""
from base64 import b64encode, b64decode
import json
import os

try:
    import oqs
except Exception:
    oqs = None

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

KEM_ALG = "Kyber512"
SYMMETRIC_KEY_LEN = 32
NONCE_LEN = 12


def require_oqs():
    if oqs is None:
        raise RuntimeError(
            "pyOQS (oqs) is not installed or liboqs not found. See README to install liboqs + pyoqs."
        )


def generate_kem_keypair(kem_alg: str = KEM_ALG):
    """
    Generate a KEM keypair and return (public_key_b64, private_key_b64).
    """
    require_oqs()
    with oqs.KeyEncapsulation(kem_alg) as kem:
        pub, priv = kem.generate_keypair()
    return b64encode(pub).decode("ascii"), b64encode(priv).decode("ascii")


def encapsulate_to_public_key(public_key_b64: str, kem_alg: str = KEM_ALG):
    """
    Encapsulate to a recipient public key. Returns (encapsulated_b64, shared_secret_bytes).
    """
    require_oqs()
    public = b64decode(public_key_b64)
    with oqs.KeyEncapsulation(kem_alg) as kem:
        ct, shared = kem.encap(public)
    return b64encode(ct).decode("ascii"), shared


def decapsulate(encapsulated_b64: str, private_key_b64: str, kem_alg: str = KEM_ALG):
    """
    Decapsulate with private key to recover shared_secret bytes.
    """
    require_oqs()
    enc = b64decode(encapsulated_b64)
    priv = b64decode(private_key_b64)
    with oqs.KeyEncapsulation(kem_alg) as kem:
        shared = kem.decap(enc, priv)
    return shared


def derive_key_and_nonce(shared_secret: bytes, info: bytes = b"file-encryption"):
    total_len = SYMMETRIC_KEY_LEN + NONCE_LEN
    okm = HKDF(master=shared_secret, key_len=total_len, salt=None, hashmod=SHA256, context=info)
    key = okm[:SYMMETRIC_KEY_LEN]
    nonce = okm[SYMMETRIC_KEY_LEN:SYMMETRIC_KEY_LEN + NONCE_LEN]
    return key, nonce


def encrypt_bytes_with_pub(plaintext: bytes, public_key_b64: str, kem_alg: str = KEM_ALG):
    enc_b64, shared = encapsulate_to_public_key(public_key_b64, kem_alg=kem_alg)
    key, nonce = derive_key_and_nonce(shared, info=b"file-encryption")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    metadata = {
        "kem": kem_alg,
        "encapsulated": enc_b64,
        "symmetric": "ChaCha20-Poly1305",
        "nonce": b64encode(nonce).decode("ascii"),
        "tag": b64encode(tag).decode("ascii"),
        "hkdf_info": "file-encryption",
    }
    return ct, metadata


def decrypt_bytes_with_priv(ciphertext: bytes, metadata: dict, private_key_b64: str):
    kem_alg = metadata.get("kem")
    encapsulated_b64 = metadata.get("encapsulated")
    tag_b64 = metadata.get("tag")
    nonce_b64 = metadata.get("nonce")
    info = metadata.get("hkdf_info", "file-encryption").encode("utf-8")

    if not (kem_alg and encapsulated_b64 and tag_b64 and nonce_b64):
        raise ValueError("Missing metadata required for decryption")

    shared = decapsulate(encapsulated_b64, private_key_b64, kem_alg=kem_alg)
    key, nonce = derive_key_and_nonce(shared, info=info)
    if b64encode(nonce).decode("ascii") != nonce_b64:
        raise ValueError("Nonce mismatch during key derivation")

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    tag = b64decode(tag_b64)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def write_encrypted_file(out_dir: str, out_name: str, ciphertext: bytes, metadata: dict):
    os.makedirs(out_dir, exist_ok=True)
    enc_path = os.path.join(out_dir, f"{out_name}.enc")
    meta_path = os.path.join(out_dir, f"{out_name}.meta.json")
    with open(enc_path, "wb") as f:
        f.write(ciphertext)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    return enc_path, meta_path


def read_encrypted_blob(enc_path: str, meta_path: str):
    with open(enc_path, "rb") as f:
        ct = f.read()
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    return ct, meta