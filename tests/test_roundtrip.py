import os
import tempfile
import json
import pytest
from pathlib import Path

from src import kem_chacha, key_manager

# Unit test that uses monkeypatch to simulate a KEM when pyoqs is not present.
def test_encrypt_decrypt_roundtrip_with_fake_kem(monkeypatch, tmp_path):
    """
    This unit test bypasses pyOQS and simulates encapsulation/decapsulation deterministically.
    It verifies the symmetric wrapping/encryption logic and metadata flow.
    """
    # Create deterministic 'shared secret' behavior
    def fake_encapsulate(public_b64, kem_alg=None):
        # produce deterministic encapsulated value and shared secret based on pub
        encapsulated = b"fake-enc:" + public_b64.encode("utf-8")
        shared = b"shared-secret-" + public_b64.encode("utf-8")
        return kem_chacha.b64encode(encapsulated).decode("ascii"), shared

    def fake_decapsulate(encapsulated_b64, private_b64, kem_alg=None):
        # produce shared secret derived from private key + encapsulated so decap works
        return b"shared-secret-" + b"PUBLIC-FROM-PRIV"  # our fake test will use a known value

    # Patch the encapsulate/decapsulate functions used in encrypt/decrypt flow
    monkeypatch.setattr(kem_chacha, "encapsulate_to_public_key", lambda pub, kem_alg=None: (kem_chacha.b64encode(b"enc").decode("ascii"), b"shared-secret-PUB"))
    monkeypatch.setattr(kem_chacha, "decapsulate", lambda enc_b64, priv_b64, kem_alg=None: b"shared-secret-PUB")

    plaintext = b"hello-pqc"
    # Build a fake public key file
    pub_b64 = "PUBKEY123"
    ct, meta = kem_chacha.encrypt_bytes_with_pub(plaintext, pub_b64)
    # Write to temp files
    enc_path = tmp_path / "f.enc"
    meta_path = tmp_path / "f.meta.json"
    enc_path.write_bytes(ct)
    meta_path.write_text(json.dumps(meta))

    # For decryption use a fake priv (content doesn't matter because we patched decapsulate)
    priv_b64 = "PRIVKEY123"
    ct_read = enc_path.read_bytes()
    meta_read = json.loads(meta_path.read_text())
    out = kem_chacha.decrypt_bytes_with_priv(ct_read, meta_read, priv_b64)
    assert out == plaintext


@pytest.mark.integration
def test_integration_roundtrip_requires_pyoqs(tmp_path):
    """
    Integration test that will run only if pyoqs is installed.
    It performs a full key generation, encrypt, decrypt cycle using real liboqs if available.
    """
    if kem_chacha.oqs is None:
        pytest.skip("pyoqs not installed; skip integration test")

    pub_b64, priv_b64 = kem_chacha.generate_kem_keypair()
    plaintext = b"integration secret"
    ct, meta = kem_chacha.encrypt_bytes_with_pub(plaintext, pub_b64)
    recovered = kem_chacha.decrypt_bytes_with_priv(ct, meta, priv_b64)
    assert recovered == plaintext