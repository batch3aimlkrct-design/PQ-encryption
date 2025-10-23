#!/usr/bin/env python3
"""
Simple local key manager utilities.

- save_privkey_secure(path, priv_b64)
- load_privkey(path)
- save_pubkey(path, pub_b64)
- load_pubkey(path)
"""
import os
from pathlib import Path

DEFAULT_KEY_DIR = Path.home() / ".pqkeys"


def ensure_key_dir(path: Path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    # Directory permissions (owner only)
    try:
        path.chmod(0o700)
    except Exception:
        pass
    return path


def save_privkey_secure(path: str, priv_b64: str):
    p = Path(path)
    ensure_key_dir(p.parent)
    with open(p, "w", encoding="utf-8") as f:
        f.write(priv_b64.strip() + "\n")
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return str(p)


def load_privkey(path: str):
    return Path(path).read_text().strip()


def save_pubkey(path: str, pub_b64: str):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(pub_b64.strip() + "\n")
    try:
        p.chmod(0o644)
    except Exception:
        pass
    return str(p)


def load_pubkey(path: str):
    return Path(path).read_text().strip()