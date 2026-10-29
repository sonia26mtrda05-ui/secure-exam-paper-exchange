#!/usr/bin/env python3
"""
secure_exam.py - Secure examination-paper exchange (hybrid RSA + AES-GCM + RSA-PSS)

Library: `cryptography` (pyca) - an established, audited cryptographic library.

Primitives
  * RSA-4096 key pairs (sender, recipient)
  * AES-256-GCM            : bulk encryption + integrity of the paper
  * RSA-OAEP (SHA-256/MGF1): protects the AES session key for the recipient
  * RSA-PSS  (SHA-256)     : sender's signature over the whole package

Usage
  python secure_exam.py keygen  --name faculty   --out sender/keys
  python secure_exam.py encrypt --in paper.pdf --sender-id faculty --recipient-id coordinator \
         --sender-key sender/keys/faculty_private.pem --recipient-pub sender/trusted/coordinator_public.pem \
         --out channel/paper.pkg
  python secure_exam.py decrypt --in channel/paper.pkg --recipient-key recipient/keys/coordinator_private.pem \
         --sender-pub recipient/trusted/faculty_public.pem --out-dir recipient/inbox
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_BITS = 4096          # large key size
AES_BITS = 256
NONCE_LEN = 12           # 96-bit nonce, recommended for GCM
TAG_LEN = 16             # 128-bit GCM tag
FORMAT_VERSION = 1
SALT_LEN = hashes.SHA256().digest_size   # PSS salt = hash length (32 bytes)


class VerificationError(Exception):
    """Raised for ANY reason a package must be rejected."""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as exc:
        raise VerificationError("Malformed base64 field in package") from exc


def canonical(obj: dict) -> bytes:
    """Deterministic JSON encoding - the exact bytes that are signed / used as AAD."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN)


# --------------------------------------------------------------------------- #
# 1. key generation / storage / loading
# --------------------------------------------------------------------------- #
def generate_keypair(name: str, out_dir: str, passphrase: bytes):
    """Create RSA-4096 pair. Private key -> PKCS#8, passphrase-encrypted, mode 0600."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)

    priv_path = out / f"{name}_private.pem"
    pub_path = out / f"{name}_public.pem"

    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # create private key file with owner-only permissions from the start
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def load_private_key(path, passphrase: bytes):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)


def load_public_key(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


# --------------------------------------------------------------------------- #
# 2-4. encrypt + wrap key + sign
# --------------------------------------------------------------------------- #
def encrypt_and_sign(plaintext: bytes, filename: str, sender_id: str, recipient_id: str,
                     sender_priv, recipient_pub) -> dict:
    # Fresh random AES-256 session key and fresh random 96-bit nonce - EVERY call
    session_key = AESGCM.generate_key(bit_length=AES_BITS)
    nonce = secrets.token_bytes(NONCE_LEN)

    metadata = {
        "version": FORMAT_VERSION,
        "package_id": str(uuid.uuid4()),
        "filename": os.path.basename(filename),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "plaintext_size": len(plaintext),
        "algorithms": {
            "symmetric": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "signature": "RSA-PSS-SHA256",
        },
    }
    aad = canonical(metadata)          # metadata is authenticated by GCM too

    ct_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]

    enc_key = recipient_pub.encrypt(session_key, _oaep())

    body = {
        "metadata": metadata,
        "encrypted_session_key": b64e(enc_key),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }
    # Sign the complete package (everything except the signature itself)
    signature = sender_priv.sign(canonical(body), _pss(), hashes.SHA256())
    body["signature"] = b64e(signature)
    return body


# --------------------------------------------------------------------------- #
# 5-6. verify, unwrap, decrypt  (plaintext returned only after ALL checks pass)
# --------------------------------------------------------------------------- #
def verify_and_decrypt(package: dict, recipient_priv, sender_pub,
                       expected_recipient_id: str | None = None) -> tuple[bytes, dict]:
    # --- structure ---------------------------------------------------------
    required = {"metadata", "encrypted_session_key", "nonce", "ciphertext", "tag", "signature"}
    if not isinstance(package, dict) or set(package) != required:
        raise VerificationError("Package structure invalid (missing/extra fields)")

    signature = b64d(package["signature"])
    body = {k: v for k, v in package.items() if k != "signature"}

    # --- STEP 1: sender authentication + whole-package integrity -----------
    try:
        sender_pub.verify(signature, canonical(body), _pss(), hashes.SHA256())
    except InvalidSignature:
        raise VerificationError(
            "SIGNATURE INVALID - package was modified or was not signed by the trusted sender") from None
    except Exception as exc:
        raise VerificationError(f"Signature check could not be completed: {exc}") from None

    meta = package["metadata"]
    if meta.get("version") != FORMAT_VERSION:
        raise VerificationError("Unsupported package version")
    if expected_recipient_id and meta.get("recipient_id") != expected_recipient_id:
        raise VerificationError(
            f"Package addressed to '{meta.get('recipient_id')}', not '{expected_recipient_id}'")

    # --- STEP 2: recover session key with recipient's private key ----------
    try:
        session_key = recipient_priv.decrypt(b64d(package["encrypted_session_key"]), _oaep())
    except Exception:
        raise VerificationError(
            "SESSION KEY RECOVERY FAILED - wrong recipient private key (package not meant for this key)") from None

    nonce, ciphertext, tag = b64d(package["nonce"]), b64d(package["ciphertext"]), b64d(package["tag"])
    if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN:
        raise VerificationError("Invalid nonce/tag length")

    # --- STEP 3: AES-GCM authentication (tag) + decrypt ---------------------
    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext + tag, canonical(meta))
    except InvalidTag:
        raise VerificationError("GCM AUTHENTICATION TAG INVALID - ciphertext/metadata corrupted") from None

    if len(plaintext) != meta.get("plaintext_size"):
        raise VerificationError("Plaintext size does not match metadata")
    return plaintext, meta


# --------------------------------------------------------------------------- #
# file-level wrappers
# --------------------------------------------------------------------------- #
def encrypt_file(in_path, out_path, sender_id, recipient_id, sender_key_path,
                 recipient_pub_path, passphrase: bytes):
    data = Path(in_path).read_bytes()
    pkg = encrypt_and_sign(data, str(in_path), sender_id, recipient_id,
                           load_private_key(sender_key_path, passphrase),
                           load_public_key(recipient_pub_path))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(pkg, indent=2))
    return pkg


def decrypt_file(pkg_path, out_dir, recipient_key_path, sender_pub_path, passphrase: bytes,
                 expected_recipient_id=None):
    try:
        package = json.loads(Path(pkg_path).read_text())
    except Exception:
        raise VerificationError("Package is not valid JSON") from None
    plaintext, meta = verify_and_decrypt(
        package, load_private_key(recipient_key_path, passphrase),
        load_public_key(sender_pub_path), expected_recipient_id)
    # Only now - after every check passed - is anything written to disk.
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / os.path.basename(meta["filename"])
    dest.write_bytes(plaintext)
    return dest, meta


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _pw(prompt, env="EXAM_KEY_PASSPHRASE"):
    return (os.environ.get(env) or getpass.getpass(prompt)).encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen"); g.add_argument("--name", required=True); g.add_argument("--out", required=True)

    e = sub.add_parser("encrypt")
    e.add_argument("--in", dest="inp", required=True); e.add_argument("--out", required=True)
    e.add_argument("--sender-id", required=True); e.add_argument("--recipient-id", required=True)
    e.add_argument("--sender-key", required=True); e.add_argument("--recipient-pub", required=True)

    d = sub.add_parser("decrypt")
    d.add_argument("--in", dest="inp", required=True); d.add_argument("--out-dir", required=True)
    d.add_argument("--recipient-key", required=True); d.add_argument("--sender-pub", required=True)
    d.add_argument("--recipient-id")

    a = ap.parse_args()
    try:
        if a.cmd == "keygen":
            p = generate_keypair(a.name, a.out, _pw("New private-key passphrase: "))
            print(f"[+] RSA-{RSA_BITS} keys written:\n    {p[0]}\n    {p[1]}")
        elif a.cmd == "encrypt":
            pkg = encrypt_file(a.inp, a.out, a.sender_id, a.recipient_id, a.sender_key,
                               a.recipient_pub, _pw("Sender key passphrase: "))
            print(f"[+] Encrypted and signed -> {a.out} (package {pkg['metadata']['package_id']})")
        else:
            dest, meta = decrypt_file(a.inp, a.out_dir, a.recipient_key, a.sender_pub,
                                      _pw("Recipient key passphrase: "), a.recipient_id)
            print(f"[+] All checks passed. Decrypted file: {dest}")
    except VerificationError as exc:
        print(f"[REJECTED] {exc}", file=sys.stderr); sys.exit(2)
    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
