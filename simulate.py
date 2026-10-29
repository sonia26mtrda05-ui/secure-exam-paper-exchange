#!/usr/bin/env python3
"""
simulate_colab.py - Secure exam-paper exchange + full simulation, in ONE file.
Works in Google Colab / Jupyter (paste into a single cell and run) and in a normal terminal.

(hybrid RSA + AES-GCM + RSA-PSS)

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
import base64
import copy
import hashlib
import shutil
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


# =========================================================================== #
# SIMULATION (sender / recipient / channel / attacker folders)
# =========================================================================== #
import types
se = types.SimpleNamespace(**globals())   # lets the code below call se.encrypt_file(...) etc.

# __file__ does not exist in a notebook cell, so fall back to the current folder
try:
    ROOT = Path(__file__).parent.resolve() / "exam_workshop"
except NameError:
    ROOT = Path.cwd() / "exam_workshop"
PASS = b"workshop-demo-passphrase"          # demo only; users type theirs in real use
results = []


def log(msg=""):
    print(msg)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def record(name, expected, ok, detail):
    results.append((name, ok))
    log(f"    expected : {expected}")
    log(f"    observed : {detail}")
    log(f"    RESULT   : {'PASS' if ok else 'FAIL'}\n")


def try_decrypt(pkg_path, rkey, spub, out_dir):
    """Returns (released_path|None, message)."""
    try:
        dest, meta = se.decrypt_file(pkg_path, out_dir, rkey, spub, PASS, "coordinator")
        return dest, "decrypted OK"
    except se.VerificationError as e:
        return None, f"[REJECTED] {e}"


def flip_b64(pkg, field):
    p = copy.deepcopy(pkg)
    raw = bytearray(se.b64d(p[field]))
    raw[len(raw) // 2] ^= 0x01                     # flip a single bit
    p[field] = se.b64e(bytes(raw))
    return p


def main():
    # ---------- fresh workspace -------------------------------------------
    for d in ("sender", "recipient", "channel", "attacker"):
        shutil.rmtree(ROOT / d, ignore_errors=True)
    for d in ("sender/keys", "sender/trusted", "sender/input", "recipient/keys",
              "recipient/trusted", "recipient/inbox", "channel", "attacker/keys"):
        (ROOT / d).mkdir(parents=True, exist_ok=True)

    log("=" * 72)
    log("SECURE EXAM-PAPER EXCHANGE - SIMULATION")
    log("=" * 72)

    # ---------- 1. key generation -------------------------------------------
    log(f"\n[SETUP] Generating RSA-{se.RSA_BITS} key pairs (this takes a few seconds each)...")
    s_priv, s_pub = se.generate_keypair("faculty", ROOT / "sender/keys", PASS)
    r_priv, r_pub = se.generate_keypair("coordinator", ROOT / "recipient/keys", PASS)
    a_priv, a_pub = se.generate_keypair("attacker", ROOT / "attacker/keys", PASS)
    # Trusted public-key exchange (assumed done over a trusted channel)
    shutil.copy(s_pub, ROOT / "recipient/trusted/faculty_public.pem")
    shutil.copy(r_pub, ROOT / "sender/trusted/coordinator_public.pem")
    log(f"  private key file mode: {oct(os.stat(s_priv).st_mode & 0o777)} (owner-only), PEM is passphrase-encrypted")
    log("  public keys exchanged into trusted/ folders.")

    # sample exam paper
    paper = ROOT / "sender/input/exam_paper.txt"
    paper.write_text(SAMPLE_PAPER)
    orig_hash = sha(paper)
    log(f"  sample paper : {paper.relative_to(ROOT)}  ({paper.stat().st_size} bytes)")
    log(f"  SHA-256      : {orig_hash}")

    # sender-side encryption
    pkg_path = ROOT / "channel/exam_paper.pkg"
    pkg = se.encrypt_file(paper, pkg_path, "faculty", "coordinator",
                          s_priv, ROOT / "sender/trusted/coordinator_public.pem", PASS)
    log(f"  package sent : {pkg_path.relative_to(ROOT)} ({pkg_path.stat().st_size} bytes)\n")

    good_rkey = r_priv
    good_spub = ROOT / "recipient/trusted/faculty_public.pem"
    inbox = ROOT / "recipient/inbox"

    # ---------- TEST 1 -------------------------------------------------------
    log("-" * 72 + "\nTEST 1: Authorised recipient recovers the original file\n" + "-" * 72)
    dest, msg = try_decrypt(pkg_path, good_rkey, good_spub, inbox)
    ok = dest is not None and sha(dest) == orig_hash
    record("T1 legitimate recovery", "file released, SHA-256 identical to original", ok,
           f"{msg}; recovered SHA-256 = {sha(dest) if dest else 'n/a'}")
    if dest:
        dest.rename(ROOT / "recipient/recovered_exam_paper.txt")   # keep inbox empty for next tests

    # ---------- TEST 2 -------------------------------------------------------
    log("-" * 72 + "\nTEST 2: Attacker modifies ciphertext / metadata / signature (etc.)\n" + "-" * 72)
    attacks = {}
    attacks["2a flip 1 bit in ciphertext"] = flip_b64(pkg, "ciphertext")
    attacks["2b flip 1 bit in signature"] = flip_b64(pkg, "signature")
    attacks["2c flip 1 bit in GCM tag"] = flip_b64(pkg, "tag")
    attacks["2d flip 1 bit in nonce"] = flip_b64(pkg, "nonce")
    attacks["2e flip 1 bit in encrypted session key"] = flip_b64(pkg, "encrypted_session_key")
    m = copy.deepcopy(pkg); m["metadata"]["filename"] = "answer_key.txt"
    attacks["2f metadata: filename changed"] = m
    m = copy.deepcopy(pkg); m["metadata"]["recipient_id"] = "attacker"
    attacks["2g metadata: recipient_id changed"] = m
    m = copy.deepcopy(pkg); m["metadata"]["created_utc"] = "2020-01-01T00:00:00+00:00"
    attacks["2h metadata: timestamp changed"] = m

    for name, bad in attacks.items():
        bad_path = ROOT / "channel" / ("tampered_" + name.split()[0] + ".pkg")
        bad_path.write_text(json.dumps(bad, indent=2))
        before = set(os.listdir(inbox))
        dest, msg = try_decrypt(bad_path, good_rkey, good_spub, inbox)
        leaked = set(os.listdir(inbox)) != before
        log(f"  {name}")
        record(name, "rejected, no plaintext released", dest is None and not leaked,
               msg + ("" if not leaked else "  !!! FILE LEAKED"))

    # ---------- TEST 3 -------------------------------------------------------
    log("-" * 72 + "\nTEST 3: Decryption with an incorrect recipient private key\n" + "-" * 72)
    dest, msg = try_decrypt(pkg_path, a_priv, good_spub, inbox)
    record("T3 wrong recipient private key", "rejected (OAEP unwrap fails), no plaintext", dest is None, msg)

    # ---------- TEST 4 -------------------------------------------------------
    log("-" * 72 + "\nTEST 4: Signature verification with an incorrect sender public key\n" + "-" * 72)
    dest, msg = try_decrypt(pkg_path, good_rkey, a_pub, inbox)
    record("T4 wrong sender public key", "rejected (signature invalid), no plaintext", dest is None, msg)

    # ---------- TEST 5 -------------------------------------------------------
    log("-" * 72 + "\nTEST 5: Same file encrypted twice -> different packages\n" + "-" * 72)
    pkg2_path = ROOT / "channel/exam_paper_second.pkg"
    pkg2 = se.encrypt_file(paper, pkg2_path, "faculty", "coordinator",
                           s_priv, ROOT / "sender/trusted/coordinator_public.pem", PASS)
    diffs = {k: pkg[k] != pkg2[k] for k in ("encrypted_session_key", "nonce", "ciphertext", "tag", "signature")}
    diffs["package_id"] = pkg["metadata"]["package_id"] != pkg2["metadata"]["package_id"]
    for k, v in diffs.items():
        log(f"    {k:<22}: {'DIFFERENT' if v else 'SAME  <-- problem'}")
    log(f"    package 1 ciphertext (first 32 b64 chars): {pkg['ciphertext'][:32]}...")
    log(f"    package 2 ciphertext (first 32 b64 chars): {pkg2['ciphertext'][:32]}...")
    d2, msg = try_decrypt(pkg2_path, good_rkey, good_spub, inbox)
    both_ok = d2 is not None and sha(d2) == orig_hash
    record("T5 fresh key+nonce each time", "all fields differ; both packages decrypt to same file",
           all(diffs.values()) and both_ok, f"{msg}; second package SHA-256 matches original = {both_ok}")
    if d2:
        d2.unlink()

    # ---------- TEST 6 (bonus) ----------------------------------------------
    log("-" * 72 + "\nTEST 6 (bonus): Attacker REPLACES package with own validly-signed fake\n" + "-" * 72)
    fake = ROOT / "attacker/fake_paper.txt"
    fake.write_text("FAKE EXAM - all questions leaked by attacker\n")
    fake_pkg = ROOT / "channel/fake_replacement.pkg"
    se.encrypt_file(fake, fake_pkg, "faculty", "coordinator", a_priv,
                    ROOT / "sender/trusted/coordinator_public.pem", PASS)   # signed with attacker's key
    dest, msg = try_decrypt(fake_pkg, good_rkey, good_spub, inbox)
    record("T6 replacement attack", "rejected - not signed by trusted faculty key", dest is None, msg)

    # ---------- summary --------------------------------------------------------
    log("=" * 72)
    passed = sum(ok for _, ok in results)
    for n, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {n}")
    log(f"\n  {passed}/{len(results)} checks passed")
    log(f"  inbox contents after all attacks: {sorted(os.listdir(inbox)) or 'EMPTY (no unverified plaintext released)'}")
    log("=" * 72)
    return passed == len(results)


SAMPLE_PAPER = """\
INSTITUTE OF TECHNOLOGY - END SEMESTER EXAMINATION (CONFIDENTIAL)
Course: Cryptography and Network Security          Max Marks: 50     Duration: 2 h

Section A (5 x 4 = 20 marks)
 Q1. Differentiate between symmetric and asymmetric encryption with one example each.
 Q2. Why must an AES-GCM nonce never be reused under the same key?
 Q3. Explain how OAEP padding improves on textbook RSA.
 Q4. What security properties does a digital signature provide?
 Q5. Compare RSA-PKCS#1 v1.5 signatures with RSA-PSS.

Section B (3 x 10 = 30 marks)
 Q6. Design a hybrid encryption scheme for sending a large file to a remote party.
     Justify each primitive and the order of operations (sign-then-encrypt vs encrypt-then-sign).
 Q7. An attacker can read and modify traffic. List three active attacks on a naive
     'encrypt-only' file-transfer protocol and how authenticated encryption defeats them.
 Q8. Explain the role of a trusted public-key distribution channel and the consequence
     of a substituted public key.

*** Do not distribute before the examination ***
"""

def in_notebook() -> bool:
    return "ipykernel" in sys.modules or "google.colab" in sys.modules


if __name__ == "__main__":
    all_ok = main()
    if not in_notebook():          # sys.exit() would show an error box inside Colab
        sys.exit(0 if all_ok else 1)
