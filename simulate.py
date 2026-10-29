#!/usr/bin/env python3
"""
simulate.py - End-to-end simulation of the secure exam-paper exchange.

Folder layout created next to this script (one computer, separate "machines"):

  sender/      keys/ (faculty private+public)   trusted/ (coordinator public)   input/ (paper)
  recipient/   keys/ (coordinator private+public) trusted/ (faculty public)     inbox/ (released plaintext)
  channel/     untrusted network - packages travel (and get attacked) here
  attacker/    attacker's own keys (used for wrong-key tests)
"""
import copy
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import secure_exam as se

ROOT = Path(__file__).parent.resolve()
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
               msg + ("" if not leaked else "  !!! FILE LEAKED")); 

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
    sys.exit(0 if passed == len(results) else 1)


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

if __name__ == "__main__":
    main()
