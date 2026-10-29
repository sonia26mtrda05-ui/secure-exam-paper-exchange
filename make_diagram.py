#!/usr/bin/env python3
"""Generates sequence_diagram.svg (no external dependencies)."""
from xml.sax.saxutils import escape
W, H = 1100, 1010
X = {"S": 150, "C": 550, "R": 950}
names = {"S": "Faculty (Sender)", "C": "Untrusted Channel / Attacker", "R": "Coordinator (Recipient)"}
# (kind, from, to, text)   kind: msg | self | note | fail
steps = [
 ("note","S","S","SETUP: RSA-4096 key pair; private key passphrase-encrypted"),
 ("note","R","R","SETUP: RSA-4096 key pair; private key passphrase-encrypted"),
 ("msg","S","R","public key (trusted channel, out-of-band)"),
 ("msg","R","S","public key (trusted channel, out-of-band)"),
 ("self","S","S","1. random AES-256 session key K + fresh 96-bit nonce"),
 ("self","S","S","2. (ciphertext, tag) = AES-GCM(K, nonce, paper, AAD=metadata)"),
 ("self","S","S","3. EK = RSA-OAEP-SHA256(Recipient public key, K)"),
 ("self","S","S","4. sig = RSA-PSS-SHA256(Sender private key, package)"),
 ("msg","S","C","package {metadata, EK, nonce, ciphertext, tag, sig}"),
 ("note","C","C","attacker may read / modify / replace / drop"),
 ("msg","C","R","package (possibly altered)"),
 ("self","R","R","5. verify sig with TRUSTED sender public key"),
 ("fail","R","R","invalid -> REJECT (nothing decrypted, nothing written)"),
 ("self","R","R","6. K = RSA-OAEP-decrypt(Recipient private key, EK)"),
 ("fail","R","R","wrong key -> REJECT"),
 ("self","R","R","7. AES-GCM decrypt: verify tag over ciphertext + metadata"),
 ("fail","R","R","tag mismatch -> REJECT"),
 ("self","R","R","8. all checks passed -> write plaintext to inbox"),
]
y0, dy = 130, 46
o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="Helvetica,Arial,sans-serif" font-size="14">',
     '<defs><marker id="a" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto"><path d="M0,0 L10,4 L0,8 z" fill="#222"/></marker></defs>',
     f'<rect width="{W}" height="{H}" fill="#fff"/>',
     '<text x="550" y="32" text-anchor="middle" font-size="20" font-weight="bold">Secure Exam-Paper Exchange - Sequence of Events</text>']
for k, x in X.items():
    o.append(f'<rect x="{x-110}" y="50" width="220" height="40" rx="6" fill="#e8f0fe" stroke="#1a4fa0"/>')
    o.append(f'<text x="{x}" y="75" text-anchor="middle" font-weight="bold">{escape(names[k])}</text>')
    o.append(f'<line x1="{x}" y1="90" x2="{x}" y2="{H-30}" stroke="#888" stroke-dasharray="5,4"/>')
for i, (kind, a, b, t) in enumerate(steps):
    y = y0 + i * dy
    xa, xb = X[a], X[b]
    if kind == "msg":
        o.append(f'<line x1="{xa}" y1="{y}" x2="{xb}" y2="{y}" stroke="#222" stroke-width="1.6" marker-end="url(#a)"/>')
        o.append(f'<text x="{(xa+xb)/2}" y="{y-7}" text-anchor="middle">{escape(t)}</text>')
    elif kind in ("self", "fail"):
        col = ("#fff4e5", "#c77700") if kind == "self" else ("#fdecea", "#b3261e")
        w = 440
        x = xa - 20 if a == "S" else (xa - w/2 if a == "C" else xa - w + 20)
        o.append(f'<rect x="{x}" y="{y-17}" width="{w}" height="30" rx="5" fill="{col[0]}" stroke="{col[1]}"/>')
        o.append(f'<text x="{x+w/2}" y="{y+3}" text-anchor="middle" fill="{"#222" if kind=="self" else "#b3261e"}">{escape(t)}</text>')
    else:
        w = 330
        x = xa - w/2 if a == "C" else (xa - 20 if a == "S" else xa - w + 20)
        o.append(f'<rect x="{x}" y="{y-17}" width="{w}" height="30" rx="5" fill="#f1f3f4" stroke="#777" stroke-dasharray="3,3"/>')
        o.append(f'<text x="{x+w/2}" y="{y+3}" text-anchor="middle" font-style="italic">{escape(t)}</text>')
o.append('</svg>')
open("sequence_diagram.svg", "w").write("\n".join(o))
print("sequence_diagram.svg written")
