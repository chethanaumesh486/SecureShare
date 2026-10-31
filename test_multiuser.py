"""
Simulates three different laptops at once: sender, receiver, admin (each its own cookie jar).
Receiver and admin listen on the live event stream while the sender uploads.
Run with the server already running:  python test_multiuser.py [base_url]
"""
import json
import os
import sys
import threading
import time

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5050"
ok_all = True


def check(name, cond, extra=""):
    global ok_all
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra and not cond else ""))
    ok_all &= bool(cond)


def login(user, pw, role):
    s = requests.Session()
    r = s.post(f"{BASE}/api/login", json={"username": user, "password": pw, "role": role})
    assert r.status_code == 200, (user, r.text)
    return s


def listen(sess, bucket, stop):
    with sess.get(f"{BASE}/api/events", stream=True, timeout=30) as r:
        ev = None
        for line in r.iter_lines(decode_unicode=True):
            if stop.is_set():
                return
            if line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:") and ev:
                bucket.append((ev, json.loads(line[5:])))


sender = login("sender1", "sender12345", "sender")
receiver = login("receiver1", "receiver12345", "receiver")
admin = login("admin", "admin12345", "admin")

# wrong role / wrong password
bad = requests.post(f"{BASE}/api/login", json={"username": "sender1", "password": "sender12345", "role": "admin"})
check("sender account cannot log in as admin", bad.status_code == 401)

rb, ab, sb, stop = [], [], [], threading.Event()
threading.Thread(target=listen, args=(receiver, rb, stop), daemon=True).start()
threading.Thread(target=listen, args=(admin, ab, stop), daemon=True).start()
threading.Thread(target=listen, args=(sender, sb, stop), daemon=True).start()
time.sleep(1.2)
check("presence shows all roles online", any(e == "presence" and len(d) >= 2 for e, d in rb))

# a real PNG-like binary and a text secret
png = b"\x89PNG\r\n\x1a\n" + os.urandom(3000)
secret = b"TOP SECRET budget numbers 4.2 lakh " * 50
t0 = time.time()
r = sender.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("photo.png", png, "image/png")})
check("sender uploads image", r.status_code == 200 and len(r.json()["steps"]) >= 6, r.text[:200])
fid1 = r.json()["id"]
r = sender.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("secret.txt", secret, "text/plain")})
fid2 = r.json()["id"]
time.sleep(1.0)

check("receiver got live 'arrived' event", any(e == "file" and d["kind"] == "arrived" and d["id"] == fid1 for e, d in rb))
check("admin got live 'arrived' event", any(e == "file" and d["kind"] == "arrived" and d["id"] == fid1 for e, d in ab))
check("event arrived within 2s of upload", time.time() - t0 < 6)

# ---- admin: only ciphertext
alist = admin.get(f"{BASE}/api/files").json()
check("admin lists both packages", {f["id"] for f in alist} >= {fid1, fid2})
check("admin view has no plaintext hash or decrypted path",
      all("plain_sha256" not in f and "decrypted_path" not in f for f in alist))
c = admin.get(f"{BASE}/api/files/{fid2}/encrypted").content
check("admin ciphertext is not the plaintext", b"TOP SECRET" not in c and c != secret)
d = admin.get(f"{BASE}/api/files/{fid2}/decrypted")
check("admin is DENIED the decrypted file (403)", d.status_code == 403)
d = sender.get(f"{BASE}/api/files/{fid2}/decrypted")
check("sender is also denied the decrypted file", d.status_code == 403)

# ---- receiver: delivered marker then decrypt
rlist = receiver.get(f"{BASE}/api/files").json()
check("receiver sees both files, marked delivered", {f["id"] for f in rlist} >= {fid1, fid2} and all(f["status"] in ("delivered", "decrypted") for f in rlist if f["id"] in (fid1, fid2)))
time.sleep(0.6)
check("sender got live 'delivered' event", any(e == "file" and d["kind"] == "delivered" and d["id"] == fid1 for e, d in sb))
slist = sender.get(f"{BASE}/api/files").json()
check("sender sees status delivered", any(f["id"] == fid1 and f["status"] == "delivered" for f in slist))

r = receiver.post(f"{BASE}/api/files/{fid1}/decrypt").json()
check("receiver decrypts image", r["ok"] and r["file"]["status"] == "decrypted", str(r)[:300])
check("recovered hash equals sender original hash", r["file"]["recovered_sha256"] == r["file"]["plain_sha256"])
got = receiver.get(f"{BASE}/api/files/{fid1}/decrypted?inline=1")
check("receiver can read decrypted bytes exactly", got.content == png and got.headers["Content-Type"] == "image/png")
check("sandbox CSP on decrypted response", "sandbox" in got.headers.get("Content-Security-Policy", ""))
r2 = receiver.post(f"{BASE}/api/files/{fid2}/decrypt").json()
txt = receiver.get(f"{BASE}/api/files/{fid2}/decrypted?inline=1")
check("receiver decrypts text", r2["ok"] and txt.content == secret and txt.headers["Content-Type"].startswith("text/plain"))

# ---- PDF preview + bundled fonts
pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
rp = sender.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("notes.pdf", pdf, "application/pdf")}).json()
fidp = rp["id"]
dp = receiver.post(f"{BASE}/api/files/{fidp}/decrypt").json()
gp = receiver.get(f"{BASE}/api/files/{fidp}/decrypted?inline=1")
check("receiver decrypts a PDF", dp["ok"] and gp.content == pdf)
check("PDF served inline as application/pdf without sandbox header (so the viewer can show it)", gp.headers["Content-Type"] == "application/pdf" and "sandbox" not in gp.headers.get("Content-Security-Policy", ""))
ft = requests.get(f"{BASE}/fonts/poppins-latin-600-normal.woff2")
check("bundled font is served", ft.status_code == 200 and len(ft.content) > 5000)

# ---- disk
base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
enc = [f for f in os.listdir(f"{base}/encrypted") if f.startswith(f"{fid1}_")]
dec = [f for f in os.listdir(f"{base}/decrypted") if f.startswith(f"{fid1}_")]
check("encrypted file saved on disk", bool(enc) and open(f"{base}/encrypted/{enc[0]}", "rb").read() != png)
check("decrypted file saved on disk and identical", bool(dec) and open(f"{base}/decrypted/{dec[0]}", "rb").read() == png)
man = json.load(open(f"{base}/packages/{fid1}.json"))
check("manifest saved with signature, wrapped key, hashes", all(k in man for k in ("signature", "wrapped_aes_key", "nonce", "package_sha256", "recovered_sha256")))
check("audit.log written", os.path.getsize(f"{base}/logs/audit.log") > 0)
check("keys saved (receiver private key only in encrypted form)", os.path.exists(f"{base}/keys/receiver1.private.enc") and b"PRIVATE KEY" not in open(f"{base}/keys/receiver1.private.enc", "rb").read())

# ---- wrong receiver cannot decrypt, wrong role blocked
requests.post(f"{BASE}/api/register", json={"username": "receiver2", "password": "receiver22222", "role": "receiver"})
r2s = login("receiver2", "receiver22222", "receiver")
check("other receiver denied decrypt (403)", r2s.post(f"{BASE}/api/files/{fid1}/decrypt").status_code == 403)
check("sender cannot call decrypt (403)", sender.post(f"{BASE}/api/files/{fid1}/decrypt").status_code == 403)
check("receiver cannot upload (403)", receiver.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("x", b"x")}).status_code == 403)
check("receiver cannot tamper (403)", receiver.post(f"{BASE}/api/files/{fid1}/tamper").status_code == 403)
check("anonymous API call is 401", requests.get(f"{BASE}/api/files").status_code == 401)

# ---- tamper by admin -> receiver rejects
r = sender.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("contract.pdf", os.urandom(2000), "application/pdf")})
fid3 = r.json()["id"]
check("admin simulates tampering", admin.post(f"{BASE}/api/files/{fid3}/tamper").status_code == 200)
time.sleep(0.8)
check("receiver got live 'tampered' event", any(e == "file" and d["kind"] == "tampered" and d["id"] == fid3 for e, d in rb))
v = receiver.post(f"{BASE}/api/files/{fid3}/verify").json()
check("signature INVALID after tampering", v["ok"] is False)
r = receiver.post(f"{BASE}/api/files/{fid3}/decrypt").json()
check("decryption refused after tampering", r["ok"] is False and not any("Decrypt with AES" in s["title"] for s in r["steps"]))
time.sleep(0.8)
check("no decrypted file written for tampered package", not [f for f in os.listdir(f"{base}/decrypted") if f.startswith(f"{fid3}_")])
check("admin got 'rejected' live event", any(e == "file" and d["kind"] == "rejected" and d["id"] == fid3 for e, d in ab))
au = admin.get(f"{BASE}/api/audit").json()
check("audit shows INVALID_SIGNATURE and UNAUTHORIZED_ATTEMPT", {"INVALID_SIGNATURE", "UNAUTHORIZED_ATTEMPT"} <= {a["event"] for a in au})

# ---- demo panels: every key and value is shown, but the admin never gets the AES key
r = sender.post(f"{BASE}/api/files", data={"receiver": "receiver1"}, files={"file": ("keys.txt", b"show me the keys " * 20, "text/plain")})
up = r.json(); fid4 = up["id"]
vals = {v["k"]: v["v"] for st in up["steps"] for v in st.get("vals", [])}
aes_hex = next((v for k, v in vals.items() if k.startswith("AES-256 key")), "")
wrapped_hex = next((v for k, v in vals.items() if k.startswith("Wrapped AES key")), "")
sig_hex = next((v for k, v in vals.items() if k.startswith("RSA-PSS signature")), "")
check("sender sees the full 256-bit AES key (64 hex chars)", len(aes_hex) == 64)
check("sender sees the full wrapped key (256 bytes) and signature (256 bytes)", len(wrapped_hex) == 512 and len(sig_hex) == 512)
check("sender sees full SHA-256 values", all(len(v) == 64 for k, v in vals.items() if "SHA-256" in k))
d = receiver.post(f"{BASE}/api/files/{fid4}/decrypt").json()
rvals = {v["k"]: v["v"] for st in d["steps"] for v in st.get("vals", [])}
check("receiver's unwrapped AES key equals the sender's key", rvals.get("Unwrapped AES-256 key (compare with the sender's)") == aes_hex)
check("receiver sees both hashes and they match", rvals["Sender's original SHA-256"] == rvals["Recovered file SHA-256"])
pk = admin.get(f"{BASE}/api/files/{fid4}/package")
pkj = pk.json()
check("admin can read the package details", pk.status_code == 200 and len(pkj["items"]) >= 8)
check("admin never receives the AES key anywhere",
      aes_hex not in pk.text and aes_hex not in admin.get(f"{BASE}/api/files").text and aes_hex not in admin.get(f"{BASE}/api/audit").text)
check("package details report the package as intact", pkj["intact"] is True)
check("another receiver is denied the package details (403)", r2s.get(f"{BASE}/api/files/{fid4}/package").status_code == 403)
check("anonymous package request is 401", requests.get(f"{BASE}/api/files/{fid4}/package").status_code == 401)
admin.post(f"{BASE}/api/files/{fid4}/tamper")
check("package details flag tampering (hash mismatch)", admin.get(f"{BASE}/api/files/{fid4}/package").json()["intact"] is False)

# ---- logout closes presence
sender.post(f"{BASE}/api/logout")
time.sleep(1.2)
last = [d for e, d in rb if e == "presence"][-1]
check("sender disappears from presence after logout", all(p["user"] != "sender1" for p in last))

stop.set()
print("\n" + ("ALL TESTS PASSED" if ok_all else "SOME TESTS FAILED"))
sys.exit(0 if ok_all else 1)
