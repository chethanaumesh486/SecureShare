"""
SecureShare: real-time secure file sharing between three roles on different computers.

  Sender   encrypts (AES-256-GCM), wraps the key (RSA-OAEP) and signs (RSA-PSS)
  Admin    sees ONLY encrypted packages (admin holds no keys, so cannot decrypt)
  Receiver verifies the signature, unwraps the key and sees the decrypted file

Everything is saved under ./data  (encrypted/, decrypted/, packages/, keys/, logs/).
Live updates are pushed to every browser with Server-Sent Events.
"""
import base64
import json
import mimetypes
import os
import queue
import secrets
import socket
import sqlite3
import threading
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, g, jsonify, request, send_file, send_from_directory
from flask import session as _cookie
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import crypto_utils as cu


class _TabSession:
    """Login state kept per browser tab (not per browser).

    Browsers share one cookie across all tabs of the same site, so logging in as the
    receiver in a second tab used to overwrite the sender's login in the first tab.
    The page sends a random tab id (header X-Tab, or ?t= for images/streams) and the
    login state is stored under that id inside the signed cookie."""

    def _tab(self):
        t = request.headers.get("X-Tab") or request.args.get("t") or "default"
        return t[:40]

    def _d(self):
        tabs = _cookie.get("tabs")
        if not isinstance(tabs, dict):
            tabs = {}
        return tabs, tabs.get(self._tab(), {})

    def get(self, k, default=None):
        return self._d()[1].get(k, default)

    def __getitem__(self, k):
        return self._d()[1][k]

    def update(self, **kw):
        tabs, d = self._d()
        d = dict(d, **kw)
        tabs[self._tab()] = d
        while len(tabs) > 12:                      # keep the cookie small
            tabs.pop(next(iter(tabs)))
        _cookie["tabs"] = tabs
        _cookie.modified = True

    def clear(self):
        tabs, _ = self._d()
        tabs.pop(self._tab(), None)
        _cookie["tabs"] = tabs
        _cookie.modified = True


session = _TabSession()

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DIRS = {k: DATA / k for k in ("encrypted", "decrypted", "packages", "keys", "logs")}
for d in DIRS.values():
    d.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "secureshare.db"

# ---- deployment settings, all from environment variables (defaults keep the local demo unchanged)
PUBLIC = os.environ.get("PUBLIC_MODE", "0") == "1"            # 1 = running on the public internet
MAX_UPLOAD = int(float(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024)
MAX_USERS = int(os.environ.get("MAX_USERS", "0"))              # 0 = no limit on registered accounts
RETAIN_HOURS = float(os.environ.get("RETAIN_HOURS", "0"))      # 0 = never delete; otherwise delete files after N hours
SEED_DEMO = os.environ.get("SEED_DEMO", "0" if PUBLIC else "1") == "1"   # create sender1/receiver1 with known passwords
BANNER = os.environ.get("PUBLIC_BANNER", "Demo system for a lab project. Do not upload anything sensitive. "
                        "Files are deleted automatically and the server restarts often.")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 1024 * 1024
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "1" if PUBLIC else "0") == "1"
if PUBLIC:
    # behind the host's HTTPS proxy: trust its forwarded address and scheme so IP limits and Secure cookies work
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_secret = DATA / "secret.key"
if not _secret.exists():
    _secret.write_text(secrets.token_hex(32))
app.secret_key = os.environ.get("SECRET_KEY") or _secret.read_text().strip()

UNLOCKED = {}          # sid -> {"role":..., "key": private-key PEM}  (memory only)
FAILS = {}             # username -> (count, locked_until)
SUBS, LOCK = [], threading.Lock()
b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)
now = time.time


# ------------------------------------------------------------------ database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    c = g.pop("db", None)
    if c:
        c.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
        password_hash TEXT NOT NULL, pub BLOB, priv_enc BLOB, created_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL,
        sender TEXT NOT NULL, receiver TEXT NOT NULL, stored_name TEXT NOT NULL,
        nonce BLOB NOT NULL, tag BLOB NOT NULL, wrapped BLOB NOT NULL, signature BLOB NOT NULL,
        package_sha256 TEXT NOT NULL, plain_sha256 TEXT NOT NULL, cipher_size INTEGER NOT NULL,
        status TEXT NOT NULL, created_at REAL NOT NULL, delivered_at REAL, decrypted_at REAL,
        decrypted_name TEXT, recovered_sha256 TEXT);
    CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT, event TEXT NOT NULL,
        detail TEXT, involved TEXT);
    """)
    c.commit()
    c.close()


def create_user(username, password, role):
    """Sender gets a signing key pair, receiver gets an encryption key pair, admin gets none."""
    pub = priv_enc = None
    if role in ("sender", "receiver"):
        pub, priv = cu.generate_rsa_keypair()
        priv_enc = cu.protect_private_key(priv, password)
        (DIRS["keys"] / f"{username}.public.pem").write_bytes(pub)
        (DIRS["keys"] / f"{username}.private.enc").write_bytes(priv_enc)
    c = sqlite3.connect(DB_PATH)
    c.execute("INSERT INTO users(username,role,password_hash,pub,priv_enc,created_at) VALUES(?,?,?,?,?,?)",
              (username, role, generate_password_hash(password), pub, priv_enc, now()))
    c.commit()
    c.close()


# --------------------------------------------------------------- live events
def push(event, data, users=None, roles=None):
    msg = {"event": event, "data": data}
    with LOCK:
        for s in list(SUBS):
            if (users is None and roles is None) or (users and s["user"] in users) or (roles and s["role"] in roles):
                s["q"].put(msg)


def presence():
    with LOCK:
        seen = {}
        for s in SUBS:
            seen[(s["user"], s["role"])] = True
    return [{"user": u, "role": r} for (u, r) in sorted(seen)]


def audit(event, detail="", actor=None, involved=()):
    actor = actor or session.get("username", "-")
    inv = sorted({actor, *involved} - {"-"})
    ts = now()
    db().execute("INSERT INTO audit(ts,actor,event,detail,involved) VALUES(?,?,?,?,?)",
                 (ts, actor, event, detail, ",".join(inv)))
    db().commit()
    entry = {"ts": ts, "actor": actor, "event": event, "detail": detail}
    with open(DIRS["logs"] / "audit.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    push("audit", entry, users=inv, roles=["admin"])


# ------------------------------------------------------------------- helpers
def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            sid = session.get("sid")
            if not sid or sid not in UNLOCKED:
                session.clear()
                return jsonify(error="Please log in."), 401
            if session["role"] not in roles:
                audit("UNAUTHORIZED_ATTEMPT", f"{session['role']} tried {request.method} {request.path}")
                return jsonify(error="Your role is not allowed to do that."), 403
            return fn(*a, **kw)
        return wrap
    return deco


def safe_write(path, data):
    """Write a file so it is really on disk (and visible in the folder) before we go on.

    Writes to a temporary file, flushes it to the disk, then renames it into place, so a
    half-written file is never seen. Reads the size back and raises a clear error if the
    file did not land where we expect."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    tmp = path.with_name(path.name + ".part")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    if not path.is_file() or path.stat().st_size != len(data):
        raise OSError(f"Could not save {path}")
    return path


def check_folders():
    """At start-up, prove that every data folder can really be written to."""
    for name, d in DIRS.items():
        probe = d / ".write_test"
        try:
            safe_write(probe, b"ok")
            probe.unlink()
        except OSError as e:
            raise SystemExit(f"\n  ERROR: cannot write to {d}\n  {e}\n  Move the project to a normal folder "
                             f"(for example your Desktop or Documents) and try again.\n")


def sync_manifests():
    """Make sure every file has an up-to-date .json in data/packages (also repairs old/missing ones)."""
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    for r in c.execute("SELECT * FROM files").fetchall():
        save_manifest(r)
    c.close()


def rel(p):
    return str(Path(p).relative_to(BASE))


HITS = {}              # (bucket, ip) -> recent request times, for the per-IP limits in public mode


def too_many(bucket, limit, window):
    """True if this IP has made `limit` requests to `bucket` in the last `window` seconds (public mode only)."""
    if not PUBLIC:
        return False
    t, key = now(), (bucket, request.remote_addr or "?")
    recent = [x for x in HITS.get(key, []) if t - x < window]
    if len(recent) >= limit:
        HITS[key] = recent
        return True
    HITS[key] = recent + [t]
    if len(HITS) > 5000:                      # keep memory bounded
        for k in [k for k, v in HITS.items() if not v or t - v[-1] > 3600]:
            HITS.pop(k, None)
    return False


def purge_old():
    """Delete files (and their database rows) older than RETAIN_HOURS. Returns how many were removed."""
    if not RETAIN_HOURS:
        return 0
    cutoff = now() - RETAIN_HOURS * 3600
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    rows = c.execute("SELECT id,stored_name,decrypted_name FROM files WHERE created_at<?", (cutoff,)).fetchall()
    for r in rows:
        targets = [DIRS["encrypted"] / Path(r["stored_name"]).name, DIRS["packages"] / f"{r['id']}.json"]
        if r["decrypted_name"]:
            targets.append(DIRS["decrypted"] / Path(r["decrypted_name"]).name)
        for t in targets:
            try:
                t.unlink()
            except OSError:
                pass
    c.execute("DELETE FROM files WHERE created_at<?", (cutoff,))
    c.commit()
    c.close()
    if rows:
        with app.app_context():
            audit("FILES_PURGED", f"{len(rows)} file(s) older than {RETAIN_HOURS:g} h deleted", actor="system")
    return len(rows)


def start_background():
    """Clean-up thread (only does anything when RETAIN_HOURS is set)."""
    def loop():
        while True:
            time.sleep(600)
            try:
                purge_old()
            except Exception as e:                 # never let the clean-up thread die
                print("purge error:", e)
    if RETAIN_HOURS:
        threading.Thread(target=loop, daemon=True).start()


def kv(label, value):
    """One labelled value for the demo panels (bytes are shown as hex)."""
    return {"k": label, "v": value.hex() if isinstance(value, (bytes, bytearray)) else str(value)}


def view(r, role, me):
    """Return a file row exactly as the given role is allowed to see it."""
    d = dict(id=r["id"], name=r["name"], mime=r["mime"], size=r["size"], sender=r["sender"],
             receiver=r["receiver"], status=r["status"], created_at=r["created_at"],
             delivered_at=r["delivered_at"], decrypted_at=r["decrypted_at"], cipher_size=r["cipher_size"],
             package_sha256=r["package_sha256"],
             encrypted_path=str(DIRS["encrypted"] / r["stored_name"]),
             algorithm="AES-256-GCM + RSA-2048 OAEP + RSA-PSS")
    if role == "sender":
        d["plain_sha256"] = r["plain_sha256"]
    if role == "receiver":
        d["plain_sha256"] = r["plain_sha256"]
        d["recovered_sha256"] = r["recovered_sha256"]
        if r["decrypted_name"]:
            d["decrypted_path"] = str(DIRS["decrypted"] / r["decrypted_name"])
    return d  # admin gets neither plaintext hash nor decrypted path


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def save_manifest(r):
    m = dict(id=r["id"], name=r["name"], mime=r["mime"], size=r["size"], sender=r["sender"],
             receiver=r["receiver"], status=r["status"], created_at=r["created_at"],
             algorithms=dict(file="AES-256-GCM", key_wrap="RSA-2048 OAEP (SHA-256)", hash="SHA-256", signature="RSA-PSS"),
             encrypted_file=rel(DIRS["encrypted"] / r["stored_name"]), nonce=b64(r["nonce"]), gcm_tag=b64(r["tag"]),
             wrapped_aes_key=b64(r["wrapped"]), signature=b64(r["signature"]), package_sha256=r["package_sha256"],
             plaintext_sha256=r["plain_sha256"], delivered_at=r["delivered_at"], decrypted_at=r["decrypted_at"],
             decrypted_file=rel(DIRS["decrypted"] / r["decrypted_name"]) if r["decrypted_name"] else None,
             recovered_sha256=r["recovered_sha256"])
    safe_write(DIRS["packages"] / f"{r['id']}.json", json.dumps(m, indent=2))


def get_file(fid):
    return db().execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()


# -------------------------------------------------------------------- pages
@app.route("/")
def index():
    r = send_from_directory(BASE / "static", "index.html")
    r.headers["Cache-Control"] = "no-store"   # always load the newest page, never a stale copy
    return r


@app.route("/fonts/<path:name>")
def fonts(name):
    resp = send_from_directory(BASE / "static" / "fonts", name)
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp


@app.get("/api/health")
def health():
    return jsonify(ok=True, public=PUBLIC, banner=BANNER if PUBLIC else "", data_dir=None if PUBLIC else str(DATA))


@app.errorhandler(Exception)
def on_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description), e.code
        return e
    app.logger.exception(e)
    return jsonify(error="Server error. See the server window for details."), 500


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.after_request
def headers(resp):
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    if PUBLIC:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


# --------------------------------------------------------------------- auth
@app.post("/api/register")
def register():
    j = request.get_json(silent=True) or {}
    u, p, role = str(j.get("username", "")).strip(), str(j.get("password", "")), j.get("role")
    if too_many("register", 10, 600):
        return jsonify(error="Too many sign-ups from your network. Try again in a few minutes."), 429
    if role not in ("sender", "receiver"):
        return jsonify(error="Only sender and receiver accounts can be self-registered."), 400
    if MAX_USERS and db().execute("SELECT COUNT(*) FROM users").fetchone()[0] >= MAX_USERS:
        return jsonify(error="This demo is full: no more accounts can be created right now."), 403
    if len(u) < 3 or len(u) > 20 or not u.replace("_", "").isalnum():
        return jsonify(error="Username: 3-20 letters, digits or underscores."), 400
    if len(p) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    if db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify(error="That username is taken."), 409
    create_user(u, p, role)
    audit("USER_REGISTERED", f"{u} as {role}" + (" (RSA-2048 key pair generated)"), actor=u)
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    j = request.get_json(silent=True) or {}
    u, p, role = str(j.get("username", "")).strip(), str(j.get("password", "")), j.get("role")
    if too_many("login", 40, 60):
        return jsonify(error="Too many attempts from your network. Wait a minute."), 429
    cnt, until = FAILS.get(u, (0, 0))
    if until > now():
        return jsonify(error=f"Too many attempts. Try again in {int(until - now())}s."), 429
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not row or row["role"] != role or not check_password_hash(row["password_hash"], p):
        cnt += 1
        FAILS[u] = (cnt, now() + 60 if cnt >= 5 else 0)
        audit("LOGIN_FAILED", f"username={u or '-'} as {role}", actor=u or "-")
        return jsonify(error="Invalid username, password or role."), 401
    FAILS.pop(u, None)
    key = None
    if row["priv_enc"]:
        try:
            key = cu.unlock_private_key(row["priv_enc"], p)
        except ValueError:
            return jsonify(error="Could not unlock your private key."), 500
    session.clear()
    sid = secrets.token_hex(16)
    UNLOCKED[sid] = {"role": row["role"], "key": key}
    session.update(sid=sid, username=row["username"], role=row["role"])
    audit("LOGIN", "private key unlocked in server memory" if key else "no private key (admin cannot decrypt)")
    return jsonify(user=row["username"], role=row["role"], data_dir=str(DATA))


@app.post("/api/logout")
def logout():
    if session.get("sid"):
        audit("LOGOUT")
        with LOCK:
            for s in [x for x in SUBS if x["sid"] == session["sid"]]:
                s["q"].put({"event": "__close__", "data": None})
    UNLOCKED.pop(session.get("sid"), None)
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if session.get("sid") in UNLOCKED:
        return jsonify(user=session["username"], role=session["role"], data_dir=None if PUBLIC else str(DATA))
    return jsonify(user=None)


@app.get("/api/receivers")
@role_required("sender")
def receivers():
    online = {p["user"] for p in presence()}
    rows = db().execute("SELECT username FROM users WHERE role='receiver' ORDER BY username").fetchall()
    return jsonify([{"user": r["username"], "online": r["username"] in online} for r in rows])


# ------------------------------------------------------------- live stream
@app.get("/api/events")
@role_required("admin", "sender", "receiver")
def events():
    sub = {"user": session["username"], "role": session["role"], "sid": session["sid"], "q": queue.Queue()}
    with LOCK:
        SUBS.append(sub)
    push("presence", presence())

    def gen():
        try:
            yield "retry: 2000\n\n"
            yield f"event: presence\ndata: {json.dumps(presence())}\n\n"
            while True:
                try:
                    m = sub["q"].get(timeout=5)
                    if m["event"] == "__close__":
                        return
                    yield f"event: {m['event']}\ndata: {json.dumps(m['data'])}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with LOCK:
                if sub in SUBS:
                    SUBS.remove(sub)
            push("presence", presence())

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -------------------------------------------------------------------- files
@app.get("/api/files")
@role_required("admin", "sender", "receiver")
def list_files():
    role, u = session["role"], session["username"]
    if role == "admin":
        rows = db().execute("SELECT * FROM files ORDER BY id DESC").fetchall()
    elif role == "sender":
        rows = db().execute("SELECT * FROM files WHERE sender=? ORDER BY id DESC", (u,)).fetchall()
    else:
        rows = db().execute("SELECT * FROM files WHERE receiver=? ORDER BY id DESC", (u,)).fetchall()
        for r in rows:  # receiver's client has now seen the package: mark as delivered
            if r["status"] == "encrypted":
                db().execute("UPDATE files SET status='delivered', delivered_at=? WHERE id=?", (now(), r["id"]))
                db().commit()
                save_manifest(get_file(r["id"]))   # keep packages/<id>.json in step with the status
                audit("FILE_DELIVERED", f"{r['name']} reached {u}", involved=[r["sender"]])
                push("file", {"kind": "delivered", "id": r["id"], "name": r["name"], "sender": r["sender"], "receiver": u},
                     users=[r["sender"]], roles=["admin"])
        rows = db().execute("SELECT * FROM files WHERE receiver=? ORDER BY id DESC", (u,)).fetchall()
    return jsonify([view(r, role, u) for r in rows])


@app.post("/api/files")
@role_required("sender")
def upload():
    if too_many("upload", 30, 600):
        return jsonify(error="Too many uploads from your network. Try again in a few minutes."), 429
    f = request.files.get("file")
    to = request.form.get("receiver", "")
    rec = db().execute("SELECT * FROM users WHERE username=? AND role='receiver'", (to,)).fetchone()
    if not f or not f.filename or not rec:
        return jsonify(error="Choose a file and a receiver."), 400
    plaintext = f.read()
    if not plaintext:
        return jsonify(error="That file is empty."), 400
    if len(plaintext) > MAX_UPLOAD:
        return jsonify(error=f"File is over {MAX_UPLOAD // (1024 * 1024)} MB."), 413

    sender = session["username"]
    name = os.path.basename(f.filename)[:120]
    mime = f.mimetype or "application/octet-stream"
    if mime == "application/octet-stream":
        mime = mimetypes.guess_type(name)[0] or mime
    mime = mime[:100]
    steps = []

    def step(title, detail, t0, vals=None):
        steps.append({"title": title, "detail": detail, "vals": vals or [],
                      "ms": round((time.perf_counter() - t0) * 1000, 1)})

    t0 = time.perf_counter()
    plain_hash = cu.sha256_hex(plaintext)
    step("Read file and fingerprint it", f"{name} · {len(plaintext):,} bytes · plaintext SHA-256 {plain_hash[:32]}…", t0,
         [kv("Plaintext SHA-256", plain_hash)])

    t0 = time.perf_counter()
    aes_key, nonce, tag, ciphertext = cu.aes_encrypt(plaintext)
    step("Encrypt with AES-256-GCM (new random key)",
         f"nonce {nonce.hex()} · ciphertext {len(ciphertext):,} bytes · starts {ciphertext[:12].hex()}…", t0,
         [kv("AES-256 key (secret: shown only to you, never stored)", aes_key), kv("Nonce", nonce),
          kv("GCM authentication tag", tag),
          kv(f"Ciphertext (first 32 of {len(ciphertext):,} bytes)", ciphertext[:32])])

    t0 = time.perf_counter()
    wrapped = cu.wrap_key(aes_key, rec["pub"])
    step(f"Wrap AES key with {to}'s RSA public key (OAEP)",
         f"32-byte key becomes a {len(wrapped)}-byte wrapped key · {wrapped[:12].hex()}…", t0,
         [kv(f"{to}'s public key SHA-256 fingerprint", cu.sha256_hex(rec["pub"])),
          kv(f"Wrapped AES key ({len(wrapped)} bytes)", wrapped)])

    t0 = time.perf_counter()
    h = cu.package_hash(name, mime, sender, to, nonce, tag, wrapped, ciphertext)
    step("Hash the whole package (SHA-256)", f"covers name, type, sender, receiver, nonce, tag, wrapped key, ciphertext · {h.hexdigest()[:32]}…", t0,
         [kv("Package SHA-256", h.hexdigest())])

    t0 = time.perf_counter()
    sig = cu.sign(h, UNLOCKED[session["sid"]]["key"])
    step(f"Sign with {sender}'s RSA private key (PSS)", f"{len(sig)}-byte signature · {sig[:12].hex()}…", t0,
         [kv(f"RSA-PSS signature ({len(sig)} bytes)", sig)])

    t0 = time.perf_counter()
    cur = db().execute(
        "INSERT INTO files(name,mime,size,sender,receiver,stored_name,nonce,tag,wrapped,signature,package_sha256,"
        "plain_sha256,cipher_size,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (name, mime, len(plaintext), sender, to, "pending", nonce, tag, wrapped, sig, h.hexdigest(), plain_hash,
         len(ciphertext), "encrypted", now()))
    fid = cur.lastrowid
    stored = f"{fid}_{secure_filename(name) or 'file'}.enc"
    db().execute("UPDATE files SET stored_name=? WHERE id=?", (stored, fid))
    db().commit()
    safe_write(DIRS["encrypted"] / stored, ciphertext)
    row = get_file(fid)
    save_manifest(row)
    enc_path = DIRS["encrypted"] / stored
    step("Save to the server's disk",
         f"{enc_path} ({enc_path.stat().st_size:,} bytes, confirmed on disk) and {DIRS['packages'] / (str(fid) + '.json')}. The plaintext is never written.", t0)

    audit("FILE_UPLOADED", f"{name} → {to} ({len(plaintext):,} bytes, encrypted)", involved=[to])
    ev = {"kind": "arrived", "id": fid, "name": name, "sender": sender, "receiver": to, "size": len(plaintext)}
    push("file", ev, users=[to, sender], roles=["admin"])
    return jsonify(id=fid, steps=steps, file=view(row, "sender", sender))


def read_cipher(r):
    return (DIRS["encrypted"] / r["stored_name"]).read_bytes()


@app.get("/api/files/<int:fid>/encrypted")
@role_required("admin", "sender", "receiver")
def get_encrypted(fid):
    r = get_file(fid)
    role, u = session["role"], session["username"]
    if not r or (role != "admin" and u not in (r["sender"], r["receiver"])):
        audit("UNAUTHORIZED_ATTEMPT", f"encrypted file #{fid} denied")
        return jsonify(error="Not allowed."), 403
    return send_file(DIRS["encrypted"] / r["stored_name"], mimetype="application/octet-stream")


@app.get("/api/files/<int:fid>/package")
@role_required("admin", "sender", "receiver")
def get_package(fid):
    """Every non-secret value of a package, for the demo panels. The AES key is never stored, so it is not here."""
    r = get_file(fid)
    role, u = session["role"], session["username"]
    if not r or (role != "admin" and u not in (r["sender"], r["receiver"])):
        audit("UNAUTHORIZED_ATTEMPT", f"package details of file #{fid} denied")
        return jsonify(error="Not allowed."), 403
    ct = read_cipher(r)
    pubs = {x["username"]: x["pub"] for x in db().execute(
        "SELECT username,pub FROM users WHERE username IN (?,?)", (r["sender"], r["receiver"]))}
    h = cu.package_hash(r["name"], r["mime"], r["sender"], r["receiver"], r["nonce"], r["tag"], r["wrapped"], ct)
    intact = h.hexdigest() == r["package_sha256"] and cu.verify(h, r["signature"], pubs[r["sender"]])
    items = [
        kv("Nonce", r["nonce"]),
        kv("GCM authentication tag", r["tag"]),
        kv(f"Wrapped AES key ({len(r['wrapped'])} bytes, only {r['receiver']}'s private key can open it)", r["wrapped"]),
        kv(f"Ciphertext (first 32 of {len(ct):,} bytes)", ct[:32]),
        kv("Package SHA-256 (as signed)", r["package_sha256"]),
        kv("Package SHA-256 (recomputed from disk now)", h.hexdigest()),
        kv(f"RSA-PSS signature ({len(r['signature'])} bytes)", r["signature"]),
        kv(f"{r['sender']}'s public key SHA-256 fingerprint", cu.sha256_hex(pubs[r["sender"]])),
        kv(f"{r['receiver']}'s public key SHA-256 fingerprint", cu.sha256_hex(pubs[r["receiver"]])),
    ]
    return jsonify(items=items, intact=intact)


@app.post("/api/files/<int:fid>/verify")
@role_required("sender", "receiver")
def verify_file(fid):
    r = get_file(fid)
    u = session["username"]
    if not r or u not in (r["sender"], r["receiver"]):
        audit("UNAUTHORIZED_ATTEMPT", f"verify of file #{fid} denied")
        return jsonify(error="Not allowed."), 403
    pub = db().execute("SELECT pub FROM users WHERE username=?", (r["sender"],)).fetchone()["pub"]
    h = cu.package_hash(r["name"], r["mime"], r["sender"], r["receiver"], r["nonce"], r["tag"], r["wrapped"], read_cipher(r))
    ok = cu.verify(h, r["signature"], pub)
    audit("SIGNATURE_VERIFIED" if ok else "INVALID_SIGNATURE", f"{r['name']} (manual check)", involved=[r["sender"], r["receiver"]])
    return jsonify(ok=ok)


@app.post("/api/files/<int:fid>/decrypt")
@role_required("receiver")
def decrypt_file(fid):
    r = get_file(fid)
    u = session["username"]
    if not r or r["receiver"] != u:
        audit("UNAUTHORIZED_ATTEMPT", f"decrypt of file #{fid} denied")
        return jsonify(error="This file was not shared with you."), 403
    steps = []

    def step(title, detail, t0, ok=True, vals=None):
        steps.append({"title": title, "detail": detail, "vals": vals or [],
                      "ms": round((time.perf_counter() - t0) * 1000, 1), "ok": ok})

    t0 = time.perf_counter()
    ciphertext = read_cipher(r)
    step("Access control", f"{u} is the intended receiver · read {len(ciphertext):,} bytes from disk", t0)

    t0 = time.perf_counter()
    pub = db().execute("SELECT pub FROM users WHERE username=?", (r["sender"],)).fetchone()["pub"]
    h = cu.package_hash(r["name"], r["mime"], r["sender"], r["receiver"], r["nonce"], r["tag"], r["wrapped"], ciphertext)
    ok = cu.verify(h, r["signature"], pub)
    step(f"Verify {r['sender']}'s RSA-PSS signature",
         "Signature valid: the package is exactly what the sender signed." if ok else
         "Signature INVALID: the stored package was changed after it was signed. Decryption refused.", t0, ok,
         [kv("Package SHA-256 recomputed now", h.hexdigest()), kv("Package SHA-256 the sender signed", r["package_sha256"]),
          kv("Sender's signature", r["signature"])])
    if not ok:
        db().execute("UPDATE files SET status='rejected' WHERE id=?", (fid,))
        db().commit()
        audit("INVALID_SIGNATURE", f"{r['name']} from {r['sender']}: decryption BLOCKED", involved=[r["sender"]])
        push("file", {"kind": "rejected", "id": fid, "name": r["name"], "sender": r["sender"], "receiver": u},
             users=[r["sender"], u], roles=["admin"])
        save_manifest(get_file(fid))
        return jsonify(ok=False, steps=steps, error="Signature verification failed. The file was modified and was not decrypted."), 200
    audit("SIGNATURE_VERIFIED", f"{r['name']} from {r['sender']}", involved=[r["sender"]])

    try:
        t0 = time.perf_counter()
        aes_key = cu.unwrap_key(r["wrapped"], UNLOCKED[session["sid"]]["key"])
        step("Unwrap the AES key with your RSA private key (OAEP)", f"recovered a {len(aes_key)}-byte key", t0,
                 vals=[kv("Wrapped AES key from the package", r["wrapped"]),
                       kv("Unwrapped AES-256 key (compare with the sender's)", aes_key)])
        t0 = time.perf_counter()
        plaintext = cu.aes_decrypt(aes_key, r["nonce"], r["tag"], ciphertext)
        step("Decrypt with AES-256-GCM", f"authentication tag verified · {len(plaintext):,} bytes recovered", t0,
                 vals=[kv("Nonce", r["nonce"]), kv("GCM tag that was checked", r["tag"])])
    except (ValueError, TypeError):
        step("AES-GCM authentication failed", "The data does not match its tag.", time.perf_counter(), False)
        db().execute("UPDATE files SET status='rejected' WHERE id=?", (fid,))
        db().commit()
        save_manifest(get_file(fid))
        audit("DECRYPTION_FAILED", f"{r['name']} from {r['sender']}", involved=[r["sender"]])
        push("file", {"kind": "rejected", "id": fid, "name": r["name"], "sender": r["sender"], "receiver": u},
             users=[r["sender"], u], roles=["admin"])
        return jsonify(ok=False, steps=steps, error="Decryption failed."), 200

    t0 = time.perf_counter()
    rec_hash = cu.sha256_hex(plaintext)
    out_name = f"{fid}_{secure_filename(r['name']) or 'file'}"
    safe_write(DIRS["decrypted"] / out_name, plaintext)
    match = rec_hash == r["plain_sha256"]
    step("Save decrypted copy and compare hashes",
         f"{DIRS['decrypted'] / out_name} · SHA-256 {rec_hash[:32]}… " + ("matches the sender's original" if match else "DOES NOT match"), t0, match,
         [kv("Sender's original SHA-256", r["plain_sha256"]), kv("Recovered file SHA-256", rec_hash)])
    db().execute("UPDATE files SET status='decrypted', decrypted_at=?, decrypted_name=?, recovered_sha256=? WHERE id=?",
                 (now(), out_name, rec_hash, fid))
    db().commit()
    save_manifest(get_file(fid))
    audit("FILE_DECRYPTED", f"{r['name']} opened by {u}", involved=[r["sender"]])
    push("file", {"kind": "decrypted", "id": fid, "name": r["name"], "sender": r["sender"], "receiver": u},
         users=[r["sender"], u], roles=["admin"])
    return jsonify(ok=True, steps=steps, file=view(get_file(fid), "receiver", u))


PREVIEW = {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"}


@app.get("/api/files/<int:fid>/decrypted")
@role_required("admin", "sender", "receiver")
def get_decrypted(fid):
    r = get_file(fid)
    role, u = session["role"], session["username"]
    # Only the receiver may ever read plaintext. Admin and sender are refused.
    if not r or role != "receiver" or r["receiver"] != u or not r["decrypted_name"]:
        audit("UNAUTHORIZED_ATTEMPT", f"({role}) tried to read the decrypted file #{fid}: DENIED")
        return jsonify(error="Only the receiver can read the decrypted file."), 403
    path = DIRS["decrypted"] / r["decrypted_name"]
    inline = request.args.get("inline") == "1"
    mime = r["mime"]
    if inline and mime in PREVIEW:
        resp = send_file(path, mimetype=mime)
    elif inline and mime.startswith("text/"):
        resp = send_file(path, mimetype="text/plain; charset=utf-8")
    else:
        return jsonify(error="Downloads are disabled. The file can only be viewed in the app."), 403
    if not (inline and mime == "application/pdf"):
        resp.headers["Content-Security-Policy"] = "sandbox"
    return resp


@app.post("/api/files/<int:fid>/tamper")
@role_required("admin")
def tamper(fid):
    """DEMO: the admin (or any intruder with disk access) flips one bit of the stored ciphertext."""
    r = get_file(fid)
    if not r:
        return jsonify(error="Not found."), 404
    p = DIRS["encrypted"] / r["stored_name"]
    data = bytearray(p.read_bytes())
    data[0] ^= 0x01
    safe_write(p, bytes(data))
    audit("DEMO_TAMPER", f"1 bit of {r['name']} flipped on disk", involved=[r["sender"], r["receiver"]])
    push("file", {"kind": "tampered", "id": fid, "name": r["name"], "sender": r["sender"], "receiver": r["receiver"]},
         users=[r["sender"], r["receiver"]], roles=["admin"])
    return jsonify(ok=True)


@app.get("/api/audit")
@role_required("admin", "sender", "receiver")
def get_audit():
    role, u = session["role"], session["username"]
    if role == "admin":
        rows = db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 80").fetchall()
    else:
        rows = db().execute("SELECT * FROM audit WHERE ',' || involved || ',' LIKE ? ORDER BY id DESC LIMIT 80",
                            (f"%,{u},%",)).fetchall()
    return jsonify([dict(ts=r["ts"], actor=r["actor"], event=r["event"], detail=r["detail"]) for r in rows])


def seed():
    """Create demo accounts on first run so the project is usable immediately."""
    c = sqlite3.connect(DB_PATH)
    have = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    c.close()
    if have:
        return
    print("First run: creating accounts and RSA keys (a few seconds)...")
    admin_pw = os.environ.get("ADMIN_PASSWORD")
    if SEED_DEMO:
        create_user("admin", admin_pw or "admin12345", "admin")
        create_user("sender1", "sender12345", "sender")
        create_user("receiver1", "receiver12345", "receiver")
    else:                                    # public mode: no accounts with known passwords
        if not admin_pw:
            admin_pw = secrets.token_urlsafe(12)
            print(f"  ADMIN_PASSWORD was not set. The admin password for this run is: {admin_pw}")
        create_user("admin", admin_pw, "admin")


if __name__ == "__main__":
    init_db()
    check_folders()
    seed()
    sync_manifests()
    start_background()
    port = int(os.environ.get("PORT", 5050))
    _probe = socket.socket()
    _probe.settimeout(1)
    if _probe.connect_ex(("127.0.0.1", port)) == 0:
        raise SystemExit(f"\n  ERROR: something is already running on port {port}. It is probably an OLD SecureShare\n"
                         f"  window (maybe from another folder), and the browser would talk to it instead of this one,\n"
                         f"  saving files in ITS folder. Close all old server windows and start again.\n")
    _probe.close()
    ip = lan_ip()
    print("\n  SecureShare is running")
    print(f"  This laptop:        http://127.0.0.1:{port}")
    print(f"  Other laptops (same Wi-Fi):  http://{ip}:{port}")
    print(f"  Files are saved in: {DATA}")
    print("  (open that folder: encrypted/, decrypted/, packages/, keys/, logs/)\n")
    if "temp" in str(DATA).lower() or ".zip" in str(DATA).lower():
        print("  WARNING: this looks like a temporary or zipped location. Extract the zip to a normal")
        print("  folder first (right-click the zip, Extract All), otherwise your files are saved in a")
        print("  temp folder that you will not find.\n")
    with app.app_context():
        audit("SERVER_STARTED", f"data folder: {DATA}", actor="system")
    print("  Demo logins:  admin / admin12345   sender1 / sender12345   receiver1 / receiver12345\n")
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=port, threaded=True, debug=False)
