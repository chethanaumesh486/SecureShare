# SecureShare

A secure file-sharing system with three roles (sender, receiver, admin), built for an Information Security lab. Files are encrypted before they are stored, signed by the sender, verified by the receiver, and the admin can see that a file exists but can never read it. All screens update live.

**Live demo:** _add your Render link here_

> Demo system. Do not upload anything sensitive.

## Roles

| Role | What they can do |
|---|---|
| **Sender** | Picks a file and a receiver, then watches it being encrypted, wrapped and signed. Sees the live status: encrypted, delivered, decrypted. |
| **Receiver** | Gets the file instantly, verifies the signature, then decrypts and views it. |
| **Admin** | Sees only encrypted bytes and the audit log. Has no keys, so cannot decrypt. Can simulate tampering to show detection. |

## How the cryptography works

| Piece | Job |
|---|---|
| AES-256-GCM | Encrypts the file with a new random key per file. Its tag detects any change. |
| RSA-2048 OAEP | Wraps that AES key with the receiver's public key. |
| SHA-256 | Hashes the whole package (name, type, sender, receiver, nonce, tag, wrapped key, ciphertext). |
| RSA-PSS | The sender signs the hash. The receiver verifies it before decrypting. |
| scrypt + AES-GCM | Protects each user's private key with their password. |
| scrypt (Werkzeug) | Stores login passwords as salted hashes. |

The sender has only a signing key pair, the receiver only an encryption key pair, and the admin has no keys. Every step's real values (AES key, wrapped key, hashes, signature) are shown in the interface for demonstration.

## Run it locally

Requires Python 3.

- **Windows:** double-click `start.bat`
- **Mac / Linux:** run `./start.sh`
- **Manually:** `pip install -r requirements.txt`, then `python server.py`

Keep the window open and open **http://127.0.0.1:5050** in a browser. Do not open `static/index.html` as a file.

Local demo accounts (created only when running locally):

| Role | Username | Password |
|---|---|---|
| Sender | `sender1` | `sender12345` |
| Receiver | `receiver1` | `receiver12345` |
| Admin | `admin` | `admin12345` |

To demo on one laptop, open three separate browser windows (use Incognito or different browsers so the logins stay separate), one per role.

## Demo flow

1. Log in as sender, receiver and admin in three windows.
2. Sender: choose a file, pick the receiver, press **Encrypt and send**.
3. Receiver and admin update on their own. The admin sees only encrypted bytes.
4. Receiver: press **Verify and decrypt**.
5. Admin: press **Try to read plaintext** (refused and logged), then **Simulate tampering**.
6. The receiver's verification now fails and decryption is refused.

## Tests

With the server running: `python test_multiuser.py http://127.0.0.1:5050`

It acts as all three roles at once and runs 51 checks: live delivery, ciphertext-only admin view, access control, files on disk, key display, and tamper rejection.

## Deployment

See [DEPLOY.md](DEPLOY.md) for free hosting on Render, the start command and all environment variables.

## Project files

| File | Purpose |
|---|---|
| `server.py` | Flask web server: roles, database, live updates, upload, decrypt, audit log |
| `crypto_utils.py` | All cryptography in one place |
| `wsgi.py` | Entry point for production hosting (gunicorn) |
| `static/index.html` | The whole front end |
| `test_multiuser.py` | Automated tests |
| `start.bat`, `start.sh` | Local launchers |

## Limitations

- The server decrypts on the receiver's behalf while they are logged in, so whoever runs the server can read decrypted files. A production design would decrypt in the receiver's browser.
- File names, sizes, sender and receiver are visible to the admin. Only the content is hidden.
- Local use runs over plain HTTP with Flask's development server. The public version relies on the host's HTTPS.
- "Simulate tampering" is a demo feature.
- On free hosting the disk is temporary, so accounts and files are lost when the service restarts.
