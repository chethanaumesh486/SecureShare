# SecureShare

Secure file sharing between three roles on different computers, with live updates.

| Role | What they see |
|---|---|
| **Sender** | Chooses a file or image and a receiver, then watches the encryption steps complete. Sees live status: encrypted, delivered, decrypted. |
| **Admin** | Sees each package as **encrypted bytes only**. Holds no key, so cannot decrypt. Sees the live audit trail. |
| **Receiver** | Gets the file the moment it is sent, verifies the signature, then the decrypted copy is saved on the server. |

## Start the server

**Windows:** double-click `start.bat`
**Mac / Linux:** run `./start.sh`
or manually: `pip install -r requirements.txt` then `python server.py`

Keep that window open. It prints two addresses:

- `http://127.0.0.1:5050` for this computer
- `http://192.168.x.x:5050` for other laptops on the **same Wi-Fi**

Always open the **address in a browser**. Do not double-click `static/index.html`: that has no server behind it and shows "Failed to fetch".

If another laptop cannot connect, allow Python through the firewall on the server laptop.

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Sender | `sender1` | `sender12345` |
| Receiver | `receiver1` | `receiver12345` |
| Admin | `admin` | `admin12345` |

More sender and receiver accounts can be created from the login page.

## Showing real-time communication

Each browser tab keeps its own login, so you can log in as sender in one tab and receiver in another of the same browser. (Incognito windows still work too.)

Use two laptops side by side (sender on one, receiver on the other) and the admin on a third laptop or in a second window. If you only have one laptop, use three browser windows, each in its own Incognito/Private window so the logins stay separate.

1. **Log in on every screen first.** Point out the green **Live** marker and the user chips at the top of each screen. Each person appears to the others instantly. Close one window and its chip disappears within a few seconds.
2. **Sender:** choose an image, pick `receiver1` (the dropdown shows online or offline), press **Encrypt and send**. The Encryption panel lists each step as it completes.
3. **Without touching the other screens**, show that:
   - the **receiver** screen pops up a message and the file appears, with no refresh
   - the **admin** screen shows the new package as grey noise, with the hex bytes, the same second
4. **Receiver:** press **Verify and decrypt**. The decrypted copy is saved to `data/decrypted/`. Switch to the sender screen: the status track updates by itself to `DELIVERED +25 MS`, `DECRYPTED +2.8 S`. Those numbers are the real time from send to delivery and to decryption.
5. **Admin:** press **Try to read plaintext**. It is refused and logged.
6. **Integrity:** on the admin screen press **Simulate tampering**. The receiver and sender are notified live. The receiver's **Verify** now fails and decryption is refused.

## Where are my files? (read this if the folders look empty)

Files are saved on the **computer that runs the server**, in the `data/` folder next to `server.py`. The exact path is printed when the server starts and shown at the bottom of every screen.

- **Extract the zip first** (right-click, Extract All). Do not run `start.bat` from inside the zip: Windows then uses a temporary folder and your files end up there, not in the folder you are looking at.
- Sender and receiver on different laptops: the files appear on the **server laptop**, not on the others.
- Files appear only after something happens: `keys/` and `logs/audit.log` on first start, `encrypted/` and `packages/` when a sender sends, `decrypted/` after the receiver decrypts.

## Showing the keys and hashes (for the demo)

Every step panel now lists its real values, with a **Copy** button on each (click a long value to expand it):

- **Sender, after Encrypt and send:** plaintext SHA-256, the one-time **AES-256 key** (shown only to the sender, never stored), nonce, GCM tag, the first bytes of the ciphertext, the receiver's public-key fingerprint, the **wrapped AES key**, the package SHA-256 and the RSA-PSS **signature**.
- **Receiver, after Verify and decrypt:** the recomputed package hash, the signature, the **unwrapped AES key** (it equals the sender's key), the GCM tag that was checked, and both file hashes side by side.
- **Everyone, "Show crypto details" under each transfer:** the public package values, with a live check that the stored hash still matches what is on disk. After "Simulate tampering" the admin sees the two hashes differ.

The admin is shown everything except the AES key. The AES key is only ever sent to the sender (when it is created) and the receiver (after unwrapping with their private key), so the admin can see the wrapped key but cannot open it.

## Saved on the server laptop in `data/`

| Folder | Contents |
|---|---|
| `encrypted/` | The encrypted files |
| `decrypted/` | The receiver's decrypted copies, written only after the signature verifies |
| `packages/` | One `.json` per file: nonce, GCM tag, wrapped AES key, signature, hashes, status, paths. Rewritten at every step (sent, delivered, decrypted, rejected) |
| `keys/` | Public keys and password-protected private keys |
| `logs/audit.log` | Every event, one JSON line each |
| `secureshare.db` | Users, file metadata, audit table |

## Front end

One page, `static/index.html`, plain JavaScript (no build step). Fonts (Poppins SemiBold for logo and headings, Inter for text and buttons, JetBrains Mono for hashes and logs; licences included) are bundled in `static/fonts/`, so it looks the same offline. The receiver sees the file's status, hashes and saved path (no inline preview). There are no download buttons anywhere (the server also refuses downloads), and the admin sees encrypted bytes only.

## How the cryptography is split

| Piece | Job |
|---|---|
| AES-256-GCM | Encrypts the file with a new random key per file; its tag detects changes |
| RSA-2048 OAEP | Wraps that AES key with the receiver's public key |
| SHA-256 | Hashes the whole package |
| RSA-PSS | The sender signs the hash; the receiver verifies it before decrypting |
| scrypt + AES-GCM | Protects each private key with its owner's password |

The sender has only a signing key pair, the receiver has only an encryption key pair, and the admin has no keys at all.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| "Failed to fetch" or "Cannot reach the SecureShare server" | The server is not running, or the page was opened as a file. Start the server and use the browser address it prints. |
| Server connected shows red on the login page | Same as above. |
| Other laptop cannot open the address | Different Wi-Fi, or the firewall is blocking Python on the server laptop. |
| "Too many attempts" | Five wrong passwords lock that username for one minute. |

## Tests

With the server running: `python test_multiuser.py http://127.0.0.1:5050`

It logs in as sender, receiver and admin at once, listens to the live streams, and runs 40 checks: live delivery, admin gets only ciphertext, plaintext requests are refused, wrong users are blocked, files land on disk, and tampered files are rejected.

## Putting it on the internet

See `DEPLOY.md` for the free-hosting steps, the start command and every environment variable (`PUBLIC_MODE`, `ADMIN_PASSWORD`, `SECRET_KEY`, `MAX_UPLOAD_MB`, `MAX_USERS`, `RETAIN_HOURS`). Without `PUBLIC_MODE=1` everything behaves exactly as before on your own laptop.

## Limits

- The server decrypts on the receiver's behalf using their key, which is unlocked in server memory while they are logged in. The admin screen cannot read plaintext, but whoever runs the server laptop can open `data/decrypted/`. A production design would decrypt in the receiver's browser.
- Plain HTTP, Flask's development server, 50 MB upload limit.
- "Simulate tampering" is a demo feature.
- Logins are lost if the server restarts. Saved files remain.
