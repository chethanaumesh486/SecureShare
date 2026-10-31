# Deploying SecureShare publicly (free, on Render)

Free hosts change their terms often. Check Render's current free-plan limits when you sign up.

## Settings

| Setting | Value |
|---|---|
| Runtime | Python 3 |
| Build command | `pip install -r requirements.txt` |
| Start command | `gunicorn -w 1 -k gthread --threads 64 --timeout 120 -b 0.0.0.0:$PORT wsgi:app` |
| Instance type | Free |

Always use **one** worker (`-w 1`): logins and live updates are kept in that process's memory.

## Environment variables

| Name | Example | What it does |
|---|---|---|
| `PUBLIC_MODE` | `1` | Turns on public mode: no demo accounts, Secure cookies, HTTPS headers, per-IP limits, hides the server path, shows the demo notice |
| `ADMIN_PASSWORD` | a long random password | Password of the `admin` account. If missing, a random one is printed in the server log |
| `SECRET_KEY` | a long random string | Signs login cookies. Generate: `python -c "import secrets;print(secrets.token_hex(32))"` |
| `MAX_UPLOAD_MB` | `5` | Largest file allowed (default 50) |
| `MAX_USERS` | `100` | Most accounts that can exist (default: no limit) |
| `RETAIN_HOURS` | `3` | Files older than this are deleted automatically (default: never) |
| `PUBLIC_BANNER` | any text | Replaces the default demo notice |
| `SEED_DEMO` | `0` or `1` | `1` creates sender1/receiver1 with known passwords. Default is `0` in public mode |
| `COOKIE_SECURE` | `0` | Only for testing public mode over plain http |

## Free-tier limits to remember

- The free service sleeps after about 15 minutes without traffic. The first visit afterwards takes about a minute.
- The disk is temporary. When the service restarts, sleeps or is redeployed, **all accounts and files are lost** (only the admin account is recreated). Create the sender and receiver accounts shortly before you present.
