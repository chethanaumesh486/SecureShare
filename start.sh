#!/usr/bin/env bash
# Starts SecureShare. Keep this terminal open while it is in use.
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt || { echo "Could not install requirements."; exit 1; }
( sleep 10; (command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:5050; xdg-open data) || (command -v open >/dev/null && open http://127.0.0.1:5050) ) >/dev/null 2>&1 &
python3 server.py
