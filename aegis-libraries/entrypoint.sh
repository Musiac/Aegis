#!/bin/bash
# Runs both servers folded into this image: redteam (static scanners + ZAP, :7906) and
# pentestlive (the one active, consent-gated probe, :7907). `wait -n` + `exit 1` means if either
# uvicorn process dies, this script exits non-zero and Docker's --restart unless-stopped brings the
# whole container back -- a dead pentestlive (or redteam) does not go unnoticed as a half-alive container.
# Needs bash: dash's (/bin/sh) `wait` has no `-n` option.
set -e
uvicorn redteam_server:app --host 0.0.0.0 --port 7906 &
uvicorn pentestlive_server:app --host 0.0.0.0 --port 7907 &
wait -n
exit 1
