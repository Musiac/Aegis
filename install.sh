#!/bin/bash
# Aegis install: builds and starts the containers -- aegis-code (the dynamic chat/backend logic),
# aegis-libraries (the scanner/tool server -- redteam + pentestlive, folded into one image/container
# 2026-10-31), aegis-sandbox + aegis-sandbox-proxy + aegis-sandbox-web (the sandbox trio) -- same recipe as
# Strix's own "clone, install, run" shape -- review this script before running it, same as you would any
# install script, including this one.
#
#   git clone https://github.com/Musiac/Aegis && cd Aegis
#   cp .env.example .env   (fill in: an LLM key for whichever provider you pick in the model dropdown,
#                            and leave the two generated tokens below alone)
#   bash install.sh
#
# What "one docker" means here: one command (this script / docker compose), not one container -- aegis-sandbox
# genuinely needs --network none as a real security boundary and cannot share a network namespace with
# aegis-libraries, which needs real network access. See README.md's Architecture section.
set -e
cd "$(dirname "$0")"
ENV_FILE=".env"
[ -f "$ENV_FILE" ] || { echo "Copy .env.example to .env and fill it in first."; exit 1; }

mkdir -p src/self self_target aegis_out dynamic_pristine dynamic_target redteam_tool_updates
# Self-scan target: Aegis scanning its OWN source, the same way. It moves through the same
# pristine -> working-copy split a cloned repo does: src/self/ is the pristine copy (read-only to the sandbox at
# /self_pristine), self_target/self/ is the working copy the sandbox fixes (at /self_target/self) and redteam
# scans read-only (at /src_self/self) -- so a fix written in the sandbox is exactly what the next re-scan sees.
# dynamic_pristine/ and dynamic_target/ are the same two dirs for a cloned repo (redteam_clone_repo): redteam
# writes a fresh clone into dynamic_pristine/<name>, the sandbox copies it from there into dynamic_target/<name>,
# and redteam then scans that SAME dir read-only at /src_dynamic/<name> -- see aegis-libraries/redteam_server.py's own docstring.
# .env is excluded: it holds the LLM keys and tool tokens, and the sandbox (which can read and export this copy)
# must never see a secret.
rsync -a --delete --exclude ".git" --exclude ".env" --exclude "__pycache__" --exclude "src" --exclude "self_target" --exclude "aegis_out" --exclude "dynamic_pristine" --exclude "dynamic_target" ./ src/self/

# The containers run as fixed, non-root uids -- the sandbox as 1001 (sandbox/Dockerfile), redteam as 1000
# (redteam/Dockerfile) -- but the host dirs they write to were just created by whoever ran this script, usually a
# different uid, so every fix, export and clone would fail with "Permission denied". A throwaway root container
# from the sandbox image (no sudo needed) seeds the self working copy from the pristine copy and hands each dir to
# the one container that writes it: self_target/, dynamic_target/ and aegis_out/ to the sandbox (1001),
# dynamic_pristine/ and redteam_tool_updates/ to redteam (1000 -- it writes fresh clones AND live scanner-tool
# updates there, see aegis-libraries/redteam_server.py's own "Live, same-session tool update" section). Every other mount of
# these dirs is read-only. It runs BEFORE redteam starts: aegis-libraries/redteam_server.py only registers "self" if
# /src_self/self already exists then.
docker build -q -t aegis-sandbox:latest ./sandbox | tail -1
docker run --rm --user 0 --network none --entrypoint sh \
  -v "$(pwd)/src/self:/self_pristine:ro" -v "$(pwd)/self_target:/self_target" -v "$(pwd)/aegis_out:/aegis_out" \
  -v "$(pwd)/dynamic_pristine:/dynamic_pristine" -v "$(pwd)/dynamic_target:/dynamic_target" \
  -v "$(pwd)/redteam_tool_updates:/redteam_tool_updates" \
  aegis-sandbox:latest -c 'rm -rf /self_target/self && cp -a /self_pristine /self_target/self &&
    chown -R 1001:1001 /self_target /dynamic_target /aegis_out && chown -R 1000:1000 /dynamic_pristine /redteam_tool_updates'

# --- aegis-libraries: static scanners + ZAP + pentestlive, folded into one image/container (2026-10-31).
# On Linux this ran as --network host; Docker Desktop (Mac/Windows) does not route --network host to
# localhost reliably (confirmed live), so this uses a dedicated bridge network (aegis-net) instead, with
# the other containers reached by container name, not 127.0.0.1 -- see AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL
# below (both now point at the SAME container, aegis-libraries, on its 2 ports).
docker network inspect aegis-net >/dev/null 2>&1 || docker network create aegis-net >/dev/null
docker build -q -t aegis-libraries:latest ./aegis-libraries | tail -1

# Build the other image now (normally built further below, sandbox is already built above) so
# redteam_trivy has something real to scan -- a plain `docker save` tarball of each of Aegis's own
# images, mounted read-only at /images/<name>.tar. This never touches the Docker socket or a registry:
# a deploy-time snapshot, same as the full-featured version's Trivy design.
docker build -q -t aegis-code:latest ./aegis-code | tail -1
mkdir -p images
docker save aegis-libraries:latest -o images/libraries.tar
docker save aegis-sandbox:latest -o images/sandbox.tar
docker save aegis-code:latest -o images/code.tar

grep -q '^REDTEAM_TOKEN=' "$ENV_FILE" || echo "REDTEAM_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
REDTEAM_TOKEN=$(grep '^REDTEAM_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
GITHUB_CLONE_TOKEN=$(grep '^GITHUB_CLONE_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
grep -q '^PENTESTLIVE_TOKEN=' "$ENV_FILE" || echo "PENTESTLIVE_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
PENTESTLIVE_TOKEN=$(grep '^PENTESTLIVE_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
docker rm -f aegis-libraries >/dev/null 2>&1 || true
docker volume create aegis-libraries-trivy-cache >/dev/null
docker run -d --name aegis-libraries --network aegis-net --read-only --tmpfs /tmp:size=2g,exec --restart unless-stopped \
  -v "$(pwd)/self_target:/src_self:ro" -v "$(pwd)/dynamic_pristine:/dynamic_pristine_rw" -v "$(pwd)/dynamic_target:/src_dynamic:ro" \
  -v "$(pwd)/images:/images:ro" -v aegis-libraries-trivy-cache:/trivy-cache \
  -v "$(pwd)/redteam_tool_updates:/tool_updates" \
  -e REDTEAM_TOKEN="$REDTEAM_TOKEN" -e GITHUB_CLONE_TOKEN="$GITHUB_CLONE_TOKEN" -e PENTESTLIVE_TOKEN="$PENTESTLIVE_TOKEN" \
  -p 127.0.0.1:7907:7907 aegis-libraries:latest >/dev/null

# --- sandbox trio: ephemeral (2026-10-31). aegis-sandbox + aegis-sandbox-proxy + aegis-sandbox-web are no
# longer created here directly -- trio_control/start_trio.sh is the one real place those `docker run` commands
# live now, called both by this install script (so a fresh install still ends with a running trio, same as
# before) and by trio_control/server.py's lazy-start/idle-reaper (so there's never two copies of these
# commands to keep in sync). aegis-sock is a Docker-managed NAMED VOLUME, not a host bind mount -- AF_UNIX
# sockets cannot be bound inside a bind-mounted host directory on Docker Desktop (macOS: osxfs/virtiofs
# returns ENOTSUP, confirmed live).
docker volume create aegis-sock >/dev/null; docker volume create aegis-work >/dev/null

# --- trio_control: the host-side (never containerized) process that creates/destroys the trio on demand.
# aegis-code has no docker.sock -- this is deliberately the ONLY thing on this machine with real `docker`
# access for the trio, and it exposes exactly start/stop/status/touch, never a generic Docker API. Binds
# 127.0.0.1 only; aegis-code reaches it over host.docker.internal (Docker Desktop's bridge-to-host DNS name).
grep -q '^TRIO_CONTROL_TOKEN=' "$ENV_FILE" || echo "TRIO_CONTROL_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
TRIO_CONTROL_TOKEN=$(grep '^TRIO_CONTROL_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
mkdir -p logs
if ! curl -s -o /dev/null "http://127.0.0.1:7909/status"; then
  TRIO_CONTROL_TOKEN="$TRIO_CONTROL_TOKEN" AEGIS_REPO_ROOT="$(pwd)" nohup python3 trio_control/server.py >> logs/trio_control.log 2>&1 &
  disown
  for i in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:7909/status" && break; sleep 0.5; done
fi
bash trio_control/start_trio.sh

# NOTE on kokoro/: a local Kokoro-82M TTS container (kokoro/Dockerfile, backend's /api/tts_kokoro) was built
# 2026-10-29, then NOT wired in here the same day -- Meta's hackathon organizers ruled it out ("Every model
# your project calls at runtime must be a Meta model... a built-in system or browser voice that isn't an AI
# model call is fine"). The code stays in the repo for personal, non-submission use only; this script never
# builds or starts aegis-kokoro-tts, and the frontend never calls /api/tts_kokoro. See README's "Meta models
# vs. OS/browser features" section.

# --- aegis-code: image already built above, for Trivy. The web UI runs as a real daemon (:8900); the CLI stays interactive. ---
# AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL point at the SAME container (aegis-net's own DNS), not
# 127.0.0.1 -- each container has its own network namespace on a bridge network, unlike --network host.
# TRIO_CONTROL_* point aegis-code at the host-side control plane over host.docker.internal (Docker Desktop's
# bridge-to-host DNS name) -- see trio_control/server.py and aegis-code/tools/trio_client.py.
docker rm -f aegis-code >/dev/null 2>&1 || true
docker run -d --name aegis-code --network aegis-net -p 8900:8900 -v aegis-sock:/sock --env-file .env --restart unless-stopped \
  -e AEGIS_REDTEAM_URL="http://aegis-libraries:7906" -e AEGIS_PENTESTLIVE_URL="http://aegis-libraries:7907" \
  -e TRIO_CONTROL_HOST="host.docker.internal" -e TRIO_CONTROL_PORT="7909" -e TRIO_CONTROL_TOKEN="$TRIO_CONTROL_TOKEN" \
  aegis-code:latest web >/dev/null

sleep 3
echo "--- aegis-libraries (redteam) ---";   docker exec aegis-libraries curl -s http://127.0.0.1:7906/health; echo
echo "--- aegis-libraries (pentestlive) ---"; curl -s http://127.0.0.1:7907/health; echo
echo "--- aegis-code web ---";  curl -s http://127.0.0.1:8900/api/providers; echo
docker ps --format '{{.Names}}\t{{.Status}}' | grep aegis
echo
echo "All set."
echo "Web UI:  http://127.0.0.1:8900"
echo "CLI:     docker run -it --rm --network aegis-net -v aegis-sock:/sock --env-file .env aegis-code:latest"
