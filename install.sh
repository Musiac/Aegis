#!/bin/bash
# Aegis install: builds and starts the 3 containers (redteam, sandbox, pentestlive), same recipe as
# Strix's own "clone, install, run" shape -- review this script before running it, same as you would any
# install script, including this one.
#
#   git clone https://github.com/Musiac/Aegis && cd Aegis
#   cp .env.example .env   (fill in: an LLM key for whichever provider you pick in the model dropdown,
#                            and leave the two generated tokens below alone)
#   bash install.sh
#
# What "one docker" means here: one command (this script / docker compose), not one container -- sandbox/
# genuinely needs --network none as a real security boundary and cannot share a network namespace with
# redteam/ or pentestlive/, which need real network access. See README.md's Architecture section.
set -e
cd "$(dirname "$0")"
ENV_FILE=".env"
[ -f "$ENV_FILE" ] || { echo "Copy .env.example to .env and fill it in first."; exit 1; }

mkdir -p src/self self_target aegis_out dynamic_pristine dynamic_target
# Self-scan target: Aegis scanning its OWN source, the same way. It moves through the same
# pristine -> working-copy split a cloned repo does: src/self/ is the pristine copy (read-only to the sandbox at
# /self_pristine), self_target/self/ is the working copy the sandbox fixes (at /self_target/self) and redteam
# scans read-only (at /src_self/self) -- so a fix written in the sandbox is exactly what the next re-scan sees.
# dynamic_pristine/ and dynamic_target/ are the same two dirs for a cloned repo (redteam_clone_repo): redteam
# writes a fresh clone into dynamic_pristine/<name>, the sandbox copies it from there into dynamic_target/<name>,
# and redteam then scans that SAME dir read-only at /src_dynamic/<name> -- see redteam/server.py's own docstring.
# .env is excluded: it holds the LLM keys and tool tokens, and the sandbox (which can read and export this copy)
# must never see a secret.
rsync -a --delete --exclude ".git" --exclude ".env" --exclude "__pycache__" --exclude "src" --exclude "self_target" --exclude "aegis_out" --exclude "dynamic_pristine" --exclude "dynamic_target" ./ src/self/

# The containers run as fixed, non-root uids -- the sandbox as 1001 (sandbox/Dockerfile), redteam as 1000
# (redteam/Dockerfile) -- but the host dirs they write to were just created by whoever ran this script, usually a
# different uid, so every fix, export and clone would fail with "Permission denied". A throwaway root container
# from the sandbox image (no sudo needed) seeds the self working copy from the pristine copy and hands each dir to
# the one container that writes it: self_target/, dynamic_target/ and aegis_out/ to the sandbox (1001),
# dynamic_pristine/ to redteam (1000, it writes fresh clones there). Every other mount of these dirs is read-only.
# It runs BEFORE redteam starts: redteam/server.py only registers "self" if /src_self/self already exists then.
docker build -q -t aegis-sandbox:latest ./sandbox | tail -1
docker run --rm --user 0 --network none --entrypoint sh \
  -v "$(pwd)/src/self:/self_pristine:ro" -v "$(pwd)/self_target:/self_target" -v "$(pwd)/aegis_out:/aegis_out" \
  -v "$(pwd)/dynamic_pristine:/dynamic_pristine" -v "$(pwd)/dynamic_target:/dynamic_target" \
  aegis-sandbox:latest -c 'rm -rf /self_target/self && cp -a /self_pristine /self_target/self &&
    chown -R 1001:1001 /self_target /dynamic_target /aegis_out && chown -R 1000:1000 /dynamic_pristine'

# --- redteam: static scanners + ZAP. On Linux this ran as --network host; Docker Desktop (Mac/Windows) does not
# route --network host to localhost reliably (confirmed live), so this uses a dedicated bridge network
# (aegis-net) instead, with the other containers reached by container name, not 127.0.0.1 -- see
# AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL below.
docker network inspect aegis-net >/dev/null 2>&1 || docker network create aegis-net >/dev/null
docker build -q -t aegis-redteam:latest ./redteam | tail -1

# Build the other 2 images now (normally built further below, sandbox is already built above) so
# redteam_trivy has something real to scan -- a plain `docker save` tarball of each of Aegis's own
# 4 images, mounted read-only at /images/<name>.tar. This never touches the Docker socket or a registry:
# a deploy-time snapshot, same as the full-featured version's Trivy design.
docker build -q -t aegis-pentestlive:latest ./pentestlive | tail -1
docker build -q -t aegis-backend:latest ./backend | tail -1
mkdir -p images
docker save aegis-redteam:latest -o images/redteam.tar
docker save aegis-sandbox:latest -o images/sandbox.tar
docker save aegis-pentestlive:latest -o images/pentestlive.tar
docker save aegis-backend:latest -o images/backend.tar

grep -q '^REDTEAM_TOKEN=' "$ENV_FILE" || echo "REDTEAM_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
REDTEAM_TOKEN=$(grep '^REDTEAM_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
GITHUB_CLONE_TOKEN=$(grep '^GITHUB_CLONE_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
docker rm -f aegis-redteam >/dev/null 2>&1 || true
docker volume create aegis-redteam-trivy-cache >/dev/null
docker run -d --name aegis-redteam --network aegis-net --read-only --tmpfs /tmp:size=2g,exec --restart unless-stopped \
  -v "$(pwd)/self_target:/src_self:ro" -v "$(pwd)/dynamic_pristine:/dynamic_pristine_rw" -v "$(pwd)/dynamic_target:/src_dynamic:ro" \
  -v "$(pwd)/images:/images:ro" -v aegis-redteam-trivy-cache:/trivy-cache \
  -e REDTEAM_TOKEN="$REDTEAM_TOKEN" -e GITHUB_CLONE_TOKEN="$GITHUB_CLONE_TOKEN" aegis-redteam:latest >/dev/null

# --- sandbox: the isolated code sandbox fixredteam/fixpentest write real fixes in (--network none) ---
# aegis-sock is a Docker-managed NAMED VOLUME, not a host bind mount -- AF_UNIX sockets cannot be
# bound inside a bind-mounted host directory on Docker Desktop (macOS: osxfs/virtiofs returns ENOTSUP,
# confirmed live). backend/'s own container (built below) mounts this same volume to reach it. The image itself
# was built above, before the self working copy was seeded.
docker rm -f aegis-sandbox aegis-sandbox-proxy >/dev/null 2>&1 || true
docker volume create aegis-sock >/dev/null; docker volume create aegis-work >/dev/null
docker run -d --name aegis-sandbox-proxy --restart unless-stopped --init --read-only --tmpfs /tmp:size=16m --cap-drop ALL \
  --security-opt no-new-privileges --memory 256m --pids-limit 64 --cpus 0.5 -v aegis-sock:/sock aegis-sandbox:latest proxy >/dev/null
# ,exec on /tmp: HOME=/tmp/home, and npx-style tools (npm-check-updates etc.) download then directly execve() a binary under
# $HOME/.npm/_npx/... -- Docker's --tmpfs default is noexec, which silently turned every such call into "Permission denied" the
# instant npm/Node were added to this image. Does not weaken the sandbox's real boundaries (--network none, cap-drop ALL, the
# resource caps below) -- a model that can already run arbitrary bash_run/repl_run code can trivially read-then-interpret a
# noexec file anyway, so noexec here was never a meaningful control, just an unexamined default.
docker run -d --name aegis-sandbox --restart unless-stopped --init --network none --read-only --tmpfs /tmp:size=1g,mode=1777,exec \
  --cap-drop ALL --security-opt no-new-privileges --memory 4g --oom-score-adj 1000 --pids-limit 256 --cpus 2 \
  -v aegis-sock:/sock -v aegis-work:/REPL -v "$(pwd)/aegis_out:/aegis_out" \
  -v "$(pwd)/src/self:/self_pristine:ro" -v "$(pwd)/self_target:/self_target" \
  -v "$(pwd)/dynamic_pristine:/dynamic_pristine:ro" -v "$(pwd)/dynamic_target:/dynamic_target" aegis-sandbox:latest sandbox >/dev/null

# --- pentestlive: the one active, consent-gated probe (pd-httpx) --- (image already built above, for Trivy)
grep -q '^PENTESTLIVE_TOKEN=' "$ENV_FILE" || echo "PENTESTLIVE_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
PENTESTLIVE_TOKEN=$(grep '^PENTESTLIVE_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
docker rm -f aegis-pentestlive >/dev/null 2>&1 || true
docker run -d --name aegis-pentestlive --network aegis-net -p 127.0.0.1:7907:7907 --read-only --tmpfs /tmp:size=256m --restart unless-stopped \
  -e PENTESTLIVE_TOKEN="$PENTESTLIVE_TOKEN" aegis-pentestlive:latest >/dev/null

# --- backend: image already built above, for Trivy. The web UI runs as a real daemon (:8900); the CLI stays interactive. ---
# AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL point at the other containers by NAME (aegis-net's own DNS), not
# 127.0.0.1 -- each container has its own network namespace on a bridge network, unlike --network host.
docker rm -f aegis-backend-web >/dev/null 2>&1 || true
docker run -d --name aegis-backend-web --network aegis-net -p 8900:8900 -v aegis-sock:/sock --env-file .env --restart unless-stopped \
  -e AEGIS_REDTEAM_URL="http://aegis-redteam:7906" -e AEGIS_PENTESTLIVE_URL="http://aegis-pentestlive:7907" \
  aegis-backend:latest web >/dev/null

sleep 3
echo "--- redteam ---";      docker exec aegis-redteam curl -s http://127.0.0.1:7906/health; echo
echo "--- pentestlive ---";  curl -s http://127.0.0.1:7907/health; echo
echo "--- backend web ---";  curl -s http://127.0.0.1:8900/api/providers; echo
docker ps --format '{{.Names}}\t{{.Status}}' | grep aegis
echo
echo "All set."
echo "Web UI:  http://127.0.0.1:8900"
echo "CLI:     docker run -it --rm --network aegis-net -v aegis-sock:/sock --env-file .env aegis-backend:latest"
