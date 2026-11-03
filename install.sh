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
[ -f "$ENV_FILE" ] || { echo "Copy .env.example to .env and fill it in first:  cp .env.example .env"; exit 1; }

# --- friendly checks, so a first-time user gets a plain sentence instead of a stack of errors ---
for cmd in docker python3 rsync curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Aegis needs '$cmd' but it was not found. Please install it, then run this again."; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Please start Docker Desktop (or the Docker service), wait until it says it is running, then run this again."; exit 1; }
grep -Eq '^MUSE_API_KEY=.+' "$ENV_FILE" || { echo "Your Meta API key is missing. Open the file .env in this folder, find the line MUSE_API_KEY= , type your own Meta API key right after the = sign, save the file, then run this again."; exit 1; }

# --- is there room? Warnings only: the install carries on, but a slow or failing run is easier to understand if you were told first (2026-11-03). ---
MIN_DISK_GB="${AEGIS_MIN_DISK_GB:-25}"; MIN_RAM_GB="${AEGIS_MIN_DOCKER_RAM_GB:-4}"; MIN_CPUS="${AEGIS_MIN_CPUS:-4}"
FREE_DISK_GB=$(df -Pk . 2>/dev/null | awk 'NR==2 {printf "%d", $4 / 1048576}')
DOCKER_CPUS=$(docker info --format '{{.NCPU}}' 2>/dev/null)
DOCKER_RAM_GB=$(docker info --format '{{.MemTotal}}' 2>/dev/null | awk '{printf "%d", $1 / 1073741824}')
[ -n "$FREE_DISK_GB" ] && [ "$FREE_DISK_GB" -lt "$MIN_DISK_GB" ] && echo "WARNING: only ${FREE_DISK_GB} GB of disk is free here. Aegis needs about ${MIN_DISK_GB} GB free (about 12 GB once installed, about 17 GB during the first install)."
[ -n "$DOCKER_RAM_GB" ] && [ "$DOCKER_RAM_GB" -lt "$MIN_RAM_GB" ] && echo "WARNING: Docker can use only ${DOCKER_RAM_GB} GB of memory. Aegis works best with at least ${MIN_RAM_GB} GB free for Docker (it peaked at about 2 GB in our tests). In Docker Desktop: Settings, Resources."
[ -n "$DOCKER_CPUS" ] && [ "$DOCKER_CPUS" -lt "$MIN_CPUS" ] && echo "WARNING: Docker can use only ${DOCKER_CPUS} processor cores. Aegis works best with at least ${MIN_CPUS}; scans will just take longer."

echo "Aegis install: this builds 3 images and starts the containers. It can take 5 to 10 minutes the first time."
echo "If a pop-up asks to allow network access, click Allow. The progress line below keeps moving, so you can tell it is not stuck."
echo

# --- progress: a spinner, a step counter, a progress bar and a running clock for every long step ---
TOTAL_STEPS=10
STEP=0
SPIN_SOFT=0     # 1 = a failing step prints a warning and the install carries on
LAST_LOG=""
_elapsed() { printf '%d:%02d' $(($1 / 60)) $(($1 % 60)); }
_bar() { # _bar <done> <total>  ->  ####----------------
  local n=$1 total=$2 w=20 i=0 f s=""
  f=$(( n * w / total ))
  while [ $i -lt $w ]; do if [ $i -lt $f ]; then s="${s}#"; else s="${s}-"; fi; i=$((i + 1)); done
  printf '%s' "$s"
}
spin_run() { # spin_run "what is happening" command [args...]
  local label="$1"; shift
  STEP=$((STEP + 1))
  local log start pid rc frame=0 frames='|/-\'
  log=$(mktemp -t aegis_install.XXXXXX); LAST_LOG="$log"; start=$SECONDS
  "$@" >"$log" 2>&1 &
  pid=$!
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r\033[K[%d/%d] [%s] %s %s  %s' "$STEP" "$TOTAL_STEPS" "$(_bar $((STEP - 1)) $TOTAL_STEPS)" "${frames:$((frame % 4)):1}" "$label" "$(_elapsed $((SECONDS - start)))"
      frame=$((frame + 1)); sleep 0.2
    done
  else
    echo "[$STEP/$TOTAL_STEPS] $label ..."
    local beat=$SECONDS
    while kill -0 "$pid" 2>/dev/null; do
      sleep 1
      if [ $((SECONDS - beat)) -ge 20 ]; then beat=$SECONDS; echo "    still working, $(_elapsed $((SECONDS - start))) so far -- this is normal, it is not stuck"; fi
    done
  fi
  if wait "$pid"; then rc=0; else rc=$?; fi
  [ -t 1 ] && printf '\r\033[K'
  if [ $rc -eq 0 ]; then
    printf '[%d/%d] [%s] done: %s (%s)\n' "$STEP" "$TOTAL_STEPS" "$(_bar $STEP $TOTAL_STEPS)" "$label" "$(_elapsed $((SECONDS - start)))"
  else
    printf '[%d/%d] FAILED: %s\n' "$STEP" "$TOTAL_STEPS" "$label"
    echo "---- last lines of its output ----"; tail -n 40 "$log"; echo "----------------------------------"
    if [ "$SPIN_SOFT" = "1" ]; then return 0; fi
    echo "The install stopped. Fix the problem above and run: bash install.sh   (it is safe to run again)"
    exit $rc
  fi
}

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
# images/ and redteam_tool_updates/ excluded (2026-10-31, real finding): docker save tarballs (1.8GB+) and live scanner-tool
# binaries (285MB), both regenerated/updated independently of source and neither ever excluded before -- with no exclude, both
# got copied into src/self/ then self_target/self/ on every run, alone enough to blow past the sandbox's /REPL quota before any
# real work started. logs/ excluded too -- trio_control.log and friends are runtime output, not source.
rsync -a --delete --exclude ".git" --exclude ".env" --exclude "__pycache__" --exclude "src" --exclude "self_target" --exclude "aegis_out" --exclude "dynamic_pristine" --exclude "dynamic_target" --exclude "images" --exclude "redteam_tool_updates" --exclude "logs" ./ src/self/

# The containers run as fixed, non-root uids -- the sandbox as 1001 (sandbox/Dockerfile), redteam as 1000
# (redteam/Dockerfile) -- but the host dirs they write to were just created by whoever ran this script, usually a
# different uid, so every fix, export and clone would fail with "Permission denied". A throwaway root container
# from the sandbox image (no sudo needed) seeds the self working copy from the pristine copy and hands each dir to
# the one container that writes it: self_target/, dynamic_target/ and aegis_out/ to the sandbox (1001),
# dynamic_pristine/ and redteam_tool_updates/ to redteam (1000 -- it writes fresh clones AND live scanner-tool
# updates there, see aegis-libraries/redteam_server.py's own "Live, same-session tool update" section). Every other mount of
# these dirs is read-only. It runs BEFORE redteam starts: aegis-libraries/redteam_server.py only registers "self" if
# /src_self/self already exists then.
spin_run "Building the sandbox image" docker build -q -t aegis-sandbox:latest ./sandbox
seed_self_copy() {
  docker run --rm --user 0 --network none --entrypoint sh \
    -v "$(pwd)/src/self:/self_pristine:ro" -v "$(pwd)/self_target:/self_target" -v "$(pwd)/aegis_out:/aegis_out" \
    -v "$(pwd)/dynamic_pristine:/dynamic_pristine" -v "$(pwd)/dynamic_target:/dynamic_target" \
    -v "$(pwd)/redteam_tool_updates:/redteam_tool_updates" \
    aegis-sandbox:latest -c 'rm -rf /self_target/self && cp -a /self_pristine /self_target/self &&
      chown -R 1001:1001 /self_target /dynamic_target /aegis_out && chown -R 1000:1000 /dynamic_pristine /redteam_tool_updates'
}
spin_run "Preparing the folders Aegis works in" seed_self_copy

# --- aegis-libraries: static scanners + ZAP + pentestlive, folded into one image/container (2026-10-31).
# On Linux this ran as --network host; Docker Desktop (Mac/Windows) does not route --network host to
# localhost reliably (confirmed live), so this uses a dedicated bridge network (aegis-net) instead, with
# the other containers reached by container name, not 127.0.0.1 -- see AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL
# below (both now point at the SAME container, aegis-libraries, on its 2 ports).
docker network inspect aegis-net >/dev/null 2>&1 || docker network create aegis-net >/dev/null
spin_run "Building the scanner image (the slowest step)" docker build -q -t aegis-libraries:latest ./aegis-libraries

# Build the other image now (normally built further below, sandbox is already built above) so
# redteam_trivy has something real to scan -- a plain `docker save` tarball of each of Aegis's own
# images, mounted read-only at /images/<name>.tar. This never touches the Docker socket or a registry:
# a deploy-time snapshot, same as the full-featured version's Trivy design.
spin_run "Building the Aegis app image" docker build -q -t aegis-code:latest ./aegis-code
mkdir -p images
save_images() {
  docker save aegis-libraries:latest -o images/libraries.tar
  docker save aegis-sandbox:latest -o images/sandbox.tar
  docker save aegis-code:latest -o images/code.tar
}
spin_run "Saving image copies for the container scan" save_images

grep -q '^REDTEAM_TOKEN=' "$ENV_FILE" || echo "REDTEAM_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
REDTEAM_TOKEN=$(grep '^REDTEAM_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
GITHUB_CLONE_TOKEN=$(grep '^GITHUB_CLONE_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
grep -q '^PENTESTLIVE_TOKEN=' "$ENV_FILE" || echo "PENTESTLIVE_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
PENTESTLIVE_TOKEN=$(grep '^PENTESTLIVE_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
start_libraries() {
  docker rm -f aegis-libraries >/dev/null 2>&1 || true
  docker volume create aegis-libraries-trivy-cache >/dev/null
  docker run -d --name aegis-libraries --network aegis-net --read-only --tmpfs /tmp:size=2g,exec --restart unless-stopped \
    -v "$(pwd)/self_target:/src_self:ro" -v "$(pwd)/dynamic_pristine:/dynamic_pristine_rw" -v "$(pwd)/dynamic_target:/src_dynamic:ro" \
    -v "$(pwd)/images:/images:ro" -v aegis-libraries-trivy-cache:/trivy-cache \
    -v "$(pwd)/redteam_tool_updates:/tool_updates" \
    -e REDTEAM_TOKEN="$REDTEAM_TOKEN" -e GITHUB_CLONE_TOKEN="$GITHUB_CLONE_TOKEN" -e PENTESTLIVE_TOKEN="$PENTESTLIVE_TOKEN" \
    -p 127.0.0.1:7907:7907 aegis-libraries:latest >/dev/null
}
spin_run "Starting the scanner container (aegis-libraries)" start_libraries

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
TRIO_EXTRA="$(grep '^TRIO_CONTROL_EXTRA_ALLOWED=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)"
# Our own previous controller (recorded in logs/trio_control.pid) is restarted so a changed setting takes effect. It is found by its saved PID,
# never by name, so another program's controller on the same machine is never touched.
if [ -f logs/trio_control.pid ] && kill -0 "$(cat logs/trio_control.pid)" 2>/dev/null; then
  kill "$(cat logs/trio_control.pid)" 2>/dev/null || true; sleep 1
fi
if ! curl -s -o /dev/null "http://127.0.0.1:7929/status"; then
  TRIO_CONTROL_TOKEN="$TRIO_CONTROL_TOKEN" TRIO_CONTROL_EXTRA_ALLOWED="$TRIO_EXTRA" AEGIS_REPO_ROOT="$(pwd)" nohup python3 trio_control/server.py >> logs/trio_control.log 2>&1 &
  echo $! > logs/trio_control.pid
  disown
  for i in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:7929/status" && break; sleep 0.5; done
fi
spin_run "Starting the sandbox" bash trio_control/start_trio.sh

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
# --add-host=host.docker.internal:host-gateway (2026-10-31): Docker Desktop (Mac/Windows) already defines
# host.docker.internal on its own, so this flag is a harmless no-op there -- but on NATIVE Linux Docker (a
# DGX, EC2, any plain Linux host), host.docker.internal does not resolve at all without it. Docker's own
# documented way to make the SAME docker run command behave identically everywhere -- found live deploying
# this same trio_control design to a native Linux host, the DGX (gaierror from check_sandbox_capacity's lazy-start);
# applied here too even though Aegis itself has no DGX deployment today.
start_code() {
  docker rm -f aegis-code >/dev/null 2>&1 || true
  docker run -d --name aegis-code --network aegis-net -p 8900:8900 -v aegis-sock:/sock --env-file .env --restart unless-stopped \
    --add-host=host.docker.internal:host-gateway \
    -e AEGIS_REDTEAM_URL="http://aegis-libraries:7906" -e AEGIS_PENTESTLIVE_URL="http://aegis-libraries:7907" \
    -e AEGIS_OUT_HOST_DIR="$(pwd)/aegis_out" \
    -e TRIO_CONTROL_HOST="host.docker.internal" -e TRIO_CONTROL_PORT="7929" -e TRIO_CONTROL_TOKEN="$TRIO_CONTROL_TOKEN" \
    aegis-code:latest web >/dev/null
}
spin_run "Starting the Aegis web app (aegis-code)" start_code

# Can the Aegis container actually reach the sandbox controller that runs on this computer? (2026-11-03) It does on Mac and Linux. On Windows with
# WSL 2 the connection can arrive from a different address, and the first task that needs the sandbox would fail with no explanation, so check now.
check_sandbox_link() {
  docker exec aegis-code python3 -c "
import os, sys, urllib.request, urllib.error
url = 'http://%s:%s/status' % (os.environ['TRIO_CONTROL_HOST'], os.environ['TRIO_CONTROL_PORT'])
try:
    r = urllib.request.urlopen(url, timeout=8)
    print('Aegis can reach its sandbox controller.')
except urllib.error.HTTPError as e:
    print('The sandbox controller refused the connection (HTTP %s).' % e.code); sys.exit(1)
except Exception as e:
    print('Aegis cannot reach its sandbox controller (%s).' % type(e).__name__); sys.exit(1)
"
}
SPIN_SOFT=1
spin_run "Checking that Aegis can reach its sandbox" check_sandbox_link
SPIN_SOFT=0
if ! grep -q "can reach its sandbox" "$LAST_LOG"; then
  cat "$LAST_LOG"
  echo "Tasks that need the sandbox (fixing code, starting a server) will fail until this is fixed. What to try:"
  echo "  - If it says 'refused': open logs/trio_control.log, find the line 'refused a request from <address>', add the line"
  echo "    TRIO_CONTROL_EXTRA_ALLOWED=<address>/32 to your .env file, and run: bash install.sh"
  echo "  - If it says 'cannot reach': make sure Docker Desktop is running, and (on Windows) that you are running this inside Ubuntu, not PowerShell."
  echo
fi

# First-run setup (2026-11-03): the scanner tools load and bring themselves up to date the first time. Doing it here, with the progress line
# above still moving, means the page is ready the moment you open it. A failure here is only a warning: the page keeps trying by itself.
SPIN_SOFT=1
spin_run "Getting the scanner tools ready (first time only, can take several minutes)" docker exec aegis-code python3 -m backend.first_run
SPIN_SOFT=0
cat "$LAST_LOG"

echo
echo "--- checks ---"
echo "aegis-libraries (scanners): $(docker exec aegis-libraries curl -s http://127.0.0.1:7906/health)"
echo "aegis-libraries (live-site probe): $(curl -s http://127.0.0.1:7907/health)"
echo "aegis-code (web): $(curl -s http://127.0.0.1:8900/api/providers)"
echo
docker ps --format '{{.Names}}\t{{.Status}}' | grep aegis
echo
echo "In Docker you will now see two permanent containers, aegis-code and aegis-libraries."
echo "A short-lived sandbox (aegis-sandbox, aegis-sandbox-proxy, aegis-sandbox-web) starts when Aegis needs it and is removed after 5 idle minutes."
echo
echo "All set."
echo "Web UI:  http://127.0.0.1:8900   (open it in your browser)"
echo "CLI:     docker run -it --rm --network aegis-net -v aegis-sock:/sock --env-file .env aegis-code:latest"
