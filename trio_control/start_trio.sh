#!/bin/bash
# Creates the ephemeral sandbox trio -- the exact same 3 `docker run` commands install.sh uses, extracted here
# so trio_control/server.py and install.sh both call this ONE script instead of two copies drifting apart.
# Run from the repo root (trio_control/server.py's _sh sets cwd=REPO_ROOT).
set -e
docker rm -f aegis-sandbox aegis-sandbox-proxy >/dev/null 2>&1 || true
docker volume create aegis-sock >/dev/null; docker volume create aegis-work >/dev/null
docker run -d --name aegis-sandbox-proxy --restart unless-stopped --init --read-only --tmpfs /tmp:size=16m --cap-drop ALL \
  --security-opt no-new-privileges --memory 256m --pids-limit 64 --cpus 0.5 -v aegis-sock:/sock aegis-sandbox:latest proxy >/dev/null
docker run -d --name aegis-sandbox --restart unless-stopped --init --network none --read-only --tmpfs /tmp:size=1g,mode=1777,exec \
  --cap-drop ALL --security-opt no-new-privileges --memory 4g --oom-score-adj 1000 --pids-limit 256 --cpus 2 \
  -v aegis-sock:/sock -v aegis-work:/REPL -v "$(pwd)/aegis_out:/aegis_out" \
  -v "$(pwd)/src/self:/self_pristine:ro" -v "$(pwd)/self_target:/self_target" \
  -v "$(pwd)/dynamic_pristine:/dynamic_pristine:ro" -v "$(pwd)/dynamic_target:/dynamic_target" aegis-sandbox:latest sandbox >/dev/null

mkdir -p sandbox_web/pip_cache sandbox_web/npm_cache
docker rm -f aegis-sandbox-web >/dev/null 2>&1 || true
docker run -d --name aegis-sandbox-web --network aegis-net --network-alias www.sandbox.com --restart unless-stopped \
  -v "$(pwd)/sandbox_web/control.py:/control/control.py:ro" \
  -v "$(pwd)/dynamic_target:/dynamic_target:ro" -v "$(pwd)/self_target:/self_target:ro" \
  -v "$(pwd)/sandbox_web/pip_cache:/pip_cache" -v "$(pwd)/sandbox_web/npm_cache:/npm_cache" \
  --entrypoint python3 aegis-code:latest -u /control/control.py >/dev/null

# Give the exec socket server a moment to bind before the first bash_run's socket connect. Checked via
# `docker exec` (not a host-side path check: Docker Desktop's volume Mountpoint lives inside its VM, not
# on the Mac filesystem, so a host `test -S` would never see it even once the socket is really there).
for i in $(seq 1 20); do
  docker exec aegis-sandbox test -S /sock/exec.sock 2>/dev/null && exit 0
  sleep 0.5
done
echo "sandbox exec socket did not appear within 10s" >&2
exit 1
