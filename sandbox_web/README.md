# aegis-sandbox-web

Added 2026-10-26. Gives Aegis a place to actually **run** a cloned (and possibly
fixed) project's own server, so an active ZAP pentest has something real to attack —
"start the cloned code's server ... and run a pentest on it" was not possible before
this; `pentest_zap` could only point at an address that was *already* running somewhere.

## What it is

A tiny container, reusing the `aegis-code:latest` image (so it already has
uvicorn/fastapi/python-docx/etc. — the same deps Aegis's own app needs) but running
only `sandbox_web/control.py` as its real process. That script is a small stdlib HTTP
control plane (no new dependencies) on port 7999 that starts/stops/restarts the project's
own `uvicorn backend.web:app --port 8900` as a tracked child process.

- **Network:** `aegis-net`, with `--network-alias www.sandbox.com` — so once an app
  is started, `pentest_zap`'s `target_url` should be exactly `http://www.sandbox.com:8900/`.
  `aegis-libraries` (where ZAP actually runs) is on the same network and already
  resolves that name via Docker's own embedded DNS; nothing was added to any `/etc/hosts`.
- **Source:** read-only mounts of the SAME host directories the code sandbox
  (`aegis-sandbox`) writes fixes into (`dynamic_target/`, `self_target/`) — a fix
  written via `edit_file` is already there the moment `sandbox_app_restart` runs; no copy
  step, no extra wiring.
- **One app at a time.** Starting a new one stops whatever was running first — this
  mirrors the real "restart the server, re-scan" cycle the owner asked for, not several
  apps side by side.
- **Isolation:** no host port is published. The only thing that can reach it is another
  container on `aegis-net` (today: the redteam container and Aegis's own
  backend, to call the control API). It has the SAME network exposure the redteam
  container has always had (outbound internet, for `pip install` etc. during the app's
  own startup) — not a new attack surface class.
- **Local OpenAI stub** (added 2026-10-30): a second stdlib HTTP server in the SAME
  process, on port 8901 (so also reachable at `http://www.sandbox.com:8901/v1`, no new
  container, no DNS/hosts change). Answers `POST /v1/chat/completions` and
  `/v1/completions` — plain or streaming — with a fixed, schema-valid canned reply, and
  `GET /v1/models`. `_start()` sets `OPENAI_API_KEY`/`OPENAI_BASE_URL` for the launched
  app via `env.setdefault(...)` — only when the real environment doesn't already define
  them, so a genuinely configured key is never overridden. This exists so a cloned app
  that needs the OpenAI API to do anything useful can still come up far enough for ZAP to
  attack its real routes, without needing real credentials or outbound internet. Redirects
  via `OPENAI_BASE_URL` rather than DNS-hijacking `api.openai.com` on purpose: the real
  hostname is HTTPS-only and a self-signed cert for it would fail verification in any SDK
  that checks it; a plain-HTTP custom base URL has no such problem and is the officially
  supported override in both the Python and Node `openai` SDKs.
- **Scope:** works for anything shaped like Aegis's own convention
  (`backend/web.py`, `uvicorn backend.web:app`) — which is exactly right for pentesting
  Aegis's own cloned code. A differently-shaped project needs an explicit `cmd`
  passed to `sandbox_app_start`/`sandbox_app_restart`, and may still fail to start if its
  own dependencies are not already in the `aegis-code` image — that failure is
  reported plainly by the control API, never swallowed.

## Start it (now ephemeral -- see trio_control/start_trio.sh, the one real place this container is created)

```bash
cd ~/GenAI/Aegis   # or wherever this repo is checked out
docker run -d --name aegis-sandbox-web \
  --network aegis-net --network-alias www.sandbox.com --network-alias aegis-sandbox-web \
  --restart unless-stopped \
  -v "$(pwd)/sandbox_web/control.py:/control/control.py:ro" \
  -v "$(pwd)/dynamic_target:/dynamic_target:ro" \
  -v "$(pwd)/self_target:/self_target:ro" \
  -v aegis-work:/REPL-shared \
  --entrypoint python3 \
  aegis-code:latest -u /control/control.py
```

`aegis-work` (unified onto the code sandbox's own cache volume 2026-10-31, replacing the
old separate `sandbox_web/pip_cache`/`npm_cache` host directories) is the SAME named volume
`aegis-sandbox` mounts at `/REPL` -- mounted here at `/REPL-shared` instead, since this
container only needs its 2 cache subdirectories (`.uvcache`, `.npm-cache`), not the rest of
the code sandbox's own working directory. `_install_deps` in `control.py` points
`UV_CACHE_DIR`/`NPM_CONFIG_CACHE` at them (Python installs go through `uv pip install
--system` now, not plain `pip` -- pip's own cache format isn't uv's, so pointing plain pip
at this directory would never have actually been a cache hit), so a package version either
container's installs already fetched (for ANY repo, not just the one that first pulled it)
is reused straight from disk on the other side too -- only a genuinely new package or
version actually hits PyPI/the npm registry again. Being a named volume (not a host bind
mount), deleting/recreating this container, `aegis-sandbox`, or any of the 3 images never
loses it either.

Rebuilding `aegis-code:latest` for an unrelated reason does not need this
container recreated — it only reuses that image for its installed dependencies and never
runs the image's own baked-in app code. **Exception (2026-10-30):** `docker restart` reuses
the layers already materialized at creation time, so if the rebuild adds/changes something
this container actually needs (e.g. nodejs/npm, added for `_install_deps`'s npm support),
a plain restart will NOT pick it up — stop+rm+re-run with this same command instead.

## Verify

```bash
docker logs aegis-sandbox-web                       # "listening on 0.0.0.0:7999, app port 8900"
docker exec aegis-code python3 -c "import urllib.request,json; print(json.load(urllib.request.urlopen('http://aegis-sandbox-web:7999/status')))"
docker exec aegis-libraries python3 -c "import urllib.request; print(urllib.request.urlopen('http://www.sandbox.com:8900/', timeout=5).status)"   # only meaningful once something is started
```

## The backend tools (`backend/tools/sandbox_web_tools.py`)

`sandbox_app_start` / `sandbox_app_restart` / `sandbox_app_stop` / `sandbox_app_status` —
registered in `tools_registry.py`, documented for the model in `system_prompt.py`'s
"ACTIVE PENTEST OF A CLONED PROJECT'S OWN SERVER" section.
