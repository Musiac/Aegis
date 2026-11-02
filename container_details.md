# Aegis container details

The full, detailed description of every container in Aegis. The short version is in the [README](README.md#architecture).

**2 permanent containers + an ephemeral, on-demand sandbox trio** (refactored 2026-10-31 — previously
6 containers, all permanent):

- **aegis-code/** (renamed from `backend/`) — the thin chat loop. Built once, run two ways: `aegis-code`
  as a daemon (serves the web UI on `:8900`, started by `install.sh`) and the CLI as a separate,
  interactive `docker run -it --rm ...` (see Install) using the same image. Reaches `aegis-libraries`
  over `aegis-net` (a bridge network) by container name, and the sandbox trio over the `aegis-sock`
  named volume (AF_UNIX sockets can't bind inside a bind-mounted host dir on Docker Desktop/macOS,
  confirmed live, hence a named volume + a container that shares it, not a plain host process). Picks an
  LLM provider from `.env` (`AEGIS_PROVIDER`, or the first one with a key configured) — `muse` (Meta's
  Muse Spark) is the only provider in the dropdown, auto-selecting the cheaper contributor tier for
  confirmed-public repos and the regular tier for everything else (private repos, self-scans). Gemini and
  Claude remain usable via `AEGIS_PROVIDER`/the auto-route env vars below even though the web UI's
  dropdown doesn't list them. No MCP server layer, no voice/audio, no multi-account login — single
  operator, bring your own Muse Spark key.

  **Optional per-skill routing (based on `.env` setting):** set both
  `AEGIS_SCAN_PROVIDER` and `AEGIS_FIX_PROVIDER` to route a plain scan/pentest request to one
  provider and a fix/remediate request to another, automatically, by each message's own wording —
  nothing is sent anywhere until the operator opts in by setting both.

  `check_scanner_versions` runs automatically at every connect and, as of 2026-10-31, **auto-updates any
  outdated scanner tool itself** — no operator confirmation asked or needed (there is no real scenario
  where the answer would ever be no); it just reports what it found and updated.

- **aegis-libraries/** (merged from `redteam/` + `pentestlive/`) — one container, two processes: static
  scanners (gitleaks, Bandit, Semgrep, pip-audit, npm audit, Trivy, OWASP ZAP) on `:7906`, and the one
  active, consent-gated probe (liveness + technology detection) against a URL you name, via
  [ProjectDiscovery's httpx](https://github.com/projectdiscovery/httpx) (`pd-httpx`), on `:7907`. Reads a
  read-only mounted copy of the target; runs on `aegis-net` (a bridge network), not `--network host`
  (Docker Desktop doesn't route `--network host` to localhost reliably). Trivy scans a local image
  tarball mounted read-only at `/images/<name>.tar` — `install.sh` `docker save`s each of Aegis's own
  images into `images/` for exactly this, so Trivy has something real to scan out of the box.

- **The sandbox trio — `aegis-sandbox` / `aegis-sandbox-proxy` / `aegis-sandbox-web` — is EPHEMERAL, not a
  permanent daemon.** At idle, none of these 3 containers exist; only `aegis-code` + `aegis-libraries` run.
  The moment a real task touches the sandbox (the first `bash_run`, clone, or similar), a small host-side
  process — `trio_control/server.py`, never itself containerized, since `aegis-code` deliberately has no
  `docker.sock` and shouldn't get one — creates all 3 containers, runs a hard safety-gate check against the
  freshly-created sandbox (3 real isolation checks: can't write outside it, can't reach the internet, real
  resource caps enforced), and only on success does the triggering call proceed; a failed gate tears the
  trio back down immediately. `trio_control` exposes exactly `start`/`stop`/`status`/`touch` over
  `127.0.0.1`, bearer-token gated — never a generic Docker API, so even full compromise of `aegis-code`
  can't pivot into controlling any other container on the host. After 5 minutes of no sandbox activity, a
  background reaper inside `trio_control` tears the trio back down on its own. During an active task you'll
  see 5 containers; at every other time, 2.

  `aegis-sandbox` — the isolated code sandbox `fixredteam`/`fixpentest` write real fixes in.
  `--network none`, read-only root, non-root, capped CPU/memory/processes. Each target has a read-only
  pristine copy and a working copy it edits (`/self_target/self` for "self", `/dynamic_target/<name>` for
  a cloned repo), the same directory `aegis-libraries` re-scans. Exports finished work to `/aegis_out` on
  the host — the only way anything leaves it. `.env` is never copied in. `aegis-sandbox-proxy` is the only
  container with real network access (a CONNECT-only proxy allowing exactly `pypi.org`,
  `files.pythonhosted.org`, `registry.npmjs.org`), reached by `aegis-sandbox` over a Unix socket since it
  has no network device at all. `aegis-sandbox-web` hosts a cloned project's own server (after fixes are
  applied) so an active ZAP pentest has something genuinely running to attack.
