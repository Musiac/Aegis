# Aegis

<p align="center"><img src="docs/assets/aegis-shield-arrow.png" alt="Aegis shield deflecting an incoming arrow" width="220"></p>
<p align="center"><img src="docs/assets/aegis-hackathon-badge.jpg" alt="Meta Global AI Developer Hackathon — 10 days on Meta's newest AI models, $1M in cash prizes" width="520"></p>

**Aegis** — **A**gentic **E**nterprise **G**uard for **I**nfo**S**ec, by **Musiac** — **Mus**e **I**ntelligence for **A**dvanced **C**yberSec.

*In Greek mythology, the aegis was no ordinary shield — the divine, impenetrable goatskin cloak and
shield carried by Zeus and Athena, bearing the severed Gorgon's head at its center, so that any enemy
who dared look upon it was turned instantly to stone before a single blow could land. To stand "under
someone's aegis" came to mean standing under protection so complete that the threat never reaches you at
all. This Aegis works the same way: it doesn't just block an attack after the fact, it finds the
vulnerability, turns it to stone — fixes it in place — and proves the fix holds, before anything hostile
ever gets through.*

An AI security agent, powered entirely by Meta's Muse Spark, that scans your own source code and
container images (static, read-only), actively pentests a target you point it at, and can write and
apply real fixes itself — then re-scans to prove the fix actually worked. Built for the Meta Global
Hackathon (dev.meta.ai/events/global-hackathon), it runs four cyber-security skills -- `redteam`,
`fixredteam`, `pentest`, `fixpentest` -- and whatever minimum code each one needs. Aegis automatically
calls Muse Spark's cheaper, contributor-tier model when working on public repos (where Meta may use the
content to train its models) and the regular, non-contributor tier for private repos or its own code
(never used for training) — disclosed to the operator at the start of every session.

We'll say it plainly: we're **Musiacs** — Muse maniacs — at IdeaNirvana. Building Aegis for this
hackathon hasn't felt like adapting to someone else's platform; it's felt like finally having the right
engine for a problem we've been working on for a while. We're genuinely excited to be building on Muse,
and we think it shows.

This isn't the first time Muse has touched our work, either. Before this hackathon existed, we asked
Muse — Meta's personal AI agent, the consumer product, not this API — to look at our own live AI product,
[Jiina](https://ideanirvana.com/solutions/jiina), the way an outside visitor would. On **12 October
2026**, Muse ran two passive checks (headers, certificates, redirects, sign-in behavior) against
`ideanirvana.com`, `ideanirvana.ai` and `solutions.ideanirvana.com` — no break-in attempt, not a
penetration test, and it found nothing critical. It still surfaced six real findings, and we fixed every
one the same day:

| Severity | Finding | Fixed |
|---|---|---|
| Medium | `ideanirvana.com` sent no security headers | ✅ same day |
| Medium | Jiina's event log showed the session key in plain text | ✅ same day |
| Low | The sign-in page could redirect to any web address after login | ✅ same day |
| Low | The content-security policy only reported, never blocked | ✅ same day (some pages still report-only) |
| Low | HSTS didn't cover subdomains | ✅ same day |
| Info | No `security.txt` contact file | ✅ published |

That's the honest reason we trust Muse enough to build Aegis on it for this hackathon: it already found
and helped us close real gaps in our own production product, before we ever had an API key in hand. Full
detail, scanner list and every other security result for Jiina is public at
[ideanirvana.com/solutions/jiina](https://ideanirvana.com/solutions/jiina).

## How Aegis relates to Jiina, and what was built this week

IdeaNirvana LLC (EIN-registered US company) is an existing startup; this hackathon submission is entered
in the Startup track by its sole founder/developer. IdeaNirvana's existing live product,
[Jiina](https://ideanirvana.com/solutions/jiina), is a multi-agentic AI assistant with a different set of
capabilities and skills (document editing, SAP/ServiceNow/Jira workflows, reporting, and more) — Jiina's
code and git history are **not** part of this repository and stay closed-source.

**Aegis is a new, separate, single-agent project**, in this new repository
([`Musiac/Aegis`](https://github.com/Musiac/Aegis), created **27 October 2026**), built specifically for
this hackathon. It shares no code history with Jiina in this public repo. What's new Aegis's capabiities: the whole security-agent persona and
skill set (`redteam`/`fixredteam`/`pentest`/`fixpentest`), the sandboxed clone/scan/fix/re-verify pipeline
described below, the live OWASP ZAP active-pentest integration, Meta Muse Spark as the driving model with
the public/private contributor-tier billing safety mechanism (see Benchmarks below), push-to-talk voice
(Meta's own ASR, `muse-voice-transcribe-1.0`) and the browser-based spoken replies, and the structural
fix-completion guard in `core.py` that stops the agent from ending a fix job half-done (see the Run log).
The one deliberate overlap with Jiina: the 12 October 2026 passive-security findings against Jiina's own
live site, described just below, predate this hackathon and are included here only as evidence of why we
trust Muse enough to build Aegis on it — not as part of the submission's own work.

## What it does

| Command | What happens |
|---|---|
| `redteam <target>` | Static scan only: gitleaks, Bandit, Semgrep, pip-audit, npm audit, Trivy. Reports every finding, asks before fixing anything. |
| `redteam <target> and fix it` | Scans, then writes and applies real fixes in an isolated sandbox copy, re-scans to confirm each one is actually gone, reports before/after. |
| `pentest <target>` | Active scan: OWASP ZAP (spider + active scanner) against a target you've stood up, or one real active probe against a live URL you explicitly consent to (typed `PENTESTLIVE`, never a plain "yes"). |
| `pentest <target> and fix it` | Attacks, writes a real fix, re-attacks to prove it's closed. |

`<target>` starts as "Aegis's own source" (self-scan) and a cloned copy of any public GitHub repo
you point it at (`run redteam on github repo: <url>`) — see "Status" below for what's live today.

## Benchmarks: why we chose Muse

Two real, timed runs, each a full clone → static scan (gitleaks/Bandit/Semgrep/pip-audit/npm-audit) →
live OWASP ZAP active pentest → fix → re-verify cycle, both scanners genuinely exercised end to end —
not a synthetic benchmark, the actual tool doing actual work.

| Target | Type | Model / tier | Wall time | Cost |
|---|---|---|---|---|
| [`flemuh/radar-public-sector`](https://github.com/flemuh/radar-public-sector) | Public repo | Muse Spark, **contributor** tier | **18m 38s** (1118.0s) | $0.189 |
| same repo, earlier run | Public repo | local qwen3.8-27b-sglang | 27m 19s (1639.1s) | $0.00 |
| This repo (private) | Private repo | Muse Spark, **Standard** (non-contributor) tier | 7m 23s (442.9s) | $2.39 |

**Muse Spark was ~32% faster than our own self-hosted qwen3.8-27b on an identical job** (same repo, same
task, same tool-calling loop) — 18m38s vs 27m19s wall-clock. We did not re-run this same job against
GPT in this test, so we're not claiming Muse beat GPT here — only that it meaningfully outran the local
model we'd otherwise default to. Meta's own inference infrastructure is the most credible explanation,
and the data backs it up plainly. (The private-repo run isn't a fair head-to-head against either of the
above — it's a different, smaller repo — so it's reported on its own, not as a third point in the same
comparison.)

**The public/private billing-tier safety mechanism was verified by reading the actual model string Muse
Spark's own API returned for every single round, not by trusting our own code.** Confirmed in the turn
log: **45 of 46 rounds** on `muse-spark-1.3-contributor` for the public repo (round 1, before the clone
tool had even run, correctly defaulted to the safe Standard tier — exactly the fail-closed behavior this
is designed to have), and **45 of 45 rounds** on `muse-spark-1.3` (Standard) for the private repo — zero
rounds on the training-eligible contributor tier, the whole way through.

**Why Aegis runs on Spark, not Wonder or Wonder Full.** `muse-wonder-1.0` is a real, callable model on
the Model API — pricier than Spark (confirmed live: $4.00/$20.00 per 1M input/output tokens, vs. Spark
Standard's $1.25/$4.25, and Wonder has no contributor tier at all) — but we picked Spark deliberately for
this build rather than defaulting to the most expensive option available. **Muse Wonder Full**, the
genuinely top-tier model, isn't a choice we could have made either way: it's restricted to subscribers of
Meta's terminal-based coding agent, Muse Code, on its Power ($50/month) or Maximum ($200/month) plans,
and is not exposed through the Model API at all, at any price. Worth knowing honestly going in, not
something we discovered as a limitation after the fact.

## Meta models vs. OS/browser features

Per guidance from Meta's hackathon organizers ("every model your project calls at runtime must be a
Meta model... a built-in system or browser voice that isn't an AI model call is fine"), here is exactly
which parts of Aegis are a Meta model call and which are a plain OS/browser feature:

**Meta model calls (the only AI models this project calls at runtime):**
- **`muse-spark-1.3` / `muse-spark-1.3-contributor`** (Model API) — every chat turn, tool-calling decision,
  and fix the agent writes. The contributor tier is used automatically for public repos, the Standard tier
  for private repos/self-scans; see the Benchmarks section above for how that's verified live, not just
  trusted from our own code.
- **`muse-voice-transcribe-1.0`** (`wss://api.meta.ai/v1/asr/realtime`) — push-to-talk's speech-to-text,
  when the mic button is used.

**OS/browser features (no model call, no third-party API, no network request to any AI provider):**
- **Spoken replies (Voice toggle's "TTS: browser")** — the browser's own built-in `window.speechSynthesis`
  (Web Speech API). This renders entirely on the operator's own machine, using whatever system voice is
  already installed (macOS/Chrome ship several) — it is not an AI model, local or remote, and nothing is
  sent anywhere for it. An earlier draft of this feature called a local, self-hosted Kokoro-82M model (open
  source, running on this machine's own CPU, no API key) — that was explicitly reverted after Meta's
  organizers confirmed a third-party model can't be used even if it's local and free; the backend code for
  it (`kokoro/`, `backend/api/tts_kokoro`) still exists in this repo for personal, non-submission use, but
  `install.sh` never starts it and the UI never calls it.
- A Gemini one-shot TTS path (`/api/tts`, `GEMINI_TTS_MODEL_NAME`) also still exists server-side from an
  earlier build, same reasoning as Kokoro (a competitor's model) — never called by the current UI either.

## Why this exists

Static pattern-matchers (Semgrep, Bandit) and semantic pentesters (like
[Strix](https://github.com/usestrix/strix)) catch different bug classes. This project's own source has
been the test subject: a 3rd-party pentest (Strix) found 4 real bugs our static scanners never would
have (cross-account sandbox access, a DNS-rebinding SSRF, a SQL validator bypass, stale WebSocket
sessions) — each one fixed, then verified closed by a fresh Strix run against the fixed code. The full
before/after writeups are not in this repo yet, but the reverse comparison is:
[Aegis scanning and fixing Strix's own source, 3 independent runs, each reaching 0 findings across
all 5 static scanners in one pass](docs/strix_full_fix_verification_2026-10-26.md).

## Install

Needs Docker and a bash shell (Linux, macOS, or WSL2 on Windows) with `rsync` and `python3`. The
containers use `--network host`, so on Docker Desktop host networking must be enabled.

```
git clone https://github.com/Musiac/Aegis
cd Aegis
cp .env.example .env            # fill in MUSE_API_KEY
bash install.sh                 # builds + starts all 4 containers, including the web UI daemon; generates REDTEAM_TOKEN/PENTESTLIVE_TOKEN into .env itself
```

That's the whole install — same shape as Strix's own `curl | bash`, minus the curl (review before you
run anything, including this). `install.sh` is a plain bash script, not a `docker compose` file — the
containers have deliberately different network modes, and the script is simpler to read end to end
before running it. It ends by printing the two ways in to the chat loop:

```
Web UI:  http://127.0.0.1:8900
CLI:     docker run -it --rm --network host -v aegis-sock:/sock --env-file .env aegis-backend:latest
```

The web UI (`aegis-backend-web`) runs as a daemon by default — open the URL and start typing. The
CLI is a separate, interactive container using the exact same backend image and the same running
redteam/sandbox/pentestlive containers; run it any time instead of (or alongside) the web UI.

**One honest caveat:** `sandbox/` runs with `--network none` as a real, load-bearing security boundary
(the isolated code sandbox fixredteam/fixpentest write real fixes in) — it genuinely cannot share a
network namespace with `redteam/` or `pentestlive/`, which need to reach the internet
(pip-audit/npm-audit's advisory databases) or a target host. "One docker" here means one command
(`bash install.sh`), not literally one container.

## Architecture

![Aegis architecture: browser → aegis-backend-web → aegis-redteam/pentestlive/sandbox-proxy, with the code-fix sandbox isolated behind --network none, Meta's Model API and GitHub as the only external services, and host-mounted volumes for scan targets and exported fixes](docs/assets/aegis_architecture.png)

Three small containers + a thin backend:

- **redteam/** — gitleaks, Bandit, Semgrep, pip-audit, npm audit, Trivy, OWASP ZAP. Reads a read-only
  mounted copy of the target; `--network host` for the tools that genuinely need it (pip-audit/npm-audit's
  advisory lookups, `git clone` of a target repo, ZAP's traffic to the target). Trivy scans a local image
  tarball mounted read-only at `/images/<name>.tar` — `install.sh` `docker save`s each of Aegis's own
  4 images into `images/` for exactly this, so Trivy has something real to scan out of the box.
- **sandbox/** — the isolated code sandbox `fixredteam`/`fixpentest` write real fixes in.
  `--network none`, read-only root, non-root, capped CPU/memory/processes. Each target has a read-only
  pristine copy and a working copy it edits (`/self_target/self` for "self", `/dynamic_target/<name>` for
  a cloned repo), the same directory redteam re-scans. Exports finished work to `/aegis_out` on the
  host — the only way anything leaves it. `.env` is never copied in.
- **pentestlive/** — one active, consent-gated probe (liveness + technology detection) against a URL
  you name, via [ProjectDiscovery's httpx](https://github.com/projectdiscovery/httpx) (`pd-httpx`).
- **backend/** — a thin chat loop that dispatches to the three containers above over a bearer-token HTTP
  API (redteam/pentestlive) or a Unix socket (sandbox). Its own 4th container, built once and run two
  ways: `aegis-backend-web` as a daemon (`--network host`, serves the web UI on `:8900`, started by
  `install.sh`) and the CLI as a separate, interactive `docker run -it --rm ...` (see Install) using the
  same image. Both need `--network host` plus the same `aegis-sock` named volume the sandbox uses
  (AF_UNIX sockets can't bind inside a bind-mounted host dir on Docker Desktop/macOS, confirmed live,
  hence a named volume + a container that shares it, not a plain host process). Picks an LLM provider from
  `.env` (`AEGIS_PROVIDER`, or the first one with a key configured) — `muse` (Meta's Muse Spark) is
  the only provider in the dropdown, auto-selecting the cheaper contributor tier for confirmed-public
  repos and the regular tier for everything else (private repos, self-scans). Gemini and Claude remain
  usable via `AEGIS_PROVIDER`/the auto-route env vars below even though the web UI's dropdown
  doesn't list them. No MCP server layer, no voice/audio, no multi-account login — single operator,
  bring your own Muse Spark key.

  **Optional per-skill routing (a personal `.env` choice, never a public default):** set both
  `AEGIS_SCAN_PROVIDER` and `AEGIS_FIX_PROVIDER` to route a plain scan/pentest request to one
  provider and a fix/remediate request to another, automatically, by each message's own wording —
  nothing is sent anywhere until the operator opts in by setting both.

## Sandbox security: live-tested, not theorized (2026-10-27)

Pointing an AI agent at an arbitrary, untrusted public repo and letting it clone, run, and actively
pentest that repo's own server is a real attack surface — the cloned code itself could be malicious.
Rather than just asserting the sandbox is safe, we ran six real attacks directly against the live
`aegis-sandbox` container (the exact container `fixredteam`/`fixpentest` use to apply fixes, same recipe
as cyberJiina's own `sandbox/`), invoked through the same `bash_run`/`export_project` code paths the
agent itself uses — not a simulation, not a code review, the actual payloads:

| # | Attack | Result |
|---|---|---|
| 1 | `rm -rf` outside the sandbox (e.g. the real Mac's `~/Downloads`) | **Blocked** — the real host filesystem is architecturally invisible; `ls /` inside the sandbox shows only its own mounted directories, nothing of the host. |
| 2 | Exfiltrate data to an external server (a real DGX address) | **Blocked** — `--network none` means no network device exists at all (`socket.gaierror: Temporary failure in name resolution`); even a "direct" attempt auto-routed through the install-only egress proxy, which returned `403 Forbidden` for a non-PyPI/npm destination. The legitimate path (PyPI, for installing dependencies) still returned `200 OK`. |
| 3 | Resource exhaustion (CPU spin, memory bomb, fork bomb) | **Contained** — memory bomb (tried ~20GB against a 4GB cap) was `SIGKILL`'d after 9.3s; fork bomb hit the 256-PID cap immediately; the sandbox answered the very next command in 0.01s in both cases — never crashed, never affected anything outside itself. |
| 4 | Read real credentials (`MUSE_API_KEY`, GitHub tokens) from inside the sandbox | **Blocked** — no real `.env` file is reachable anywhere in the sandbox's filesystem, only inert `.env.example` templates; `.env` is deliberately never copied in. |
| 5 | Container breakout (Docker socket, root, kernel writes) | **Blocked** — no Docker socket present; all Linux capabilities are zeroed at the kernel level (`CapEff: 0000000000000000`); running as non-root (`uid=1001`); root filesystem remount refused; `/proc/sys` writes refused (read-only). |
| 6 | Symlink/zip-slip attack on the exported fix zip | **Found, then fixed and re-verified live (2026-10-27)**: `export_project` originally dereferenced symlinks into the zip rather than storing the link — a planted `/etc/passwd` symlink was exported as 880 bytes of real content. Fixed by adding `-y` to the `zip` command (store symlinks as symlinks); re-ran the identical attack against the rebuilt sandbox and confirmed the exported zip now extracts `leaked_passwd.txt` as an actual 11-byte symlink pointing at `/etc/passwd`, not dereferenced content. |

Five of six held completely; the sixth is a real finding, disclosed here rather than left undiscovered,
with its actual exploitability honestly scoped rather than overstated. (Tested directly against
cyberJiina's identical sandbox image, which Aegis shares byte-for-byte via the same `sandbox/Dockerfile`.)

## UI

Two fixed-height panes side by side, each scrolling independently: the live terminal (scan/fix
progress) on the left, the chat conversation on the right. The header holds the model dropdown
(**Muse Spark** — your own key), a running "Total cost" readout (the real, metered LLM token cost for the session so far, updated after every
turn), and a connection status indicator. No audio controls — text in, text out.

Under both panes sits a strip of example questions (six at a time, shown shortened). Clicking one puts
the full question in the chat box, unsent, so you can edit it first; the small arrow at the bottom right
pages between examples 1–6 and 7–12. The list lives in `backend/static/app.js` (`EXAMPLES`).

## Run log

Every turn writes one-line events to the backend's stdout, so the efficiency of a run can be read without
the page: `docker logs aegis-backend-web | grep cj-turn`. Events: `session_open` / `session_close`,
`turn_start`, one `round` per model call (tokens, cost, seconds, which tools it asked for), one `tool` per
tool call (scrubbed arguments, seconds, whether it was a repeat or failed, and metadata about the result such
as `count`, `exit_code`, `active_scan_ran`), `count_check` for Word reports, and a `turn_end` summary (rounds,
tool calls by name, repeated and failed calls, model seconds vs tool seconds, tokens, turn and session cost).
Tool output itself is never logged, and credentials in commands, URLs and arguments are masked.

Scanner results carry exact tallies computed by code (`summary.total`, `by_severity`, `by_rule`), and a ZAP
Word report is checked against them before it is created, so a total or a rule count cannot drift from the scan.

## Example questions

These twelve are the questions shown in the UI. Edit the placeholders (`OWNER/REPO`, the token path,
`localhost:8080`) before sending.

**Scan and fix a repo**

1. `go to the public repo https://github.com/usestrix/strix, load it locally and run static and if it has a server like gradio or fastapi then stand up the server and run dynamic tests, and fix the issues found in these tests.`
2. `scan https://github.com/usestrix/strix and report what you find, but do not fix anything.`
3. `scan self and fix any issue you find.`
4. `check the dependencies of https://github.com/usestrix/strix for known CVEs (pip-audit and npm audit).`
5. `look for hardcoded secrets and leaked API keys in https://github.com/usestrix/strix.`
6. `check the versions of all your scanner tools and tell me which ones need an update.`
7. `scan the private repo https://github.com/OWNER/REPO (my token is in /secrets/github_token.txt) and fix any issue you find.`
8. `scan self with every scanner, fix everything you can, and give me a Word report of what you changed.`

**Active testing**

9. `go to the private repo https://github.com/OWNER/REPO (token file: /secrets/github_token.txt), load it locally and run redteam and if it has a server like gradio or fastapi then stand up the server and run pentest tests, and fix the issues found in these tests.`
10. `pentest http://localhost:8080/ with ZAP, and if you get in, fix the vulnerability and prove it is closed.`
11. `do a liveness and technology check on https://example.com (a site I do not own; I will type PENTESTLIVE to confirm).`

**Understanding the results**

12. `scan self with Bandit and Semgrep only, then explain each finding in plain language.`

## Status

- [x] Self-scan and self-fix (Aegis scanning and fixing its own source) — `install.sh` copies the
  source into `src/self` (pristine, read-only to the sandbox) and seeds `self_target/self`, the working
  copy the sandbox fixes and redteam re-scans read-only, so every fix is what the next re-scan sees.
- [x] Point at any public (or, with `GITHUB_CLONE_TOKEN`, private) GitHub repo — `redteam_clone_repo`
  clones it into the dynamic target pool at runtime (no container restart); use the name it returns with
  every later redteam_*/export_project call. Fixes for a cloned repo are made in `dynamic_target/<name>`,
  the same directory redteam re-scans.
- [ ] fixpentest's re-attack — ZAP attacks a target that is already running, and fixes are written in the
  network-less sandbox; nothing yet redeploys the fixed code, so a re-attack hits the unfixed target.
- [x] `backend/`'s chat loop — dispatches a person's words to the right tool, picks the LLM provider from
  `.env`, loops tool calls to completion. Shared by the CLI (`python -m backend.cli`) and the web UI.
- [x] The web UI (terminal + chat panes, model dropdown, running cost readout) — built, runs as the
  `aegis-backend-web` daemon on `:8900`, started by `install.sh` by default.
- [x] A real, repeatable fix loop for a cloned external repo — 3 independent runs against
  [usestrix/strix](https://github.com/usestrix/strix), each from a fresh clone, each reaching 0 findings
  across all 5 static scanners in one pass; see [the verification
  writeup](docs/strix_full_fix_verification_2026-10-26.md).

## License

Aegis is licensed under the [Apache License, Version 2.0](LICENSE). The full license text is in
the [`LICENSE`](LICENSE) file.

```
Copyright 2026 Musiac/IdeaNirvana

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

In short, you may use, modify and redistribute this software, including commercially, provided you:

- include a copy of the license with any redistribution;
- keep the existing copyright, patent, trademark and attribution notices;
- state prominently in any file you modify that you changed it;
- carry forward any `NOTICE` file's attributions, if one is added to this project.

The license includes an express patent grant from every contributor, which terminates for anyone who
files patent litigation alleging the software infringes a patent. It grants no right to use the
project's trade names or trademarks, and the software is provided "AS IS", without warranties or
conditions of any kind. This summary is for convenience only; the [`LICENSE`](LICENSE) text governs.
