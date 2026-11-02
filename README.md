# Aegis

<p align="center"><img src="docs/assets/aegis-shield-arrow.png" alt="Aegis shield deflecting an incoming arrow" width="220"></p>
<p align="center"><img src="docs/assets/aegis-hackathon-badge.jpg" alt="Meta Global AI Developer Hackathon — 10 days on Meta's newest AI models, $1M in cash prizes" width="520"></p>

**Aegis** — **A**gentic **E**nterprise **G**uard for **I**nfo**S**ec, by **Musiac** — **Mus**e **I**ntelligence for **A**dvanced **C**yberSec.

*In Greek mythology, the aegis was no ordinary shield — the divine, impenetrable shield carried by Zeus and Athena, so that any enemy
who dared look upon it was turned instantly to stone. This Aegis works the same way: does not wait for an attack, it finds the vulnerability before hand, turns it to stone — fixes it in place — and proves the fix holds, before anything hostile
ever gets through.*

Think of Aegis as a guard dog that also happens to be a locksmith: it scans your code and container
images, actively tests the locks on a target you point it at, picks the ones it finds weak, fixes them
itself, then checks the door again to be sure it's really locked now. It doesn't stop at a report — it
keeps looping scan → fix → re-scan until the scan comes back clean. It's powered entirely by Meta's **Muse Spark**
and **Muse Wonder** models and runs four skills: `redteam`, `fixredteam`, `pentest`, `fixpentest`. Built for the
[Meta Global Hackathon](https://dev.meta.ai/events/global-hackathon).

Aegis is also careful with money: on public repos it uses **Muse Spark**'s cheaper contributor tier (where
Meta may use the content to train its models); on private repos or its own code, it switches itself to
the standard, non-contributor tier (content never used for training) — like checking your ticket before
deciding which seat you get.

We're **Musiacs** — **Muse Maniacs** — at **IdeaNirvana**, and that's not a line, it's where the repo's name
comes from (`Musiac/Aegis`). Before this hackathon even existed, we asked Meta's **Muse** (their personal
AI agent, not the **Muse** model) to look at our own live product, [Jiina](https://ideanirvana.com/solutions/jiina),
the way a stranger off the street would. On **12 October 2026**, logged in with a real test account, **Muse**
ran two passive checks against `ideanirvana.com`, `ideanirvana.ai` and `solutions.ideanirvana.com`.
Nothing critical turned up, but six real findings did — and we fixed every one the same day:

| Severity | Finding | Fixed |
|---|---|---|
| Medium | `ideanirvana.com` sent no security headers | ✅ same day |
| Medium | Jiina's event log showed the session key in plain text | ✅ same day |
| Low | The sign-in page could redirect to any web address after login | ✅ same day |
| Low | The content-security policy only reported, never blocked | ✅ same day (some pages still report-only) |
| Low | HSTS didn't cover subdomains | ✅ same day |
| Info | No `security.txt` contact file | ✅ published |

That's the moment that turned us into Musiacs, and the reason we built Aegis on **Muse** for this hackathon.
Full detail and every other Jiina security result is public at
[ideanirvana.com/solutions/jiina](https://ideanirvana.com/solutions/jiina).

## How Aegis relates to Jiina, and what was built this week

IdeaNirvana LLC is an existing startup; this hackathon entry is submitted in the Startup track by its
sole founder/developer. Our existing live product, [Jiina](https://ideanirvana.com/solutions/jiina), is
a multi-agentic assistant with its own unrelated skills (document editing, SAP/ServiceNow/Jira
workflows, reporting). **Jiina's code and git history are not part of this repository** and stay
closed-source.

**Aegis is a new, separate, single-agent project**, in its own repository
([`Musiac/Aegis`](https://github.com/Musiac/Aegis), created **27 October 2026**) built specifically for
this hackathon, sharing no code history with Jiina. Everything here is new for this hackathon: the whole
security-agent persona and skill set (`redteam`/`fixredteam`/`pentest`/`fixpentest`), the sandboxed
clone → scan → fix → re-verify pipeline, the live OWASP ZAP active-pentest integration, **Muse Spark** as
the driving model (with the larger **Muse Wonder** for harder jobs) and the public/private billing safety switch (see Benchmarks), push-to-talk voice
(Meta's own ASR, `muse-voice-transcribe-1.0`), and the structural guard in `core.py` that won't let the
agent call a fix job done when it isn't (see the Run log). The one deliberate overlap with Jiina is the
12 October 2026 passive-security story above — it predates this hackathon and is here only to show why
we trust **Muse** enough to build Aegis on it, not as part of the submission's own work.

## What it does

| Command | What happens |
|---|---|
| `redteam <target>` | Static scan only: gitleaks, Bandit, Semgrep, pip-audit, npm audit, Trivy. Reports every finding, asks before fixing anything. |
| `redteam <target> and fix it` | Scans, then writes and applies real fixes in an isolated sandbox copy, re-scans to confirm each one is actually gone, reports before/after. |
| `pentest <target>` | Active scan: OWASP ZAP (spider + active scanner) against a target you've stood up, or one real active probe against a live URL you explicitly consent to (typed `PENTESTLIVE`, never a plain "yes"). |
| `pentest <target> and fix it` | Attacks, writes a real fix, re-attacks to prove it's closed. |

`<target>` starts as "Aegis's own source" (self-scan) and a cloned copy of any public GitHub repo
you point it at (`run redteam on github repo: <url>`) — see "Status" below for what's live today.

**Stop, pause and resume mid-task** — just type it, no special syntax: "stop" / "restart" / "rewind"
cancels whatever is running and discards its progress; "pause" cancels but keeps every step done so far.
Either way, saying "start" or "continue" afterward picks the right behavior automatically — after a stop
it redoes the same task from scratch, after a pause it picks up exactly where it left off (no repeated
clones, no repeated scans). These are read mid-task, not just between tasks: say it any time, and it
takes effect as soon as the step Aegis is currently on finishes (never mid-command).

**Aegis can update its own scanner tools** — it checks scanner recency automatically the moment you connect,
before you type anything (Send stays disabled until the check comes back), and if anything is behind (e.g.
"Semgrep 1.182.1 → 1.183.0 available"), it asks whether to update. Say yes (or "go ahead, upgrade" —
any plain affirmative works, no fixed phrase) and it runs a real upgrade: a genuine `pip install --upgrade`
for Bandit/Semgrep/pip-audit, or a fresh binary download for gitleaks/Trivy/ZAP, written into the host-mounted
`redteam_tool_updates/` folder (`install.sh` creates and owns it, same pattern as every other persistent folder
this project uses) so its own read-only root filesystem is never touched. This is a real, permanent update — it
survives a container restart or recreate, not just the current session, the same way a scan target's own fixes
do. It re-checks afterward and reports the real result — every tool updated cleanly, or (if one failed) exactly
which ones are still on their old version and that it's proceeding anyway.

## Benchmarks: why we chose **Muse**

We put **Muse Spark** in a drag race against our own self-hosted model — same repo, same job, same
tool-calling loop: clone → static scan (gitleaks/Bandit/Semgrep/pip-audit/npm-audit) → live OWASP ZAP
active pentest → fix → re-verify. No synthetic benchmark, just the real tool doing real work, timed.

| Target | Type | Model / tier | Wall time | Cost |
|---|---|---|---|---|
| [`flemuh/radar-public-sector`](https://github.com/flemuh/radar-public-sector) | Public repo | **Muse Spark**, **contributor** tier | **18m 38s** (1118.0s) | $0.189 |
| same repo, earlier run | Public repo | local qwen3.8-27b-sglang | 27m 19s (1639.1s) | $0.00 |
| This repo (private) | Private repo | **Muse Spark**, **Standard** (non-contributor) tier | 7m 23s (442.9s) | $2.39 |

**Muse Spark won by ~32%** — 18m38s vs 27m19s on an identical job. The sports car beat the home-grown
hatchback running on our own GPU.

**When Spark isn't enough, Muse Wonder is.** On a public repo with a very long list of scanner findings, [`openai/openai-agents-python`](https://github.com/openai/openai-agents-python), **Muse Spark** struggled to work through and fix everything the scanners reported, and its attempt was stopped after making little real progress. We switched the same job to its bigger brother, **Muse Wonder**, and **Muse Wonder** did the job: it fixed the static findings, stood up a real server and pentested it, and brought the ZAP findings down to 13 stable ones, in 16m 5s for $2.049. Wonder costs more per token and has no cheaper contributor tier, so Aegis uses Spark by default and Wonder is one click away in the model dropdown.

## Meta models vs. OS/browser features

Here is exactly which parts of Aegis are a Meta model call and which are a plain OS/browser feature:

**Meta model calls (the only AI models this project calls at runtime):**
- **`muse-spark-1.3` / `muse-spark-1.3-contributor`** (Model API) — every chat turn, tool-calling decision,
  and fix the agent writes. The contributor tier is used automatically for public repos, the Standard tier
  for private repos/self-scans.

- **`muse-wonder-1.0`** (Model API) — Meta's larger model, selectable in the model dropdown for jobs where **Muse Spark**
  struggles (for example the very long findings list on `openai/openai-agents-python`). Standard tier only; Meta offers no contributor tier for it.

- **`muse-voice-transcribe-1.0`** (`wss://api.meta.ai/v1/asr/realtime`) — push-to-talk's speech-to-text,
  when the mic button is used.

**OS/browser features (no model call, no third-party API, no network request to any AI provider):**
- **Spoken replies (Voice toggle's "TTS: browser")** — the browser's own built-in `window.speechSynthesis`
  (Web Speech API). This renders entirely on the operator's own machine, using whatever system voice is
  already installed (macOS/Chrome ship several) — it is not an AI model, local or remote, and nothing is
  sent anywhere for it. An earlier draft of this feature called a local, self-hosted Kokoro-82M model (open
  source, running on this machine's own CPU). We reverted after Meta's organizers confirmed a third-party model can't be used even if it's local and free; the backend code for it (`kokoro/`, `backend/api/tts_kokoro`) still exists but
  `install.sh` never starts it and the UI never calls it. A Gemini one-shot TTS path (`/api/tts`, `GEMINI_TTS_MODEL_NAME`) also still exists server-side from an
  earlier build, same reasoning as Kokoro (a competitor's model) — never gets called by the current UI either.

## Testing

We ran Aegis end to end on six real public repositories, from small to large: clone, static scan, a live OWASP ZAP pentest where the repo can be run, fix, re-verify, export and report. Every run was timed and its cost metered. Five of the six finished clean on the static scanners; the sixth had 3 pip-audit findings the tool cannot fix, because the repository's own package pins conflict. Runs took about 1 to 20 minutes and cost $0.30 to $2.50. One run (`openai/openai-agents-python`, a repo with a very long findings list) needed the bigger **Muse Wonder** model after **Muse Spark** struggled with it; the details are in the results file.

Full table with dates, wall times, costs and outcomes: **[test/test_results.md](test/test_results.md)**.

## Why this exists

A pattern-matcher like Semgrep or Bandit reads your code; a semantic pentester like
[Strix](https://github.com/usestrix/strix) actually runs it and tries to break in — two different
skill sets, two different bug classes. We used our own source as the guinea pig: Strix found 4 real bugs
our static scanners never would have (cross-account sandbox access, a DNS-rebinding SSRF, a SQL
validator bypass, stale WebSocket sessions), we fixed every one, and a fresh Strix run confirmed they
stayed fixed. The reverse comparison is public too:
[Aegis scanning and fixing Strix's own source, 3 independent runs, each reaching 0 findings across
all 5 static scanners in one pass](docs/strix_full_fix_verification_2026-10-26.md).

## Install

**You'll need:** Docker, a bash shell (Linux, macOS, or WSL2 on Windows), plus `rsync` and `python3`.

```
git clone https://github.com/Musiac/Aegis
cd Aegis
cp .env.example .env            # fill in MUSE_API_KEY
bash install.sh                 # builds + starts aegis-code + aegis-libraries + a running sandbox trio; generates REDTEAM_TOKEN/PENTESTLIVE_TOKEN/TRIO_CONTROL_TOKEN into .env itself
```

The `install.sh` is a plain bash script, not a `docker compose` file — the
containers have deliberately different network modes, and the script is simpler to read end to end
before running it. It ends by printing the two ways in to the chat loop:

```
Web UI:  http://127.0.0.1:8900
CLI:     docker run -it --rm --network aegis-net -v aegis-sock:/sock --env-file .env aegis-code:latest
```

The web UI (`aegis-code`) runs as a daemon by default — open the URL and start typing. The
CLI is a separate, interactive container using the exact same image and the same running
`aegis-libraries`/sandbox containers; run it any time instead of (or alongside) the web UI.
`install.sh` also starts `trio_control` (a plain host process, not a container) and leaves the sandbox
trio running right after install — it idles back down to nothing after 5 minutes with no activity, same
as it does for every later task.

**Isolated Sandbox:** `aegis-sandbox` runs with `--network none` as a real, load-bearing security boundary
(the isolated code sandbox fixredteam/fixpentest write real fixes in) — it cannot share a
network namespace with `aegis-libraries`, which needs to reach the internet
(pip-audit/npm-audit's advisory databases) or a target host. "One docker" here means one command
(`bash install.sh`), not literally one container. See Architecture below for the full ephemeral-trio design.

## Built on LightMA™

**LightMA™: our own lightweight, auditable agentic framework**

Before writing a line of Aegis, we looked at the usual suspects — LangChain, LangGraph, Microsoft Agent
Framework, Google ADK, Strands — and wanted something a single person could read top to bottom and
trust, for an agent doing real, consequential work like writing code fixes and running live attacks. So
we built our own: a simple round loop that scans, reasons, and calls real tools, with structural guards
built in so the loop can't quietly call itself "done" when it isn't.

Aegis is our first agent on LightMA™ — one agent, real scans, real fixes, real reports, all in a single
conversation. We've been adding skills to it ever since.

LightMA — a Lightweight MultiAgentic framework — is built on many guardrails and gentle nudges which keep
either a single-agentic solution like Aegis, or any multi-agentic system, on track to ensure it never
loses sight of the original task given by the user. This ensures Aegis always finishes the task it
receives. The full list of guardrails and nudges is in [aegis_guardrails_and_nudges.txt](aegis_guardrails_and_nudges.txt).

## Architecture

![Aegis architecture, high level: the operator talks to Aegis, which calls 1 active + 6 passive scan tools plus guardrails, runs commands in a locked-down sandbox, and can clone a repo, pentest it live, and write fixes back](docs/assets/aegis_architecture-highlevel.png)

![Aegis architecture: browser → aegis-code → aegis-libraries/sandbox-proxy, with the code-fix sandbox isolated behind --network none, Meta's Model API and GitHub as the only external services, and host-mounted volumes for scan targets and exported fixes](docs/assets/aegis_architecture-technical.png)

Aegis runs as two kinds of containers:

- **Permanent containers (2), always running:**
  - **`aegis-code`** holds the Aegis main code: the chat loop, the web UI and the CLI.
  - **`aegis-libraries`** holds all the scanner libraries and tools: gitleaks, Bandit, Semgrep, pip-audit, npm audit, Trivy and OWASP ZAP.
- **Short-lived containers (3), created on demand:** a sandbox trio (`aegis-sandbox`, `aegis-sandbox-proxy`, `aegis-sandbox-web`) that exists only while a task needs a sandbox and is removed after 5 minutes of no use.

**Why the code and the libraries are in separate containers:** the scanner libraries are large. If everything lived in one container, every small code change would force a rebuild of that whole heavy image, and each deploy would take a long time. With the split, a code change rebuilds only the small `aegis-code` image, so builds and deploys are fast. The heavy libraries image changes rarely.

Every container, network, volume and port is described in [container_details.md](container_details.md).

## Security

Aegis attacks other people's code, so we treated its own security as a first-class feature. In short:

- **We ran Aegis on itself ("eat your own dog food").** Aegis scanned and fixed its own source, and the Strix pentester found 4 real bugs in it that static scanners miss; we fixed every one and a fresh run confirmed they stayed fixed.
- **We tried to break out of the sandbox ourselves.** Six real attacks against the live sandbox (deleting host files, exfiltrating data, resource bombs, stealing keys, container breakout, a zip symlink trick). Five were blocked or contained; the sixth found a real bug in our export step, which we fixed and re-verified.
- **The sandbox is locked down:** no network device at all, read-only root, non-root user, zero Linux capabilities, capped CPU, memory and processes. Its only way out to the internet is an allow-list proxy (PyPI and npm only), and finished work leaves only through one export folder.
- **The main container has no Docker access.** A small host-side helper creates and removes the sandbox containers, accepts only four commands (`start`, `stop`, `status`, `touch`) on localhost with a token, and runs a safety check on every new sandbox before it is used.
- **Real credentials never enter the sandbox,** and secrets in commands and logs are masked.
- **Active attacks need consent.** A live probe of a real URL runs only when you type the exact consent word; active scanning otherwise targets only servers Aegis stood up itself in the sandbox.
- **Private code is protected by default:** private repos and Aegis's own code automatically use the non-training model tier, and Aegis warns before cloning a private repo.
- **Aegis keeps its own scanners current:** it checks scanner versions every time you connect and updates outdated tools itself.
- **The agent cannot call a job done when it isn't:** structural guards force the fix and report steps, and report numbers are computed by code, not by the model.

The full record of the six sandbox attacks and their results is in [aegis_security_details.md](aegis_security_details.md).

## UI

Two fixed-height panes side by side, each scrolling independently: the live terminal (scan/fix
progress) on the left, the chat conversation on the right. The header holds the model dropdown
(**Muse Spark** or **Muse Wonder** — your own key), a running "Total cost" readout (the real, metered LLM token cost for the session so far, updated after every
turn), and a connection status indicator. No audio controls — text in, text out.

Under both panes sits a strip of example questions (six at a time, shown shortened). Clicking one puts
the full question in the chat box, unsent, so you can edit it first; the small arrow at the bottom right
pages between examples 1–6 and 7–12. The list lives in `backend/static/app.js` (`EXAMPLES`).

## Aegis observability

Aegis works like a Hibachi Chef - cooks right on your table. As Aegis works diligently on each task you give to it, it opens a terminal for you to see exactly each command it is running in the sandbox, with the output of that command displayed right there to you. At the end of working session of Aegis, you can click on download to get the full log of its working session in front of you.

![Aegis mid-job: the terminal on the left filled with live tool calls (clone, bash_run, redteam_bandit, create_word_document) while the chat on the right narrates each step in plain language, ending with a downloadable Word report](docs/assets/aegis_terminal_live_run.jpg)

## Run log

Every turn writes one-line events to the backend's stdout, so the efficiency of a run can be read without
the page: `docker logs aegis-code | grep cj-turn`. Events: `session_open` / `session_close`,
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
7. `scan the private repo https://github.com/OWNER/REPO (my token is in FILEPATH_WITH_GITHUB_API) and fix any issue you find.`
8. `scan self with every scanner, fix everything you can, and give me a Word report of what you changed.`

**Active testing**

9. `go to the private repo https://github.com/OWNER/REPO (token file: FILEPATH_WITH_GITHUB_API), load it locally and run redteam and if it has a server like gradio or fastapi then stand up the server and run pentest tests, and fix the issues found in these tests.`
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
  `aegis-code` daemon on `:8900`, started by `install.sh` by default.
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
