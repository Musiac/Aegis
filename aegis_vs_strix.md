# Aegis and Strix, side by side: the detailed numbers

This is the detail behind the short comparison in the [README](README.md#where-we-stand). We compared Aegis with [Strix](https://github.com/usestrix/strix), the most-starred open-source AI pentesting agent on GitHub, on the same code, with the same model, on the same machine, on the same day (3 November 2026). **We ran it ourselves, so this is not an independent evaluation.** We publish exactly what we ran so you can judge it, and repeat it if you like.

## Setup

| | Aegis | Strix |
|---|---|---|
| Version | 0.1.0 for runs 1 to 3, 0.1.1 for run 4 (see the notes below) | 1.7.0 (commit `6b7ae2eb`, sandbox image `strix-sandbox:1.3.1`), run in `quick` mode |
| Model | Meta Muse Wonder (`muse-wonder-1.0`) | Meta Muse Wonder (`muse-wonder-1.0`), through Meta's Responses API |
| Target | `openai/openai-agents-python` at commit `e355d691` (91 MB) | same |
| Changes for this test | none | one 5-line local patch, because Meta's endpoint rejects the "freeform" tool type Strix sends by default. Everything else is stock Strix |
| Cost | token counts from the run logs, priced at Muse Wonder's published rates ($4.00 input, $0.20 cached input, $20.00 output per million tokens), with the same formula for both tools | same |

## What we measured

Strix was run twice. Aegis was run four times: once in static mode (`redteam … and fix it`) and three times in pentest mode (`pentest … and fix it`). Every run finished. Aegis's third run exposed a bug (see the notes below), which we fixed and released as 0.1.1 before the fourth run.

| Run | Wall time | Cost | Input tokens (cached) | Output tokens | Issues reported |
|---|---|---|---|---|---|
| Strix, run 1 | 19 min 55 s | $20.96 | 60.5 M (97.0%) | 101,056 | **13**: 1 High and 1 Medium in the SDK's code, 11 Informational dependency CVEs |
| Strix, run 2 | 30 min 45 s | $28.67 | 77.4 M (96.7%) | 179,952 | **11**: 2 High and 3 Medium in the SDK's code, 1 Low and 5 Informational dependency CVEs |
| Aegis, run 1 (static) | 7 min 13 s | $1.11 | 1.4 M (95%) | 29,327 | **319** static findings: gitleaks 9, Bandit 295, Semgrep 15. The pentest did not run: the server failed to start |
| Aegis, run 2 (pentest) | 8 min 18 s | $1.40 | 2.0 M (96%) | 34,313 | **336**: the same 319 static findings plus 17 ZAP alerts (2 Medium, 2 Low, 13 Informational) |
| Aegis, run 3 (pentest) | 11 min 30 s | $2.47 | 3.5 M (95%) | 51,193 | **319** static findings. The server started, but ZAP's active scan did not run (twice). Aegis reported that rather than call it clean |
| Aegis 0.1.1, run 4 (pentest) | 7 min 51 s | $1.42 | 1.8 M (92%) | 25,421 | **319** static findings. ZAP's active scan ran, before and after the fixes, against a small test app: 0 alerts |

Cached-token figures for Aegis are derived from its per-round costs, because Aegis does not log them. Without the cache discount, Strix's run 1 would have cost $244.

**Issue collection only.** Strix reports findings and does not fix them. Aegis also fixes, so for a like-for-like cost, count only the part of each Aegis run before its first fix (Aegis logs this point):

| | Strix | Aegis |
|---|---|---|
| Time to a finished list of issues | 19 min 55 s and 30 min 45 s | 5 min 34 s, 4 min 15 s, 6 min 41 s and 3 min 27 s |
| Cost of that list | $20.96 and $28.67 | $0.69, $0.49, $1.29 and $0.60 |

Aegis's whole run, including fixing, re-scanning and writing the report, cost $1.11, $1.40, $2.47 and $1.42.

## What the numbers do and do not say

- **The issue counts do not measure the same thing.** Strix reports findings it validated with a proof-of-concept, and rated the dependency CVEs "informational" because the vulnerable code was not reachable from the SDK. Aegis counts raw scanner hits, mostly Bandit pattern matches, plus ZAP alerts. A higher number is not better.
- **Strix found real logic bugs that Aegis did not.** In run 1 it found that the MCP `require_approval` policy fails open for renamed tools, and that streamed events leak output-guardrail-blocked content. Run 2 found the streaming problem again in a different form, plus new issues. The two Strix runs did not report the same list, so repeat runs matter. Aegis's scanners and one ZAP scan of an example server cannot find bugs of that kind.
- **Aegis fixes and checks its own fixes; Strix's open-source CLI does not.** After fixing, Aegis re-ran its scanners (and, in pentest mode, ZAP) and all static scanners were at zero. That shows the scanners went quiet, not that the SDK's behaviour is unchanged: we did not run the SDK's own tests on the fixed code.
- **Aegis's pentest depended on how the server was started, and we fixed one cause.** The model picks which example server to start. In 0.1.0, one run's server failed to start and one run's ZAP active scan never ran: the model had started the server bound to `127.0.0.1`, so the scanner, which runs in a separate container, could not reach it. We fixed that in 0.1.1 (the start tool now binds to all interfaces and checks the app is reachable from outside its own container, ZAP refuses to report "0 findings" for an unreachable target, and the prompt says so). In the one run since, on 0.1.1, ZAP's active scan ran. One run is not proof it will run every time. In that run ZAP found no alerts on a small test app, which is weaker evidence than run 2's scan of a larger example server.
- **Aegis cost far less in this test**, mostly because it sent 1 to 3.5 million tokens against Strix's 54 to 77 million, which reflects how differently the two work. That also means Strix is searching more deeply for exploitable bugs.
- **Small sample.** Two Strix runs, four Aegis runs (three on 0.1.0, one on 0.1.1), one target repository, one model, one machine. Cost also varied between runs of the same tool: Strix's second run cost 37% more than its first, and Aegis's runs ranged from $1.11 to $2.47.

## Feature comparison

✅ means yes, ❌ means no, 🟡 means partly. "Not documented" means we found no mention, not that we tested it and it is absent. Strix facts come from its docs and source; Aegis facts come from its code. Aegis is described as of 0.1.1.

| | Aegis | Strix 1.7.0 |
|---|---|---|
| Has a user interface | ✅ Yes: web UI with a chat and a live terminal pane | ✅ Yes: terminal UI, plus `strix view`, a local web dashboard for live or finished runs; headless mode for CI |
| Shows its work as it goes | ✅ Yes: every command appears in the terminal pane | ✅ Yes: live terminal UI and dashboard |
| Can be stopped | ✅ Yes: say "stop"; the work in progress is discarded and "continue" starts the task again | ✅ Yes: Esc stops an agent in the terminal UI, which then shows "Agent stopped" |
| Can be paused, then continued where it left off | ✅ Yes: say "pause"; every step and tool result so far is kept, and "continue" picks the same run back up exactly where it stopped | 🟡 We found no manual pause. In interactive mode it pauses by itself when the dollar budget is reached, and sending any message resumes it. A stopped or interrupted run can be restarted later with `--resume`, which restores the history of unfinished agents; we did not test that |
| Fixes the issues it finds | ✅ Yes, in a sandbox copy | 🟡 The open-source CLI does not: it reports findings with remediation text and suggested before/after code. Its README lists one-click autofix pull requests under Strix Cloud, the hosted product |
| Checks that a fix worked | ✅ Yes: re-runs the scanners and, in pentest mode, ZAP | ❌ The open-source CLI does not. A bundled skill tells a separate coding agent to patch and re-run Strix |
| Attacks a running app | ✅ Yes: OWASP ZAP against a server it starts from the repo | ✅ Yes: Kali-based sandbox with ZAP, Nuclei, sqlmap, Caido and a browser |
| Proves bugs with working exploits | ❌ No | ✅ Yes: it writes proof-of-concept exploits |
| Network isolation | The sandbox where fixes are written has no network. The container that runs the target app can reach the internet for dependency installs | Attacks run in a Docker sandbox. We found no outbound-network restriction in its code; the sandbox adds network capabilities for scanning |
| Starts the target app itself | 🟡 Yes, with limits: the model chooses an example server (see the notes above) | Takes source, a repository URL, a live URL or an API spec; in our runs it tested the SDK locally with scripted models |
| Voice | ✅ Yes: push-to-talk input; replies use the browser's built-in voice | ❌ No voice feature found |
| Updates its own scanners | ✅ Yes: checks and updates them when it starts | ❌ Scanners are in a pinned sandbox image, so they change with new Strix releases. The CLI can update itself (`--update`) |
| Keeps a run from running away | Round limit, forced-finish checks, and a rule that stops it after two failed server starts | `--max-turns` (default 500 per agent), `--max-budget` in dollars, and a budget slice reserved for the final report |
| Switching the AI model | ✅ A dropdown in the UI with three Meta models (Spark Contributor, Spark, Wonder), changeable between tasks | ❌ An environment variable or config file, set before the run |
| Reports | A Word report and a zip of the fixed project | Markdown report, JSON, CSV and SARIF |
| Gives you a diff of every fix made | ✅ `CHANGES.txt` in the zip is a real before/after diff of the original and the fixed project | ❌ The open-source CLI changes no code, so there is no diff. Its findings carry suggested before/after code snippets |
| Gives you a full Word report to download | ✅ A Word report, offered as a download in the chat and also added to the zip | ❌ Markdown, JSON, CSV and SARIF files in the run folder. Its web viewer can export a PDF, after an email verification against Strix's servers |
| Gives you the full terminal log to download | ✅ A download button on the terminal pane saves every command and its output as a text file | ❌ It keeps a diagnostic log (`strix.log`) and a database of every command in the run folder, and shows them in its UI, but we found no readable terminal-log export. In our run the log file contained none of the commands |
| CI/CD | ❌ Not available yet | ✅ GitHub Actions workflow; `--fail-on` exit codes |
| Asks you to type a consent word before touching a live website | ✅ For a website that is not yours, you must type the word `PENTESTLIVE` first; Aegis will not accept "yes" | ❌ Its README carries an "authorized use only" notice; we found no consent step in the tool |
| Attacks a live website you point it at | 🟡 On a third-party site it makes one liveness and technology check, never a vulnerability scan. Its attacks run against apps it starts itself, inside its sandbox | ✅ URLs, domains and IP addresses are all targets |
| Choose how deep the scan goes | ❌ | ✅ `quick`, `standard` or `deep` (deep is the default) |
| Scan only what a pull request changed | ❌ | ✅ `--scope-mode diff` with `--diff-base` |
| Test an API from an OpenAPI or Postman file | ❌ | ✅ |
| Several AI agents working together | ❌ Aegis is a single agent by design | ✅ Multi-agent orchestration |
| Checks repo size and disk space before it clones | ✅ | Not documented |
| Clones a private repo from a token file | ✅ You give it the path to a file holding a GitHub token; the scanner container uses it to clone, and the code sandbox only receives the repository | 🟡 It runs a plain `git clone` on your computer, so a private repo works only if your own git is already logged in (or the token is in the URL). It has no token-file option |
| Shows the running cost on screen | ✅ A total in the page header, updated after every turn | ✅ In the terminal UI and the final summary |

## Guards that keep a task on track

Both tools have ways to stop an agent from drifting or quitting early. Strix nudges an agent that ends a turn without calling a tool (bounded by a recovery limit), warns it as its dollar budget runs down, and caps its turns. Aegis has those kinds of limits too, and because Aegis also fixes code, it has guards that only make sense for a fixing tool. Strix's open-source CLI does not fix code, so it has no equivalent:

- If the scan found issues but the agent has not fixed anything, Aegis tells it to start fixing.
- A fix job is not allowed to end until the fixed project is exported and the Word report is created.
- Each of those nudges is limited, so a task cannot loop on them forever, and a hard round ceiling stops a runaway turn.
- After two failed attempts to start a server, it stops retrying and says so.
- Scan totals are computed by code, and a Word report is checked against them before it is created, so the numbers cannot drift from the scan.
- When a report ships, the sandbox server is stopped and the scratch space is cleared at the next connection.

## What this page does not compare

We left out community size, public benchmarks and the choice of AI providers. Strix is far more established (tens of thousands of stars and a published benchmark), and we do not want that to be lost: it is a mature project and Aegis is brand new. Aegis currently works only with Meta's Muse models because of the hackathon's rules. Once the hackathon winners are announced on 8 November 2026 we plan to support many more providers in a later release, so a provider row would compare the hackathon's rules and not the tool.

## Other tools

We also reviewed eight other open-source tools in this space (Shannon, PentAGI, PentestGPT, RedAmon, Codex Security, RAPTOR, Decepticon and HexStrike). None of them documented all of scanning, attacking, fixing and re-verifying as one default open-source run. The closest partial matches are RedAmon (opens fix pull requests but does not re-attack), Decepticon (an optional patch-and-verify step) and Codex Security (separate patch and verify-fix steps, no live pentest). Several of them lead Aegis on maturity, model choice or CI.
