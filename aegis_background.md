# Aegis background

Where Aegis comes from, and how it relates to our other product. Back to the [README](README.md).

## The Musiacs story

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

## Why we built our own agent loop

For Aegis we looked at the frameworks in common use: LangChain, LangGraph, Microsoft Agent Framework, Google ADK and Strands. They carry a huge overhead because they have so many features. We wanted something lightweight, yet simple enough to read and reason about from end to end.

A multi-agent architecture was not a fit either. Aegis's skills (red-teaming, pentesting and fixing the issues found in any repo) make it a single-operator agent doing real, consequential work: writing code fixes and running active security scans. Orchestrating and routing between several agents would add considerable overhead for no gain.

We did not have to look any further. We had already written our own LiveMA framework for Jiina, our single-agent, live two-way voice assistant, whose skills cover the enterprise: ERP solutions like SAP and JDE, ServiceNow, Salesforce, DB Intelligence, RFP generation, document editing and many more. So for Aegis, our cybersecurity guard and shield, we wrote our own single-agent loop (LightMA) and did not use any of the large, overhead-heavy, common multi-agent frameworks. More on it in [aegis_architecture.md](aegis_architecture.md).

Aegis has four skills: `redteam`, `pentest`, `fixredteam` and `fixpentest`. We built them for one purpose: ease of use. It is literally point and forget. To use Aegis, a user just gives it the URL of a public repo, and that is it. Aegis takes over: it clones the repo, uses `redteam` and `pentest` to find the issues in the code, and uses `fixredteam` and `fixpentest` to hand back a zip file of the fully fixed code. It fixes not only the critical issues but the medium and low priority ones too.

## How Aegis relates to Jiina, and what was built this week

IdeaNirvana LLC is an existing startup; this hackathon entry is submitted in the Startup track by its
sole founder/developer. Our existing live product, [Jiina](https://ideanirvana.com/solutions/jiina), is
a single-agent, live voice assistant with its own unrelated skills (document editing, SAP/ServiceNow/Jira
workflows, reporting). **Jiina's code and git history are not part of this repository** and stay
closed-source.

**Aegis is a new, separate, single-agent project**, in its own repository
([`Musiac/Aegis`](https://github.com/Musiac/Aegis), created **27 October 2026**) built specifically for
this hackathon. Aegis's pattern and architecture were ported from Jiina, our closed-source single-agent product, whose skills cover other areas such as ERP, DB Intel and document understanding. The code for Aegis follows the same single-agent pattern and architecture, but we wrote Aegis for cybersecurity work, with the pentest, redteam, fixpentest and fixredteam skills, for this hackathon, which started on 26 October 2026. Jiina's code and history are not in this repository. New for this hackathon: the whole
security-agent persona and skill set (`redteam`/`fixredteam`/`pentest`/`fixpentest`), the sandboxed
clone → scan → fix → re-verify pipeline, the live OWASP ZAP active-pentest integration, **Muse Spark** as
the driving model (with the larger **Muse Wonder** for harder jobs) and the public/private billing safety switch (see [test/test_results.md](test/test_results.md)), push-to-talk voice
(Meta's own ASR, `muse-voice-transcribe-1.0`), and the structural guard in `core.py` that won't let the
agent call a fix job done when it isn't (see the Run log). The one deliberate overlap with Jiina is the
12 October 2026 passive-security story above — it predates this hackathon and is here only to show why
we trust **Muse** enough to build Aegis on it, not as part of the submission's own work.

## Why this exists

A pattern-matcher like Semgrep or Bandit reads your code; a semantic pentester like
[Strix](https://github.com/usestrix/strix) actually runs it and tries to break in — two different
skill sets, two different bug classes. We used our own source as the guinea pig: Strix found 4 real bugs
our static scanners never would have (cross-account sandbox access, a DNS-rebinding SSRF, a SQL
validator bypass, stale WebSocket sessions), we fixed every one, and a fresh Strix run confirmed they
stayed fixed. The reverse comparison is public too:
[Aegis scanning and fixing Strix's own source, 3 independent runs, each reaching 0 findings across
all 5 static scanners in one pass](docs/strix_full_fix_verification_2026-10-26.md).
