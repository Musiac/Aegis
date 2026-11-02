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

## How Aegis relates to Jiina, and what was built this week

IdeaNirvana LLC is an existing startup; this hackathon entry is submitted in the Startup track by its
sole founder/developer. Our existing live product, [Jiina](https://ideanirvana.com/solutions/jiina), is
a multi-agentic assistant with its own unrelated skills (document editing, SAP/ServiceNow/Jira
workflows, reporting). **Jiina's code and git history are not part of this repository** and stay
closed-source.

**Aegis is a new, separate, single-agent project**, in its own repository
([`Musiac/Aegis`](https://github.com/Musiac/Aegis), created **27 October 2026**) built specifically for
this hackathon. Its agent loop (`core.py`) grew out of code first written in our closed-source projects Jiina and cyberJiina, so parts of it resemble them; this repository's git history contains none of theirs. New for this hackathon: the whole
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
