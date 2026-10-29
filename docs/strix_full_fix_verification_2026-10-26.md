# Full fix verification -- usestrix/strix, 2026-10-26

Three separate, independent runs of the exact same request against the real `backend` chat loop --
"go to https://github.com/usestrix/strix and scan and fix the issues in it." -- each starting from a
**freshly re-cloned** copy (no reused state between runs), each ending with every scanner at **0
findings** in a single conversation turn: no stuck loop, no untouched tool, no "needs a follow-up pass."

This is the result of a hardening pass on `backend/system_prompt.py` done the same day, after several
earlier runs against this exact target surfaced real, reproducible bugs (wrong-line suppression
placement, npm fixes never attempted, a transitive dependency with no line to edit, false positives
diagnosed but never suppressed, batching several Semgrep fixes into one re-scan). Each bug was
confirmed live, fixed in the prompt, and re-tested before moving on -- see the git history of
`backend/system_prompt.py` around 2026-10-26 for the full list of fixes and their citations.

## Same starting point, every run

| Tool | Initial findings (every run) |
|---|---|
| gitleaks | 2 |
| Bandit | 0 |
| Semgrep | 6 |
| pip-audit | 9 |
| npm-audit | 5 |

## Results

| Run | Wall-clock time | LLM cost | Final: gitleaks / Bandit / Semgrep / pip-audit / npm-audit | Artifacts |
|---|---|---|---|---|
| 1 (first clean run, 2026-10-26 03:30) | ~3m 40s | $1.2934 | 0 / 0 / 0 / 0 / 0 | `usestrix_strix_2026-10-26-07-33-11.zip`, `Static_fix_report_--_usestrix_strix_2026-10-26T07-33-43.docx` |
| 2 (verification, 2026-10-26 08:50) | ~4m 35s | $0.9379 | 0 / 0 / 0 / 0 / 0 | `usestrix_strix_2026-10-26-12-54-05.zip`, `Static_fix_report_--_usestrix_strix_2026-10-26T12-54-47.docx` |
| 3 (verification, 2026-10-26 08:55) | ~3m 35s | $0.6597 | 0 / 0 / 0 / 0 / 0 | `usestrix_strix_2026-10-26-12-58-25.zip`, `Static_fix_report_--_usestrix_strix_2026-10-26T12-58-53.docx` |

**Totals across the 3 runs: ~11m 50s wall-clock, $2.891 LLM cost.**

Cost is the real, metered LLM token cost for the whole conversation (every scan + every fix + the final
report), computed by `backend/model_pricing.py` from each call's actual token usage -- not an estimate.
Wall-clock time is the real duration of the backend process handling the one request end to end: clone,
scan, fix, re-scan (as many passes as each finding needed), export, and generate the Word report.

## What "0 findings" means here

Every one of the original 26 findings (2 + 0 + 6 + 9 + 5) across the 3 runs was either:
- a real code/config change (dependency version bumps for `cryptography`/`filelock` in `pyproject.toml`,
  a redacted secret, real `npm install` upgrades for the 5 vulnerable frontend packages), or
- a `# nosemgrep: <exact rule id>` / `# gitleaks:allow` suppression on the exact flagged line, with a
  cited reason, for a finding confirmed to already be mitigated or intentional by design (the uv/npm
  supply-chain cooldowns were already configured; the Jinja2 environment renders LLM prompts, not
  browser HTML; the Caido API client's URL is config-derived, not user input; the PoC viewer's
  `dangerouslySetInnerHTML` renders already-processed highlighter output).

Each run re-scanned after every individual fix (not one batch-then-rescan pass) and confirmed that
specific finding was actually gone before moving to the next -- the per-finding looping and suppression-
placement rules added to `system_prompt.py` this same day are what made this reliable across 3
independent runs instead of a one-off.
