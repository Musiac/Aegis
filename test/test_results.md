# Aegis test results

Timed runs against the real backend. Back to the [README](../README.md).

## Run matrix: repeatability evidence

Every row below is a timed run against the real backend, driven through the live `/ws` chat API end to end (clone, static scan, dynamic/active pentest where a server exists, fix, re-verify, export, report) — one row per repo, its last successful run.

| Date | Target | Wall time | Cost | Outcome |
|---|---|---|---|---|
| 2026-10-30 | [`usestrix/strix`](https://github.com/usestrix/strix) | 5m 57s | $0.904 | Static clean; ZAP 3 informational-only findings left |
| 2026-10-30 | [`google/pica`](https://github.com/google/pica) | 1m 13s | $0.297 | Static clean (no dynamic — no cargo toolchain) |
| 2026-10-30 | [`microsoft/TokenEconomizer`](https://github.com/microsoft/TokenEconomizer) | 4m 9s | $0.760 | Static clean |
| 2026-10-30 | [`aws/tools-for-devops-agent`](https://github.com/aws/tools-for-devops-agent) | 8m 25s | $1.077 | Static clean |
| 2026-10-30 | [`aws/sagemaker-python-sdk`](https://github.com/aws/sagemaker-python-sdk) | 19m 46s | $2.504 | Static clean except 3 pip-audit findings, not fixable by this tool (repo's own package pins conflict) |
| 2026-10-30 | [`openai/openai-agents-python`](https://github.com/openai/openai-agents-python) \* | 16m 5s | $2.049 | Static clean; real server stood up and pentested; ZAP down to 13 stable findings |

\* A Spark (Contributor) attempt on this repo was aborted — it made little real progress. Spark successfully finished all other repos above; this one needed the bigger Muse Wonder model to complete.

All costs are metered Muse token cost for the whole conversation (every scan + every fix +
the report), computed by `backend/model_pricing.py` from actual token usage.
