"""Structured one-line-per-event log of what Aegis actually did in a turn, written to stdout so `docker logs aegis-backend-web`
shows it. The point is to judge a run's efficiency from the server side alone: how many model rounds, which tools in what order, how long
each took, what each cost, which calls were repeats, which failed.

Nothing sensitive is written. Tool RESULTS are never logged, only metadata about them (ok, counts, exit code, sizes, a scrubbed error).
Tool ARGUMENTS are logged scrubbed: values under a key that looks like a secret become ***, document bodies become a length, and
anything that looks like a credential inside a command or URL is masked. Each line is `[cj-turn] {json}`."""
import json
import re
import sys
import time
from datetime import datetime, timezone

_SENSITIVE_KEY = re.compile(r"pass|token|secret|key|auth|cookie|bearer|credential", re.I)
_URL_CREDS = re.compile(r"(https?://)[^/\s:@]+:[^@\s/]+@")
_SCHEME_TOKEN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{6,}")
_AUTH_WORDS = re.compile(r"(?i)\b(authorization|token|password|passwd|secret|api[_-]?key)\b([\"']?\s*[:=]\s*[\"']?)([^\s\"',}&]+)")
_KNOWN_SECRET_SHAPES = re.compile(r"\b(?:ghp_|gho_|ghs_|github_pat_|sk-|sk-ant-|AKIA|AIza|xox[abp]-)[A-Za-z0-9_\-]{8,}")


def scrub(value, limit: int = 200) -> str:
    """Masks credentials in free text and shortens it."""
    s = str(value if value is not None else "")
    s = _URL_CREDS.sub(r"\1***@", s)
    s = _SCHEME_TOKEN.sub(lambda m: f"{m.group(1)} ***", s)
    s = _AUTH_WORDS.sub(lambda m: f"{m.group(1)}{m.group(2)}***", s)
    s = _KNOWN_SECRET_SHAPES.sub("***", s)
    s = s.replace("\n", " ").strip()
    return s if len(s) <= limit else s[:limit] + f"...(+{len(s) - limit})"


def summarize_args(name: str, args: dict) -> dict:
    out = {}
    for k, v in (args or {}).items():
        if _SENSITIVE_KEY.search(str(k)):
            out[k] = "***"
        elif name == "create_word_document" and k == "body":
            out[k] = f"<{len(str(v))} chars>"
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = scrub(v, 200)
    return out


def summarize_result(result) -> dict:
    """Metadata about a tool result, never its content."""
    s = result if isinstance(result, str) else str(result)
    info = {"chars": len(s)}
    try:
        d = json.loads(s)
    except ValueError:
        return info
    if not isinstance(d, dict):
        return info
    for k in ("ok", "exit_code", "timed_out", "truncated", "seconds", "count", "active_scan_ran", "created", "size_kb", "accessible", "error_type"):
        if k in d:
            info[k] = d[k]
    if isinstance(d.get("findings"), list):
        info["listed"] = len(d["findings"])
    summ = d.get("summary")
    if isinstance(summ, dict):
        info["summary_total"] = summ.get("total")
        info["summary_truncated"] = summ.get("truncated")
    for k in ("stdout", "stderr"):
        if isinstance(d.get(k), str):
            info[f"{k}_chars"] = len(d[k])
    if d.get("error"):
        info["error"] = scrub(d["error"], 160)
    return info


def log(event: str, **fields) -> None:
    rec = {"t": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3], "event": event, **fields}
    try:
        print("[cj-turn] " + json.dumps(rec, default=str, ensure_ascii=False), file=sys.stdout, flush=True)
    except Exception:                                                             # noqa: BLE001 -- logging must never break a turn
        pass


class Stopwatch:
    def __init__(self):
        self.t0 = time.monotonic()

    def lap(self) -> float:
        return round(time.monotonic() - self.t0, 2)
