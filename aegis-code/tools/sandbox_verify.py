"""verify_sandbox_safety -- proves the sandbox's isolation guarantees with REAL commands run through the same exec_server.py
socket bash_run uses, rather than asserting them in prose. Reuses sandbox_tools._call for the socket round-trip so there is
exactly one place that talks to exec_server.py.

Three checks, each run for real and reported exactly as it comes back:
  1. write_outside_sandbox -- tries to write into a read-only mount (/dynamic_pristine) and the read-only root filesystem
     (/etc), and shows both fail.
  2. external_network -- tries a real HTTPS request to www.ibm.com and shows it fails near-instantly (the sandbox container
     has --network none: no network device at all, so this is not a timeout, it is an immediate "network unreachable").
  3. resource_caps -- reads the REAL cgroup limits Docker enforces on this container (memory.max, pids.max, cpu.max) rather
     than trying to exhaust them. Deliberately NOT a destructive test: actually triggering an OOM/fork-bomb to "prove" the
     cap works would crash the very sandbox needed for the rest of the session's work. The caps themselves (read here, not
     invented) are what bound a runaway process to this one container -- see install.sh's docker run flags for the source
     of truth these numbers are read from live.
"""
import json
import re

from .sandbox_tools import _call

CHECKS = [
    {
        "key": "write_outside_sandbox",
        "progress": "now running: trying to write outside the sandbox's writable paths (a read-only mount and the read-only root filesystem)...",
        "simple": "Now testing: trying to create a file outside the sandbox...",
        "cmd": (
            "echo '--- touch /dynamic_pristine/__verify_test (read-only clone mount) ---'; "
            "touch /dynamic_pristine/__verify_test 2>&1; "
            "echo '--- touch /etc/__verify_test (read-only root filesystem) ---'; "
            "touch /etc/__verify_test 2>&1; "
            "rm -f /dynamic_pristine/__verify_test /etc/__verify_test 2>/dev/null; "
            "echo CHECK_DONE"
        ),
    },
    {
        "key": "external_network",
        "progress": "now running: trying a real HTTPS request to www.ibm.com (an external site this sandbox has no reason to reach)...",
        "simple": "Now testing: trying to reach www.ibm.com from inside the sandbox...",
        "cmd": "curl -s -m 3 -o /dev/null -w 'http_code=%{http_code} exit_code=%{exitcode}\\n' https://www.ibm.com 2>&1; echo CHECK_DONE",
    },
    {
        "key": "resource_caps",
        "progress": "now running: reading the real memory/process/CPU caps the Docker host enforces on this container...",
        "simple": "Now testing: checking the sandbox's memory/CPU/process limits...",
        "cmd": (
            "echo \"memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)\"; "
            "echo \"pids.max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)\"; "
            "echo \"cpu.max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)\"; "
            "echo CHECK_DONE"
        ),
    },
]


def _evaluate(results: list) -> tuple:
    """Real pass/fail judgment for the 3 checks -- the single source of truth both verify_sandbox_safety's own
    reply and run_safety_gate's hard gate rely on (moved out of web.py's old greeting-only narration, 2026-10-31,
    so a genuine isolation failure is a real, code-checked fact, never left to the model's own reading of raw
    stdout). Returns (passed, reasons) -- reasons is a list of real, specific mismatches, empty when passed."""
    by_check = {r["check"]: (r.get("raw") or {}) for r in results}
    reasons = []
    w = by_check.get("write_outside_sandbox", {})
    w_out = (w.get("stdout") or "") + (w.get("stderr") or "")
    if w_out.count("Read-only file system") < 2:
        reasons.append(f"write_outside_sandbox: expected 'Read-only file system' twice (once per path tried), got {w_out[:200]!r}")
    n = by_check.get("external_network", {})
    n_out = n.get("stdout") or ""
    m = re.search(r"exit_code=(\d+)", n_out)
    if not (m and m.group(1) != "0"):
        reasons.append(f"external_network: expected a nonzero curl exit code (network unreachable), got {n_out[:200]!r}")
    c = by_check.get("resource_caps", {})
    c_out = c.get("stdout") or ""
    if not re.search(r"(memory\.max=\S+|pids\.max=\S+|cpu\.max=\S+)", c_out):
        reasons.append(f"resource_caps: no real cgroup limit read back, got {c_out[:200]!r}")
    return (not reasons), reasons


async def _run_checks(ctx: dict = None) -> list:
    ctx = ctx or {}
    results = []
    emit = ctx.get("emit_terminal_progress")
    emit_status = ctx.get("emit_status")   # the short transient "now doing X" line shown live next to the busy
                                            # indicator (see web.py) -- plain-English per-check narration, found
                                            # missing live 2026-10-30: this used to be covered by the old
                                            # automatic-greeting instructions (removed when the greeting was
                                            # shortened), so a mid-task call had nothing simple in the CHAT pane
                                            # at all, only the technical terminal-pane line below.
    for c in CHECKS:
        if emit_status:
            await emit_status(c["simple"])
        if emit:
            await emit("verify_sandbox_safety", c["progress"])
        raw = _call("POST", "/run", {"kind": "bash", "code": c["cmd"], "name": "", "timeout": 10}, timeout=20)
        results.append({"check": c["key"], "cmd": c["cmd"], "raw": raw})
    if emit_status:
        await emit_status("")   # clears the transient line once all 3 checks are done
    return results


async def verify_sandbox_safety(args: dict, ctx: dict) -> str:
    """Runs 3 REAL checks against the live sandbox container -- not claims, actual commands -- and reports exactly what each
    one shows, plus a real, code-computed pass/fail. Call this ONCE, right after the sandbox is confirmed up (the first
    bash_run/sandbox_app_start of a session), before doing any real work in it, so the operator sees the isolation
    guarantees demonstrated, not just asserted. run_safety_gate() below already runs this same check automatically the
    moment the ephemeral trio is freshly created, and refuses to proceed with the operator's task if it fails -- this
    tool stays separately callable for an explicit, narrated re-check mid-session."""
    results = await _run_checks(ctx)
    passed, reasons = _evaluate(results)
    return json.dumps({
        "ok": True,
        "passed": passed,
        "reasons": reasons,
        "note": (
            "Each check above is a REAL command that ran just now inside THIS session's own sandbox container -- `passed` "
            "and `reasons` are a real, code-computed verdict, not something to re-derive from the raw stdout yourself. "
            "Report `passed` plainly; if it's false, name exactly which check(s) failed and why, from `reasons`, never "
            "soften or omit a failure. The resource_caps check deliberately reads the enforced limits rather than trying "
            "to exhaust them (that would crash the sandbox needed for the rest of this session) -- say that plainly "
            "rather than implying a crash test was run."
        ),
        "results": results,
    })


def format_gate_lines(results: list) -> list:
    """Plain-English, code-computed (never model-guessed) one-liner per check -- the exact same judgment
    _evaluate() makes, in the same shape the old automatic-greeting narration used to show (removed from the
    greeting 2026-10-31, moved here instead, see run_safety_gate()). Shared formatter so the chat-facing note
    and anything else that reports this can never drift from the real pass/fail logic."""
    by_check = {r["check"]: (r.get("raw") or {}) for r in results}
    lines = []
    w = by_check.get("write_outside_sandbox", {})
    w_out = (w.get("stdout") or "") + (w.get("stderr") or "")
    lines.append("Can't write outside the sandbox (blocked: read-only)" if w_out.count("Read-only file system") >= 2
                 else f"Write-outside-sandbox check: unexpected output ({w_out[:120]!r})")
    n = by_check.get("external_network", {})
    n_out = n.get("stdout") or ""
    m = re.search(r"exit_code=(\d+)", n_out)
    lines.append("Can't reach the internet (blocked: no network device)" if m and m.group(1) != "0"
                 else f"External-network check: unexpected output ({n_out[:120]!r})")
    c = by_check.get("resource_caps", {})
    c_out = c.get("stdout") or ""
    caps = ", ".join(re.findall(r"(memory\.max=\S+|pids\.max=\S+|cpu\.max=\S+)", c_out)) or "unavailable"
    lines.append(f"Resource limits enforced: {caps}")
    return lines


def run_safety_gate() -> tuple:
    """The hard gate: runs the exact same 3 checks, right after sandbox_tools._call lazy-starts a fresh trio and
    before the operator's actual task proceeds in it (owner's own instruction, 2026-10-31: the safety check must
    happen after the sandbox trio is created, and only on success does real work start inside it). Deliberately
    plain sync (not async like _run_checks/verify_sandbox_safety above): _call's lazy-start path is itself sync and
    already runs inside an active event loop (called from async tool functions without await, same as every other
    _call use), so an async gate here would need asyncio.run() from inside a running loop -- a guaranteed
    RuntimeError. Returns (passed, reasons_text, lines) -- lines is format_gate_lines(results), for the caller to
    fold into whatever tool result triggered the lazy-start, so the model reports it in its own next chat reply
    (added 2026-10-31: running this silently meant the operator never saw it confirmed in chat at all, even
    though it demonstrably ran and passed)."""
    results = []
    for c in CHECKS:
        raw = _call("POST", "/run", {"kind": "bash", "code": c["cmd"], "name": "", "timeout": 10}, timeout=20)
        results.append({"check": c["key"], "cmd": c["cmd"], "raw": raw})
    passed, reasons = _evaluate(results)
    return passed, "; ".join(reasons), format_gate_lines(results)
