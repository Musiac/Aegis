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

from .sandbox_tools import _call

CHECKS = [
    {
        "key": "write_outside_sandbox",
        "progress": "now running: trying to write outside the sandbox's writable paths (a read-only mount and the read-only root filesystem)...",
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
        "cmd": "curl -s -m 3 -o /dev/null -w 'http_code=%{http_code} exit_code=%{exitcode}\\n' https://www.ibm.com 2>&1; echo CHECK_DONE",
    },
    {
        "key": "resource_caps",
        "progress": "now running: reading the real memory/process/CPU caps the Docker host enforces on this container...",
        "cmd": (
            "echo \"memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)\"; "
            "echo \"pids.max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)\"; "
            "echo \"cpu.max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)\"; "
            "echo CHECK_DONE"
        ),
    },
]


async def verify_sandbox_safety(args: dict, ctx: dict) -> str:
    """Runs 3 REAL checks against the live sandbox container -- not claims, actual commands -- and reports exactly what each
    one shows. Call this ONCE, right after the sandbox is confirmed up (the first bash_run/sandbox_app_start of a session),
    before doing any real work in it, so the operator sees the isolation guarantees demonstrated, not just asserted."""
    results = []
    emit = ctx.get("emit_terminal_progress")
    for c in CHECKS:
        if emit:
            await emit("verify_sandbox_safety", c["progress"])
        raw = _call("POST", "/run", {"kind": "bash", "code": c["cmd"], "name": "", "timeout": 10}, timeout=20)
        results.append({"check": c["key"], "cmd": c["cmd"], "raw": raw})
    return json.dumps({
        "ok": True,
        "note": (
            "Each check above is a REAL command that ran just now inside THIS session's own sandbox container -- report "
            "exactly what its stdout/stderr/exit_code show, never invent or assume a result. The resource_caps check "
            "deliberately reads the enforced limits rather than trying to exhaust them (that would crash the sandbox "
            "needed for the rest of this session) -- say that plainly rather than implying a crash test was run."
        ),
        "results": results,
    })
