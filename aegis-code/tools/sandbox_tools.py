"""repl_run/bash_run/export_project/repl_list -- the isolated code sandbox fixredteam/fixpentest use to read, write and re-scan the target
source tree. The code never runs in this process: it runs in the `sandbox` container (../../sandbox/), --network none, read-only root,
non-root, no secrets mounted. This talks to it over a Unix socket in a shared volume, same transport a larger assistant's MCP tool would use.

Deliberately simpler than the full-featured version's version: no MCP server layer (fastmcp is not a dependency at all here -- this calls the socket
directly), and no platform-tools callback bridge (the sandbox has no need to call back into Aegis itself; fixing a real repo's source
needs file read/write and shell commands, not web_search from inside the sandbox). export_project writes into /aegis_out on the host."""
import base64
import http.client
import json
import os
import re
import socket

from . import trio_client
from .narration import narrate

_SOCK = os.getenv("AEGIS_SANDBOX_SOCK", "/sock/exec.sock")


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("sandbox", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _raw_call(method: str, path: str, body: dict, timeout: float):
    conn = _UnixConn(_SOCK, timeout)
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = json.loads(resp.read() or b"{}")
    conn.close()
    return data


def _call(method: str, path: str, body: dict = None, timeout: float = 60.0) -> dict:
    try:
        result = _raw_call(method, path, body, timeout)
        trio_client.touch()
        return result
    except Exception:                                                              # noqa: BLE001
        # Never trust os.path.exists(_SOCK) alone: the trio is ephemeral but aegis-sock is a persistent named
        # volume, so a stale socket FILE from the last, now-destroyed sandbox container still exists on disk --
        # os.path.exists would wrongly report "up" with nothing listening. A real connect failure (refused /
        # no such file) is the only reliable "the trio isn't here" signal, so that's what triggers the lazy
        # start. Retry exactly once -- a genuinely broken trio must still surface as a real error, not hang.
        started = trio_client.start_trio()
        if not started.get("ok"):
            return {"error": f"Could not start the code sandbox: {started.get('error', 'unknown error')}"}
        try:
            return _raw_call(method, path, body, timeout)
        except Exception as e:                                                     # noqa: BLE001
            return {"error": f"The code sandbox did not answer after starting ({type(e).__name__})."}


async def repl_run(args: dict, ctx: dict) -> str:
    """Runs Python 3.12 in the isolated sandbox and returns what it printed. See bash_run for the shell equivalent."""
    code, name, timeout = str(args.get("code") or ""), str(args.get("name") or ""), max(1, min(int(args.get("timeout") or 20), 45))
    return json.dumps(_call("POST", "/run", {"kind": "python", "code": code, "name": name, "timeout": timeout}, timeout=timeout + 15))


async def bash_run(args: dict, ctx: dict) -> str:
    """Runs a bash command in the isolated sandbox (python, uv, coreutils, grep, sed, awk, jq, git, curl). Working directory and exported
    shell variables carry over between calls, like a real terminal. This is the tool fixredteam/fixpentest use to read and edit a target's
    working copy (/self_target/self for "self", /dynamic_target/<name> for a cloned repo) -- the same directory redteam re-scans."""
    command, timeout = str(args.get("command") or ""), max(1, min(int(args.get("timeout") or 20), 45))
    return json.dumps(_call("POST", "/run", {"kind": "bash", "code": command, "name": "", "timeout": timeout}, timeout=timeout + 15))


async def cleanup_sandbox_scratch(args: dict, ctx: dict) -> str:
    """Deletes this sandbox's accumulated scratch: /REPL/work, /REPL/tmp, every stale /dynamic_target/<name> (nothing reuses one across a
    browser session), and /aegis_out beyond the newest 20 exports. Called deterministically in code at the start of every new session (see
    web.py), not something the model needs to call itself -- exposed here mainly so core.py's startup path and a manual re-run share one
    implementation. Exempt from the /REPL size cap: this is the one operation that must still work once /REPL is already full."""
    return json.dumps(_call("POST", "/cleanup", {}, timeout=30.0))


# Runs INSIDE the sandbox (python kind): builds CHANGES.txt as a REAL before/after diff (pristine copy vs the fixed working copy) and puts it into the zip.
# The sandbox's own export step writes a CHANGES.txt too, but when the working copy has no usable git history it falls back to "files modified in the last
# hour", which lists EVERY file of a freshly copied project and shows no diff at all (seen in a real run: LICENSE, .gitignore and 40 untouched files "modified").
_CHANGES_SCRIPT = r"""
import os, sys, difflib, subprocess
PRISTINE, WORK, ZIP, PROJECT = sys.argv[1:5]
SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.mypy_cache'}
def listing(root):
    out = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f.endswith('.pyc') or f == 'CHANGES.txt':
                continue
            full = os.path.join(d, f)
            out[os.path.relpath(full, root)] = full
    return out
def read(path):
    if path is None:
        return []
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read().splitlines(keepends=True)
    except (UnicodeDecodeError, OSError):
        return None
a, b = listing(PRISTINE), listing(WORK)
rows, chunks, plus_all, minus_all, binary = [], [], 0, 0, []
for rel in sorted(set(a) | set(b)):
    old, new = read(a.get(rel)), read(b.get(rel))
    if old is None or new is None:
        if (a.get(rel) and b.get(rel) and open(a[rel], 'rb').read() != open(b[rel], 'rb').read()) or (rel not in a or rel not in b):
            binary.append(rel)
        continue
    if old == new:
        continue
    kind = 'added' if rel not in a else ('removed' if rel not in b else 'modified')
    diff = list(difflib.unified_diff(old, new, fromfile='a/' + rel, tofile='b/' + rel))
    plus = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    minus = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    plus_all += plus; minus_all += minus
    rows.append('  - %s  (%s, +%d / -%d)' % (rel, kind, plus, minus))
    chunks.append(''.join(l if l.endswith('\n') else l + '\n\\ No newline at end of file\n' for l in diff))
head = ['# Changes Made to This Project', '']
if rows or binary:
    head += ['%d file(s) changed, +%d / -%d lines (compared with the untouched clone):' % (len(rows) + len(binary), plus_all, minus_all), ''] + rows
    head += ['  - %s  (binary or non-text file changed)' % r for r in binary]
    head += ['', '=' * 80, '', 'Unified diff of every changed file (a/ = before, b/ = after):', '']
else:
    head += ['No file differs from the untouched clone.', '']
body = '\n'.join(head) + '\n' + ''.join(chunks)
LIMIT = 600000
if len(body) > LIMIT:
    body = body[:LIMIT] + '\n... (diff truncated at %d characters; the full fixed tree is in this zip)\n' % LIMIT
with open(os.path.join(WORK, 'CHANGES.txt'), 'w', encoding='utf-8') as fh:
    fh.write(body)
r = subprocess.run(['zip', '-q', ZIP, PROJECT + '/CHANGES.txt'], cwd=os.path.dirname(WORK), capture_output=True, text=True, timeout=30)
print('CHANGES_OK files=%d plus=%d minus=%d zip_rc=%d %s' % (len(rows) + len(binary), plus_all, minus_all, r.returncode, (r.stderr or '')[:100]))
"""


def _real_changes(project: str, zip_path: str) -> str:
    """Rewrites CHANGES.txt inside the already-made zip with the real diff. Returns the script's one-line result ('' if it could not run)."""
    pristine = "/self_pristine" if project == "self" else f"/dynamic_pristine/{project}"
    work = f"/REPL/work/{project}"
    code = f"import sys\nsys.argv = ['changes', {pristine!r}, {work!r}, {zip_path!r}, {project!r}]\n" + _CHANGES_SCRIPT
    out = _call("POST", "/run", {"kind": "python", "code": code, "name": "", "timeout": 40}, timeout=55)
    text = str(out.get("stdout") or "")
    return text.strip() if "CHANGES_OK" in text else ""


async def export_project(args: dict, ctx: dict) -> str:
    """Zips a finished project folder from /REPL/work into /aegis_out on the host -- the only way anything leaves the sandbox."""
    project = str(args.get("project") or "")
    await narrate(ctx, "Now creating the diff file and storing CHANGES.txt.")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,100}", project):
        # The fixed working copy is copied into /REPL/work by code (a fixed command that only differs by name): leaving it to the model cost a whole
        # round (33 s in a real run) right before every export. A name that is not a working copy (already placed in /REPL/work by hand) is left as it is.
        src = "/self_target/self" if project == "self" else f"/dynamic_target/{project}"
        _call("POST", "/run", {"kind": "bash", "name": "", "timeout": 30,
                               "code": f"if [ -d {src} ]; then mkdir -p /REPL/work && rm -rf /REPL/work/{project} && cp -r {src} /REPL/work/{project}; fi"}, timeout=45)
    result = _call("POST", "/export", {"project": project}, timeout=35.0)
    if result.get("ok") and result.get("path") and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", project):
        line = _real_changes(project, str(result["path"]))
        if line:
            result["changes_file"] = "CHANGES.txt"
            result["note"] = f"Created {result.get('filename')} containing CHANGES.txt: a real unified diff of every changed file against the untouched clone ({line.replace('CHANGES_OK ', '')})."
        m = re.search(r"files=(\d+) plus=(\d+) minus=(\d+)", line or "")
        # remembered for the closing message, which states where the zip is (see summary.deliverables_block) -- "path" (added 2026-10-30)
        # additionally lets create_word_document append the report straight into THIS zip once it's built (doc_tools._deliver), so the
        # report survives even when the live session's own browser-delivered download was never saved anywhere on disk.
        ctx["last_export"] = {"filename": str(result.get("filename") or ""), "path": str(result.get("path") or ""),
                              "turn": ctx.get("turn_no"), "has_changes": bool(line),
                              "files": int(m.group(1)) if m else None, "plus": int(m.group(2)) if m else None, "minus": int(m.group(3)) if m else None}
        await narrate(ctx, f"Created {result.get('filename')}, containing the fixed project and CHANGES.txt. Copied to {result['path']} on the host.")
    elif result.get("ok"):
        await narrate(ctx, f"Created {result.get('filename', 'the export zip')}, copied to {result.get('path', 'the host')}.")
    else:
        await narrate(ctx, f"Export failed: {result.get('error', 'unknown error')}.")
    return json.dumps(result)


async def append_doc_to_export(zip_path: str, doc_filename: str, data_base64: str) -> dict:
    """Appends an already-built .docx (as base64) into an EXISTING export zip sitting in /aegis_out (added 2026-10-30) -- called from
    doc_tools._deliver right after a report is built, using ctx["last_export"]["path"] (export_project's own real zip path). This is the
    ONLY way the report survives independent of whatever the live session's browser-side download did with it: a driver script that never
    saves the websocket's data_base64 payload (a real gap hit live 2026-10-30 -- a finished run's report was only ever in the browser's
    download card, never on any disk) still gets the report, inside the SAME zip CHANGES.txt already lives in. Backend-web has no mount
    for /aegis_out at all, so this HAS to run inside the sandbox container, over the same exec socket bash_run/export_project already use,
    not as a plain Python zipfile.write in this process. Best-effort: a failure here (e.g. the zip was already cleaned up) is reported but
    never blocks the real, already-delivered emit_document from reaching the browser."""
    if not zip_path or not re.fullmatch(r"[A-Za-z0-9._\-/]{1,300}", zip_path) or not zip_path.startswith("/aegis_out/"):
        return {"ok": False, "error": "no valid export zip path to append into"}
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", doc_filename)[:120] or "report.docx"
    code = (
        "import base64, zipfile\n"
        f"data = base64.b64decode({data_base64!r})\n"
        f"with zipfile.ZipFile({zip_path!r}, 'a', zipfile.ZIP_DEFLATED) as z:\n"
        f"    z.writestr({safe_name!r}, data)\n"
        "print('APPEND_OK')\n"
    )
    out = _call("POST", "/run", {"kind": "python", "code": code, "name": "", "timeout": 20}, timeout=35)
    if "APPEND_OK" in json.dumps(out):
        return {"ok": True, "zip_path": zip_path, "doc_filename": safe_name}
    return {"ok": False, "error": str(out)[:300]}


async def repl_list(args: dict, ctx: dict) -> str:
    """Lists the scripts already saved in /REPL. Check this before writing new code."""
    return json.dumps(_call("GET", "/list", timeout=15))


async def check_sandbox_capacity(args: dict, ctx: dict) -> str:
    """Reports the sandbox's current scratch quota (repl_cap_mb), how much of it is already used (repl_used_scratch_mb -- real scratch only,
    reusable pip/uv caches never count against this), and how much real free space the underlying volume has (volume_free_mb). Call this
    BEFORE cloning any repo whose size you are not confident fits -- compare the repo's size (from redteam_check_repo_size) against
    repl_cap_mb - repl_used_scratch_mb. If the repo would not fit, tell the user the exact numbers and ask whether to raise the quota (via
    increase_sandbox_capacity) before cloning; never raise it yourself without the user saying yes."""
    return json.dumps(_call("GET", "/health", timeout=15))


async def increase_sandbox_capacity(args: dict, ctx: dict) -> str:
    """Raises the sandbox's /REPL scratch quota to the given size in MB, persisted so it survives a container restart/recreate. ONLY call this
    after the operator has explicitly agreed, in this conversation, to raise the limit for a specific oversized repo you warned them about via
    check_sandbox_capacity/redteam_check_repo_size -- never on your own initiative, and never silently. Refuses (with a real error, never a
    fabricated success) if the requested size would leave less than 10% of the volume's real free space as headroom."""
    try:
        mb = int(args.get("mb") or 0)
    except (TypeError, ValueError):
        return json.dumps({"ok": False, "error": "mb must be an integer number of megabytes"})
    if mb <= 0:
        return json.dumps({"ok": False, "error": "mb must be a positive integer"})
    return json.dumps(_call("POST", "/set_cap", {"mb": mb}, timeout=15))


_EDIT_ROOTS = ("/dynamic_target/", "/self_target/", "/REPL/work/")


def _edit_one(path: str, old: str, new: str, every: bool) -> dict:
    if not path.startswith(_EDIT_ROOTS) or ".." in path.split("/"):
        return {"ok": False, "path": path, "error": f"edit_file only works inside a working copy ({', '.join(_EDIT_ROOTS)}...): {path!r} is not."}
    if not old:
        return {"ok": False, "path": path, "error": "old_text is empty: give the exact text to replace (copy it from the file)."}
    b = lambda t: base64.b64encode(t.encode("utf-8")).decode("ascii")      # noqa: E731
    code = (
        "import base64, pathlib\n"
        f"p = pathlib.Path(base64.b64decode('{b(path)}').decode())\n"
        f"old = base64.b64decode('{b(old)}').decode()\n"
        f"new = base64.b64decode('{b(new)}').decode()\n"
        f"every = {bool(every)}\n"
        "if not p.is_file():\n    raise SystemExit('EDIT_ERROR: no such file: ' + str(p))\n"
        "text = p.read_text(encoding='utf-8')\n"
        "n = text.count(old)\n"
        "if n == 0:\n    raise SystemExit('EDIT_ERROR: old_text was not found in ' + str(p) + ' (whitespace must match exactly; re-read the lines first)')\n"
        "if n > 1 and not every:\n    raise SystemExit('EDIT_ERROR: old_text matches ' + str(n) + ' places in ' + str(p) + '; include more surrounding text, or pass replace_all')\n"
        "i = text.index(old)\n"
        "p.write_text(text.replace(old, new) if every else text.replace(old, new, 1), encoding='utf-8')\n"
        "line = text.count(chr(10), 0, i) + 1\n"
        "print('EDIT_OK replaced', n if every else 1, 'occurrence(s) in', p, 'starting at line', line)\n"
    )
    out = _call("POST", "/run", {"kind": "python", "code": code, "name": "", "timeout": 20}, timeout=35)
    if "EDIT_OK" in json.dumps(out):
        return {"ok": True, "path": path, "result": str(out.get("stdout") or out.get("output") or "").strip() or "edit applied"}
    return {"ok": False, "path": path, "error": next((str(v).strip() for v in out.values() if "EDIT_ERROR" in str(v)), None) or str(out)[:300]}


async def edit_file(args: dict, ctx: dict) -> str:
    """Replaces text in files inside a working copy, with no shell quoting involved: path, old_text and new_text travel base64-encoded to a fixed
    script in the sandbox. This replaces the heredoc-built python patch scripts she used to write, whose quote escaping broke (a real run lost three
    rounds, about 4 minutes, to one mangled patch). Exact match only: 0 matches or more than one (without replace_all) is an error that says so.
    One call can carry several edits (`edits`: a list of {path, old_text, new_text, replace_all}), applied in order; the local model sends one tool call
    per round, so batching them saves a whole round per extra edit. An edit that fails does not stop the ones after it, and each result is reported."""
    edits = args.get("edits")
    if not isinstance(edits, list) or not edits:
        edits = [{"path": args.get("path"), "old_text": args.get("old_text"), "new_text": args.get("new_text"), "replace_all": args.get("replace_all")}]
    if not ctx.get("_fix_narrated_this_turn"):
        # Narrated once per turn, not once per edit_file call -- a real fix run calls this many times in a row for one scan's worth of
        # findings, and repeating "now fixing" before every single one would flood the terminal pane with noise instead of signal.
        ctx["_fix_narrated_this_turn"] = True
        await narrate(ctx, "Now fixing the results obtained from the scan.")
    results = []
    for i, e in enumerate(edits[:20], start=1):
        e = e if isinstance(e, dict) else {}
        # a top-level path/old_text/new_text sitting ALONGSIDE an edits list is treated as that list's own shared default (a real run passed
        # path at the top level, meaning it for every edit, and got 3 silent "path is empty" failures until it retried with path repeated per item)
        path = e.get("path") if e.get("path") is not None else args.get("path")
        old_t = e.get("old_text") if e.get("old_text") is not None else args.get("old_text")
        new = e.get("new_text") if e.get("new_text") is not None else args.get("new_text")
        replace_all = e.get("replace_all") if e.get("replace_all") is not None else args.get("replace_all")
        r = _edit_one(str(path or ""), str(old_t or ""), str(new) if new is not None else "", bool(replace_all))
        r["n"] = i
        results.append(r)
    if len(results) == 1 and "edits" not in args:
        r = results[0]
        return json.dumps({"ok": r["ok"], **({"result": r["result"]} if r["ok"] else {"error": r["error"]})})
    return json.dumps({"ok": all(r["ok"] for r in results), "applied": sum(r["ok"] for r in results), "failed": sum(not r["ok"] for r in results), "results": results})
