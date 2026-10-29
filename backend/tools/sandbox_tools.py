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

_SOCK = os.getenv("AEGIS_SANDBOX_SOCK", "/sock/exec.sock")


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("sandbox", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _call(method: str, path: str, body: dict = None, timeout: float = 60.0) -> dict:
    if not os.path.exists(_SOCK):
        return {"error": "The code sandbox is not available (no sandbox socket)."}
    try:
        conn = _UnixConn(_SOCK, timeout)
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return data
    except Exception as e:                                                        # noqa: BLE001
        return {"error": f"The code sandbox did not answer ({type(e).__name__})."}


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
        # remembered for the closing message, which states where the zip is (see summary.deliverables_block)
        ctx["last_export"] = {"filename": str(result.get("filename") or ""), "turn": ctx.get("turn_no"), "has_changes": bool(line),
                              "files": int(m.group(1)) if m else None, "plus": int(m.group(2)) if m else None, "minus": int(m.group(3)) if m else None}
    return json.dumps(result)


async def repl_list(args: dict, ctx: dict) -> str:
    """Lists the scripts already saved in /REPL. Check this before writing new code."""
    return json.dumps(_call("GET", "/list", timeout=15))


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
