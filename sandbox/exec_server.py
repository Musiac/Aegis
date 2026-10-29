"""The sandbox's exec server: a tiny HTTP server on a UNIX SOCKET (/sock/exec.sock) -- the container has no network device, so the socket (in a volume
that only mcp-ui also mounts) is the only way in. The MCP tools repl_run / repl_list / bash_run call it.

  GET  /health
  GET  /list                      saved scripts in /REPL with their first comment line
  GET  /read?name=<file>          one saved script
  POST /run {"kind": "python"|"bash", "code": "...", "name": "", "timeout": 20}
        python + name: the code is saved as /REPL/<name>.py (empty code = run the saved file); python without a name runs from a scratch file; bash runs the command.

A python run gets its own scratch directory (deleted afterwards) as the working directory, so user data does not pile up or leak between runs. A bash run is
different (2026-10-20): its WORKING DIRECTORY persists across calls -- a `cd` in one bash_run is still in effect for the next one -- by starting each run in
the directory recorded from the end of the last one (WORK_DIR by default) and recording the new one afterward (CWD_STATE). This is filesystem state only,
never a live process: each run still gets its own fresh process group, killed in full on timeout exactly as before, so nothing can be left running in the
background between calls. /REPL/work is the persistent playground (reset it yourself with `rm -rf /REPL/work/* /REPL/work/.[!.]* 2>/dev/null` for a fresh
start); /REPL's top level still holds only reusable scripts and installed packages (/REPL/.pkgs), untouched by this. Limits: wall-clock timeout (whole
process group killed), CPU seconds, file size, open files, output size, at most MAX_CONCURRENT runs at once, /REPL size cap.

/aegis_out (added 2026-10-20) is a SEPARATE real folder on the DGX host, bind-mounted read-write, for exporting finished work out of the sandbox
where the owner can actually see and back it up: zip a project there (zip/unzip are installed) as a durable copy that survives even a full /REPL volume
loss. It is the one path this container can reach that is not inside its own private volumes; nothing else about the container's isolation changes."""
import json
import os
import re
import resource
import secrets
import shlex
import shutil
import signal
import socketserver
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

SOCK = os.getenv("REPL_EXEC_SOCK", "/sock/exec.sock")
REPL_DIR = "/REPL"
WORK_DIR = os.path.join(REPL_DIR, "work")          # the persistent bash playground -- never deleted between runs, only by the user's own `rm`
CWD_STATE = os.path.join(REPL_DIR, ".cwd")          # the last working directory a bash run ended in; read at the start of the next one
ENV_STATE = os.path.join(REPL_DIR, ".env_state")    # exported shell variables from the end of the last bash run (export -p); sourced at the start of the next one
DEFAULT_TIMEOUT, MAX_TIMEOUT = 20, 45
MAX_OUTPUT = 12000                 # characters kept per stream
MAX_CODE = 200_000
MAX_CONCURRENT = int(os.getenv("REPL_MAX_CONCURRENT", "4"))
REPL_CAP_BYTES = int(os.getenv("REPL_DIR_CAP_MB", "400")) * 1024 * 1024
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _load_cwd() -> str:
    """The directory the last bash run ended in, or WORK_DIR the first time or if that directory no longer exists (e.g. the user rm -rf'd it)."""
    try:
        with open(CWD_STATE, encoding="utf-8") as f:
            saved = f.read().strip()
    except OSError:
        saved = ""
    return saved if saved and os.path.isdir(saved) else WORK_DIR


def _save_cwd(path: str) -> None:
    """Atomic write (same directory, then rename) so a crash mid-write never corrupts the state file."""
    try:
        tmp = CWD_STATE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(path)
        os.replace(tmp, CWD_STATE)
    except OSError:
        pass

# HOME and UV_CACHE_DIR are deliberately FIXED, shared paths (not per-run): UV_CACHE_DIR exists to cache installed packages ACROSS runs, which a randomized path would defeat.
# This is the sandbox's own private tmpfs, --network none, no other user or process ever shares it, so the usual "predictable /tmp path" attack does not apply here.
USER_ENV = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": "/REPL/.pkgs:/opt/repl", "HOME": "/tmp/home",  # nosec B108
            "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1",
            "UV_CACHE_DIR": "/tmp/uv-cache",  # nosec B108
            "UV_PYTHON_DOWNLOADS": "never", "UV_PYTHON": "/opt/base-venv/bin/python", "MPLBACKEND": "Agg",
            "HTTP_PROXY": "http://127.0.0.1:3128", "HTTPS_PROXY": "http://127.0.0.1:3128", "http_proxy": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128"}


def _clip(b: bytes) -> tuple:
    s = b.decode("utf-8", "replace")
    if len(s) <= MAX_OUTPUT:
        return s, False
    half = MAX_OUTPUT // 2
    return s[:half] + f"\n...[{len(s) - MAX_OUTPUT} characters omitted]...\n" + s[-half:], True


def _dir_bytes(path: str) -> int:
    total = 0
    for root, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _deny_setsid_seccomp():
    """Loads a seccomp filter in the CURRENT (child) process that makes setsid()/setpgid() fail with EPERM instead of succeeding -- a run could
    otherwise call `env -u REPL_RUN_TAG setsid ...` to clear its own run tag and leave the run's process group/session; once the shell that
    started it exited, the detached process would be reparented to PID 1 and the ancestry-based cleanup (_descendant_pids(), below) could no
    longer trace it, so it would survive past the run's timeout and could keep consuming the sandbox's process-count cap. no_new_privs is set
    first so nothing executed after this point can regain the ability to install a different (looser) filter. Raises on any failure so the
    caller (apply(), below) fails the run closed rather than ever executing untrusted code without this restriction in place."""
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    PR_SET_NO_NEW_PRIVS = 38
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    import pyseccomp as seccomp
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    f.add_rule(seccomp.ERRNO(1), "setsid")      # errno 1 = EPERM
    f.add_rule(seccomp.ERRNO(1), "setpgid")
    f.load()


def _limits(cpu_s: int):
    def apply():
        os.setsid()
        _deny_setsid_seccomp()
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_FSIZE, (200 * 1024 * 1024, 200 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _descendant_pids(root_pid: int) -> list:
    """Every live PID whose ancestry traces back to root_pid, found by reading /proc/*/stat -- NOT by process group, since a run's own code can
    call setsid() to move a child into a new session and escape os.killpg() entirely."""
    children: dict = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8") as f:
                stat = f.read()
            ppid = int(stat.rsplit(")", 1)[1].split()[1])      # field 2 (comm) may itself contain ")", so split after the LAST one
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(entry))
    out, stack = [], [root_pid]
    while stack:
        pid = stack.pop()
        for child in children.get(pid, []):
            out.append(child)
            stack.append(child)
    return out


def _pids_with_env_tag(tag: str) -> list:
    """Every live PID whose environment carries REPL_RUN_TAG=<tag> -- a real environment variable is inherited by every descendant at fork/exec
    and survives setsid() and reparenting to init untouched (unlike ppid ancestry, which breaks the instant a process's immediate parent dies
    and it is reparented away). This is the authoritative backstop for _kill_tree below: ppid-walking can still miss a process that was ALREADY
    reparented before cleanup ever ran (proc.communicate() returning normally means proc had already exited, so any start_new_session=True
    grandchild it spawned was reparented to init before run_command got control back at all -- no reordering of the kill/scan steps can beat a
    race that already finished before cleanup started)."""
    out = []
    needle = f"REPL_RUN_TAG={tag}\0".encode()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/environ", "rb") as f:
                if needle in f.read():
                    out.append(int(entry))
        except OSError:
            continue
    return out


def _kill_tree(root_pid: int, run_tag: str = "") -> None:
    victims = set(_descendant_pids(root_pid))          # walk the tree first, while every real parent is still alive (helps the TIMEOUT path)
    if run_tag:
        victims.update(_pids_with_env_tag(run_tag))    # the tag-based backstop: finds anything already reparented to init by the time we got here
    try:
        os.killpg(root_pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def run_command(argv: list, cwd: str, timeout: int, tool_token: str = "") -> dict:
    t0 = time.monotonic()
    run_tag = secrets.token_hex(8)     # tags every process this run spawns (inherited by descendants, survives setsid/reparenting) so cleanup
                                        # can find a grandchild that already got reparented to init before cleanup even started -- see _kill_tree.
    env = dict(USER_ENV, REPL_TOOL_TOKEN=tool_token, REPL_RUN_TAG=run_tag) if tool_token else {**USER_ENV, "REPL_RUN_TAG": run_tag}
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            preexec_fn=_limits(timeout + 5))
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc.pid, run_tag)
        try:
            out, err = proc.communicate(timeout=5)             # bounded: an escaped grandchild that still holds the pipes must never block the handler
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
    finally:
        _kill_tree(proc.pid, run_tag)                          # stragglers started in the background, including anything already reparented to init
    so, t1 = _clip(out)
    se, t2 = _clip(err)
    return {"exit_code": proc.returncode, "stdout": so, "stderr": se, "timed_out": timed_out, "truncated": t1 or t2, "seconds": round(time.monotonic() - t0, 2)}


def do_run(req: dict) -> tuple:
    kind = str(req.get("kind", "python"))
    code = str(req.get("code", ""))
    name = str(req.get("name", "")).strip()
    tool_token = str(req.get("tool_token", ""))[:100]
    timeout = max(1, min(int(req.get("timeout") or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    if kind not in ("python", "bash") or len(code) > MAX_CODE:
        return 400, {"error": "kind must be python or bash, and the code must be under 200 KB"}
    if not _slots.acquire(blocking=False):
        return 429, {"error": "The sandbox is busy (4 runs at once). Try again in a few seconds."}
    scratch = tempfile.mkdtemp(prefix="run-") if kind == "python" else None   # python: a throwaway temp dir, deleted after, every time (stateless by design)
    try:
        if kind == "python":
            if name:
                base = name[:-3] if name.endswith(".py") else name
                if not _NAME.match(base):
                    return 400, {"error": "name may use letters, digits, dot, dash and underscore only"}
                path = os.path.join(REPL_DIR, base + ".py")
                if code:
                    if _dir_bytes(REPL_DIR) > REPL_CAP_BYTES:
                        return 507, {"error": "/REPL is full; delete files with bash (rm) first"}
                    with open(path, "w") as f:
                        f.write(code)
                elif not os.path.exists(path):
                    return 404, {"error": f"{base}.py does not exist in /REPL"}
            else:
                if not code:
                    return 400, {"error": "code is empty"}
                path = os.path.join(scratch, "main.py")
                with open(path, "w") as f:
                    f.write(code)
            res = run_command(["/opt/base-venv/bin/python", path], scratch, timeout, tool_token)
            if name:
                res["file"] = os.path.basename(path)
        else:
            if not code.strip():
                return 400, {"error": "command is empty"}
            if _dir_bytes(REPL_DIR) > REPL_CAP_BYTES:
                return 507, {"error": "/REPL is full; delete files with bash (rm) first"}
            start_cwd = _load_cwd()
            tag = f"{os.getpid()}.{threading.get_ident()}"
            cwd_tmp, env_tmp = os.path.join(REPL_DIR, f".cwd.{tag}.tmp"), os.path.join(REPL_DIR, f".env.{tag}.tmp")
            # A real exported variable set in one run (an API key, a PATH addition, a venv activation) is still set in the next one, the same way a real
            # terminal works: sourced here BEFORE the user's command, captured AFTER it. The source line is silent (2>/dev/null) so a first-ever or
            # hand-emptied state file never shows an error the user did not cause. $? is captured IMMEDIATELY after the user's own code, so the exit
            # code this returns is always theirs, never the bookkeeping's.
            # REPL_TOOL_TOKEN is excluded from the captured/sourced state on purpose -- it scopes which platform tools THIS specific call may use and must
            # never leak forward into a later call that was given a different (or no) token. REPL_RUN_TAG is excluded the same way: sourcing an OLD
            # tag here would overwrite the current call's fresh one in the wrapped script's own shell, so a child it spawns would carry the wrong
            # tag and _kill_tree's tag-based cleanup (see run_command) would never find it.
            wrapped = (f"[ -f {shlex.quote(ENV_STATE)} ] && . {shlex.quote(ENV_STATE)} 2>/dev/null\n"
                       f"{code}\n__rc=$?\npwd > {shlex.quote(cwd_tmp)} 2>/dev/null\n"
                       f"export -p | grep -vE '^declare -x (REPL_TOOL_TOKEN|REPL_RUN_TAG)=' > {shlex.quote(env_tmp)} 2>/dev/null\nexit $__rc")
            res = run_command(["/bin/bash", "-c", wrapped], start_cwd, timeout, tool_token)
            try:
                with open(cwd_tmp, encoding="utf-8") as f:
                    ended_at = f.read().strip()
                os.remove(cwd_tmp)
            except OSError:
                ended_at = ""                           # timed out / killed before reaching the pwd line: stay where this run started, nothing lost
            _save_cwd(ended_at if ended_at and os.path.isdir(ended_at) else start_cwd)
            if os.path.exists(env_tmp):
                os.replace(env_tmp, ENV_STATE)          # reached the export -p line (the wrapper's last one): a real, complete new env state
        return 200, res
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
        _slots.release()


UPDATABLE_DIR = "/aegis_out"
_ZIP_EXCLUDE = ["*/__pycache__/*", "*.pyc", "*/.pytest_cache/*", "*/.git/*"]


def do_export(req: dict) -> tuple:
    """Zips a project under /REPL/work straight to /aegis_out -- a dedicated endpoint so the destination and naming are never something the
    model has to get right in a hand-written shell command (2026-10-20: a real run zipped to a path INSIDE the sandbox and then tried to hand the
    file over as base64 text, which delivers nothing the owner can actually open). Before zipping, creates CHANGES.txt showing all file modifications."""
    project = str(req.get("project", "")).strip()
    try:
        entries = sorted(n for n in os.listdir(WORK_DIR) if not n.startswith(".") and os.path.isdir(os.path.join(WORK_DIR, n)))
    except OSError:
        entries = []
    if not project:
        if len(entries) == 1:
            project = entries[0]
        else:
            return 400, {"error": "Which project? Pass its folder name.", "projects_in_work": entries}
    if not _NAME.match(project) or project not in entries:
        return 404, {"error": f"No folder named {project!r} directly under /REPL/work.", "projects_in_work": entries}
    if not os.path.isdir(UPDATABLE_DIR):
        return 500, {"error": "/aegis_out is not mounted on this host -- nothing was zipped."}

    # Create CHANGES.txt with before/after diff of all modified files (2026-10-24)
    project_path = os.path.join(WORK_DIR, project)
    changes_file = os.path.join(project_path, "CHANGES.txt")
    changes_created = False
    try:
        # Try git diff first if it's a git repo
        git_dir = os.path.join(project_path, ".git")
        if os.path.isdir(git_dir):
            p = subprocess.run(["git", "diff", "HEAD"], cwd=project_path, capture_output=True, text=True, timeout=10)
            if p.returncode == 0 and p.stdout.strip():
                with open(changes_file, "w") as f:
                    f.write("# Changes Made to This Project\n\n")
                    f.write("This file shows the before/after diff of all files modified during the scan and fix cycle.\n\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(p.stdout)
                changes_created = True
        # If no git or no diff, create a simple file listing
        if not changes_created:
            # Find recently modified files (modified in last hour as a heuristic)
            modified_files = []
            now = time.time()
            for root, dirs, files in os.walk(project_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        if now - os.path.getmtime(fpath) < 3600 and fname != "CHANGES.txt":  # modified in last hour
                            rel_path = os.path.relpath(fpath, project_path)
                            modified_files.append(rel_path)
                    except OSError:
                        pass
            if modified_files:
                with open(changes_file, "w") as f:
                    f.write("# Changes Made to This Project\n\n")
                    f.write("The following files were modified during the scan and fix cycle:\n\n")
                    for fpath in sorted(modified_files):
                        f.write(f"  - {fpath}\n")
                changes_created = True
    except Exception:                                                                   # noqa: BLE001
        pass  # If diff creation fails, just continue without it

    dest_name = f"{project}_{time.strftime('%Y-%m-%d-%H-%M-%S')}.zip"
    dest = os.path.join(UPDATABLE_DIR, dest_name)
    exclude_args = []
    for pat in _ZIP_EXCLUDE:
        exclude_args += ["-x", pat]
    try:
        # -y: store symlinks as symlinks, never dereference them into the zip (2026-10-27 hardening --
        # a planted /etc/passwd symlink was previously exported as real file content).
        p = subprocess.run(["zip", "-r", "-q", "-y", dest, project] + exclude_args, cwd=WORK_DIR, capture_output=True, text=True, timeout=30)
    except Exception as e:                                                             # noqa: BLE001
        return 500, {"error": f"{type(e).__name__}: {e}"}
    if p.returncode != 0 or not os.path.isfile(dest):
        return 500, {"error": (p.stderr or p.stdout or "zip failed with no output")[:1000]}

    result = {"ok": True, "project": project, "filename": dest_name, "path": dest, "size_bytes": os.path.getsize(dest)}
    if changes_created:
        result["changes_file"] = "CHANGES.txt"
        result["note"] = f"Created {dest_name} with CHANGES.txt showing before/after diff of all modified files."
    return 200, result


def first_comment(path: str) -> str:
    try:
        with open(path, errors="replace") as f:
            for line in f.read(2000).splitlines():
                s = line.strip().strip('"\'').lstrip("#").strip()
                if s and not s.startswith("!/"):
                    return s[:120]
    except OSError:
        pass
    return ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def address_string(self):
        return "uds"

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"ok": True, "python": os.popen("/opt/base-venv/bin/python -V").read().strip(), "slots": MAX_CONCURRENT})
        if u.path == "/list":
            files = []
            for n in sorted(os.listdir(REPL_DIR)):
                p = os.path.join(REPL_DIR, n)
                if os.path.isfile(p) and not n.startswith("."):
                    files.append({"name": n, "bytes": os.path.getsize(p), "summary": first_comment(p)})
            return self._send(200, {"dir": REPL_DIR, "files": files, "installed_packages_dir": "/REPL/.pkgs"})
        if u.path == "/read":
            n = (parse_qs(u.query).get("name") or [""])[0]
            p = os.path.join(REPL_DIR, os.path.basename(n))
            if not _NAME.match(os.path.basename(n)) or not os.path.isfile(p):
                return self._send(404, {"error": "no such file in /REPL"})
            return self._send(200, {"name": os.path.basename(n), "content": open(p, errors="replace").read(20000)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/run", "/export"):
            return self._send(404, {"error": "not found"})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            status, body = do_export(req) if path == "/export" else do_run(req)
        except Exception as e:
            status, body = 500, {"error": f"{type(e).__name__}: {e}"}
        self._send(status, body)


class UnixHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    address_family = __import__("socket").AF_UNIX
    daemon_threads = True

    def server_bind(self):
        if os.path.exists(SOCK):
            os.unlink(SOCK)
        self.socket.bind(SOCK)
        os.chmod(SOCK, 0o600)   # both ends run as the SAME uid 1001 (sandbox/Dockerfile), so owner-only is enough (bandit B103, fixed 2026-10-20 -- see proxy_server.py's matching note)
        self.server_name, self.server_port = "uds", 0


if __name__ == "__main__":
    os.makedirs(REPL_DIR, exist_ok=True)
    os.makedirs(os.path.join(REPL_DIR, ".pkgs"), exist_ok=True)
    os.makedirs(WORK_DIR, exist_ok=True)
    UnixHTTPServer(SOCK, Handler).serve_forever()
