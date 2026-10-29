"""Aegis's sandbox-web control plane: a tiny stdlib HTTP server (no deps beyond the image's own python3) that starts/stops/restarts the
REAL web server of a cloned-and-fixed project, so an active ZAP pentest has something genuinely running to attack -- the missing piece that made
"start the cloned code's server in sandbox env ... and run a pentest on it" not actually possible before 2026-10-26.

Runs as THIS container's own process 1 (see the docker run command in sandbox_web/README.md), on a fixed control port (default 7999) that only
aegis-backend-web calls (backend/tools/sandbox_web.py). The controlled app is started as a tracked child process on APP_PORT (default
8900, matching Aegis's own entrypoint.sh convention: `uvicorn backend.web:app --host 0.0.0.0 --port 8900`), inside this SAME container, on
`aegis-net` -- so the redteam container (also on that network) can reach it by container/alias name, the same way it already reaches
aegis-backend-web. One app runs at a time; starting a new one stops whatever was running first (mirrors a real "restart the server, re-scan"
cycle, not several apps side by side).

Project source is read from the SAME host-mounted directories the sandbox's own bash_run/edit_file write into (/dynamic_target/<name>,
/self_target/self) -- mounted HERE read-only, since this container only ever runs code, never edits it; a fix made in the code sandbox shows up
here automatically on the next (re)start, no copy step needed.
"""
import http.server
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "7999"))
APP_PORT = int(os.environ.get("APP_PORT", "8900"))
_SRC_ROOTS = {"dynamic": "/dynamic_target", "self": "/self_target"}
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

_state_lock = threading.Lock()
_state = {"proc": None, "project": None, "cmd": None, "started_at": None, "log": []}


def _project_dir(name: str) -> str:
    if name == "self":
        return os.path.join(_SRC_ROOTS["self"], "self")
    return os.path.join(_SRC_ROOTS["dynamic"], name)


def _tail_reader(proc, buf, limit=4000):
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        buf.append(line.rstrip("\n"))
        del buf[:-200]                                                             # keep only the newest lines, not an unbounded log


def _stop_locked():
    """Must be called with _state_lock held."""
    proc = _state["proc"]
    if proc and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    _state.update(proc=None, project=None, cmd=None, started_at=None)


def _wait_ready(port: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1.5)  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- loopback health-check: scheme+host pinned to http://127.0.0.1, port is a validated int
            return True
        except urllib.error.HTTPError:                                             # any real HTTP response (even 404/401) means the server IS up
            return True
        except Exception:                                                          # noqa: BLE001 -- connection refused / not ready yet
            time.sleep(0.5)
    return False


def _start(project: str, cmd: str, ready_seconds: float):
    if not _NAME_RE.match(project):
        return {"ok": False, "error": f"{project!r} is not a safe project name."}
    root = _project_dir(project)
    if not os.path.isdir(root):
        return {"ok": False, "error": f"no such working copy: {root} (clone/populate it first)."}
    entry = os.path.join(root, "backend", "web.py")
    default_cmd = f"uvicorn backend.web:app --host 0.0.0.0 --port {APP_PORT}"
    use_cmd = (cmd or "").strip() or default_cmd
    if not cmd and not os.path.isfile(entry):
        return {"ok": False, "error": f"no backend/web.py under {root}; this project is not shaped like a FastAPI app on the default convention "
                                       f"-- pass an explicit start command instead of relying on the default."}
    with _state_lock:
        _stop_locked()
        buf = []
        env = dict(os.environ)
        try:
            proc = subprocess.Popen(shlex.split(use_cmd), cwd=root, env=env, preexec_fn=os.setsid,  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args -- command source is the internal authenticated control plane (regex-validated project name + operator-provided cmd); shell=True removed via shlex.split so metacharacters cannot inject
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception as e:                                                     # noqa: BLE001
            return {"ok": False, "error": f"could not launch: {type(e).__name__}: {e}"}
        _state.update(proc=proc, project=project, cmd=use_cmd, started_at=time.time(), log=buf)
        threading.Thread(target=_tail_reader, args=(proc, buf), daemon=True).start()
    ready = _wait_ready(APP_PORT, ready_seconds)
    if not ready and proc.poll() is not None:
        with _state_lock:
            tail = "\n".join(buf[-40:])
            _stop_locked()
        return {"ok": False, "error": f"the app exited immediately (exit code {proc.returncode}). Last output:\n{tail}"}
    return {"ok": ready, "project": project, "port": APP_PORT, "cmd": use_cmd,
            "error": None if ready else f"started (pid alive) but did not answer on :{APP_PORT} within {ready_seconds}s -- it may still be booting; "
                                          "check status again, or read its log."}


def _status():
    with _state_lock:
        proc, project, cmd, started, buf = _state["proc"], _state["project"], _state["cmd"], _state["started_at"], list(_state["log"])
    running = bool(proc and proc.poll() is None)
    return {"running": running, "project": project, "cmd": cmd, "port": APP_PORT if running else None,
            "uptime_s": round(time.time() - started, 1) if running and started else None,
            "exit_code": None if running or proc is None else proc.returncode, "log_tail": buf[-30:]}


class Handler(http.server.BaseHTTPRequestHandler):
    def _reply(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n == 0:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        if self.path.rstrip("/") == "/status":
            self._reply(200, _status())
        else:
            self._reply(404, {"ok": False, "error": "unknown path"})

    def do_POST(self):
        path = self.path.rstrip("/")
        body = self._body()
        if path == "/start" or path == "/restart":                                # restart = start: _start() always stops whatever ran first
            self._reply(200, _start(str(body.get("project") or ""), str(body.get("cmd") or ""), float(body.get("ready_seconds") or 20)))
        elif path == "/stop":
            with _state_lock:
                was_running = bool(_state["proc"] and _state["proc"].poll() is None)
                _stop_locked()
            self._reply(200, {"ok": True, "was_running": was_running})
        else:
            self._reply(404, {"ok": False, "error": "unknown path"})

    def log_message(self, fmt, *args):                                            # quiet; the app's own output already goes to this container's stdout via the tail thread's source
        pass


if __name__ == "__main__":
    print(f"[sandbox_web control] listening on 0.0.0.0:{CONTROL_PORT}, app port {APP_PORT}", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), Handler).serve_forever()  # nosec B104 -- must bind non-loopback so sibling containers on aegis-net can reach the control plane by name
