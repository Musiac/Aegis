"""Aegis's sandbox-web control plane: a tiny stdlib HTTP server (no deps beyond the image's own python3) that starts/stops/restarts the
REAL web server of a cloned-and-fixed project, so an active ZAP pentest has something genuinely running to attack -- the missing piece that made
"start the cloned code's server in sandbox env ... and run a pentest on it" not actually possible before 2026-10-26.

Runs as THIS container's own process 1 (see the docker run command in sandbox_web/README.md), on a fixed control port (default 7999) that only
aegis-code calls (backend/tools/sandbox_web.py). The controlled app is started as a tracked child process on APP_PORT (default
8900, matching Aegis's own entrypoint.sh convention: `uvicorn backend.web:app --host 0.0.0.0 --port 8900`), inside this SAME container, on
`aegis-net` -- so the redteam container (also on that network) can reach it by container/alias name, the same way it already reaches
aegis-code. One app runs at a time; starting a new one stops whatever was running first (mirrors a real "restart the server, re-scan"
cycle, not several apps side by side).

Project source is read from the SAME host-mounted directories the sandbox's own bash_run/edit_file write into (/dynamic_target/<name>,
/self_target/self) -- mounted HERE read-only, since this container only ever runs code, never edits it; a fix made in the code sandbox shows up
here automatically on the next (re)start, no copy step needed.

LOCAL OPENAI STUB (added 2026-10-30): a second tiny stdlib HTTP server, STUB_PORT (default 8901), on the SAME container/IP as APP_PORT -- so
it's already reachable at http://www.sandbox.com:8901/v1, no new container and no DNS/hosts change, since www.sandbox.com already resolves
to this container. Answers POST /v1/chat/completions and /v1/completions (streaming or not) with a fixed, schema-valid canned response,
regardless of what was asked -- just enough for a target app's real OpenAI client to get a well-formed reply instead of failing closed on a
missing/unreachable API key, so its actual routes come up for ZAP to attack. _start() sets OPENAI_API_KEY/OPENAI_BASE_URL (OpenAI SDK env
var names; both Python and Node official SDKs read OPENAI_BASE_URL to redirect off api.openai.com) for the launched app ONLY when the real
environment does not already define them -- never overriding a genuinely configured key. Deliberately plain HTTP, not HTTPS: redirecting via
OPENAI_BASE_URL avoids ever needing to spoof api.openai.com's own TLS certificate, which a self-signed cert could not satisfy for an SDK that
verifies it (the DNS-hijack-the-real-hostname approach was considered and rejected for exactly this reason)."""
import http.server
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "7999"))
APP_PORT = int(os.environ.get("APP_PORT", "8900"))
STUB_PORT = int(os.environ.get("STUB_PORT", "8901"))
STUB_API_KEY = os.environ.get("STUB_API_KEY", "sk-aegis-local-stub-0000000000000000")   # never validated anywhere real; any string works
STUB_BASE_URL = f"http://www.sandbox.com:{STUB_PORT}/v1"
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


_DEP_INSTALL_TIMEOUT_S = 180
# Persistent, NON-ephemeral caches for pip/npm (added 2026-10-30) -- bind-mounted from the host (see sandbox_web/README.md's docker run
# command), so they survive this container being deleted and recreated, same spirit as /REPL/.uvcache for the code sandbox. pip/npm both
# already skip re-downloading a package version already sitting in their own cache, so the SECOND time any repo (or a different repo that
# happens to share a dependency) needs e.g. requests==2.34.2, it's a cache hit, not a fresh PyPI/npm-registry fetch -- only genuinely new
# package/version combinations ever get downloaded again.
PIP_CACHE_DIR = os.environ.get("PIP_CACHE_DIR", "/pip_cache")
NPM_CACHE_DIR = os.environ.get("NPM_CONFIG_CACHE", "/npm_cache")
_INSTALL_ENV = dict(os.environ, PIP_CACHE_DIR=PIP_CACHE_DIR, NPM_CONFIG_CACHE=NPM_CACHE_DIR)


def _run_install(cmd: list, root: str, buf: list) -> None:
    buf.append(f"[deps] running: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, cwd=root, env=_INSTALL_ENV, capture_output=True, text=True, timeout=_DEP_INSTALL_TIMEOUT_S)
        buf.append(f"[deps] exit code {p.returncode}")
        if p.returncode != 0:
            buf.append((p.stderr or p.stdout or "")[-2000:])
    except subprocess.TimeoutExpired:
        buf.append(f"[deps] install timed out after {_DEP_INSTALL_TIMEOUT_S}s -- proceeding anyway; it will likely fail on a missing module/package.")
    except Exception as e:                                                        # noqa: BLE001
        buf.append(f"[deps] install failed: {type(e).__name__}: {e}")


def _install_deps(root: str, buf: list) -> None:
    """Best-effort: install the project's OWN declared dependencies before starting it (added 2026-10-30 -- this container has always had
    real outbound internet for exactly this, per this file's own module docstring, but nothing ever actually ran pip/npm until now). Never
    blocks or fails startup on its own -- recorded into buf (the same log the operator sees via sandbox_app_status / a startup error), so a
    real install failure is visible, never silently swallowed. Runs BOTH Python and npm installs when both manifests are present (a repo
    can have a Python backend AND a React/npm frontend) -- this is not an either/or choice."""
    did_any = False
    if os.path.isfile(os.path.join(root, "requirements.txt")):
        _run_install(["pip", "install", "--quiet", "--no-input", "--disable-pip-version-check", "-r", "requirements.txt"], root, buf)
        did_any = True
    elif os.path.isfile(os.path.join(root, "pyproject.toml")) or os.path.isfile(os.path.join(root, "setup.py")):
        _run_install(["pip", "install", "--quiet", "--no-input", "--disable-pip-version-check", "-e", "."], root, buf)
        did_any = True
    if os.path.isfile(os.path.join(root, "package.json")):
        npm_cmd = ["npm", "ci", "--no-audit", "--no-fund"] if os.path.isfile(os.path.join(root, "package-lock.json")) else \
                  ["npm", "install", "--no-audit", "--no-fund"]
        _run_install(npm_cmd, root, buf)
        did_any = True
    if not did_any:
        buf.append("[deps] no requirements.txt/pyproject.toml/setup.py/package.json found -- nothing to install.")


_RUN_SCRATCH_DIR = "/app_scratch"


def _writable_copy(project: str, root: str, buf: list) -> str:
    """/dynamic_target and /self_target are mounted READ-ONLY in this container by design (see module docstring: "this container only ever
    runs code, never edits it") -- but npm install/pip install -e . both need to WRITE into the project directory itself (node_modules,
    egg-info), which a read-only mount refuses. Rather than loosen that mount (which would let a started app's own process write into the
    SAME tree the code sandbox's edit_file/bash_run operate on -- real interference risk between the two containers), copy the project into
    a scratch directory THIS container already owns and run install+launch from there instead. Wiped and re-copied fresh on every start
    (matches the existing one-app-at-a-time design -- no accumulation across different projects)."""
    dest = os.path.join(_RUN_SCRATCH_DIR, project)
    shutil.rmtree(dest, ignore_errors=True)
    try:
        shutil.copytree(root, dest)
    except Exception as e:                                                        # noqa: BLE001
        buf.append(f"[deps] could not copy project to a writable scratch dir for install: {type(e).__name__}: {e}")
        return root
    return dest


def _start(project: str, cmd: str, ready_seconds: float, install: bool = True):
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
        run_root = root
        if install:
            run_root = _writable_copy(project, root, buf)
            _install_deps(run_root, buf)
        env = dict(os.environ)
        # Give the app's real OpenAI client something to talk to instead of failing closed on a missing/unreachable key -- only when the
        # operator did NOT already configure a real one, so this never overrides a genuine, intentional key.
        env.setdefault("OPENAI_API_KEY", STUB_API_KEY)
        env.setdefault("OPENAI_BASE_URL", STUB_BASE_URL)
        try:
            proc = subprocess.Popen(shlex.split(use_cmd), cwd=run_root, env=env, preexec_fn=os.setsid,  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args -- command source is the internal authenticated control plane (regex-validated project name + operator-provided cmd); shell=True removed via shlex.split so metacharacters cannot inject
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
    install_log = "\n".join(x for x in buf if x.startswith("[deps]"))
    return {"ok": ready, "project": project, "port": APP_PORT, "cmd": use_cmd, "install_log": install_log,
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
            install = body.get("install")
            self._reply(200, _start(str(body.get("project") or ""), str(body.get("cmd") or ""), float(body.get("ready_seconds") or 20),
                                     install=True if install is None else bool(install)))
        elif path == "/stop":
            with _state_lock:
                was_running = bool(_state["proc"] and _state["proc"].poll() is None)
                _stop_locked()
            self._reply(200, {"ok": True, "was_running": was_running})
        else:
            self._reply(404, {"ok": False, "error": "unknown path"})

    def log_message(self, fmt, *args):                                            # quiet; the app's own output already goes to this container's stdout via the tail thread's source
        pass


_STUB_PATHS = ("/v1/chat/completions", "/v1/completions")


class StubOpenAIHandler(http.server.BaseHTTPRequestHandler):
    """Answers any /v1/chat/completions or /v1/completions request with a fixed, schema-valid canned reply -- streaming (SSE) or not,
    matching what the request asked for. Never reads the Authorization header's actual value; any API key is accepted, since this never
    talks to the real OpenAI API and nothing here is ever validated against it."""

    def _json(self, obj: dict) -> bytes:
        return json.dumps(obj).encode()

    def do_POST(self):
        if self.path.rstrip("/") not in _STUB_PATHS:
            body = self._json({"error": {"message": f"unknown path {self.path!r}", "type": "invalid_request_error"}})
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except ValueError:
            req = {}
        model = str(req.get("model") or "stub-model")
        content = "Hello, welcome to local openai server"
        created = int(time.time())
        rid = f"chatcmpl-aegis-stub-{created}"
        is_chat = "/chat/" in self.path
        if req.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            delta_key = "delta" if is_chat else "text"
            first = {"id": rid, "object": "chat.completion.chunk" if is_chat else "text_completion", "created": created, "model": model,
                     "choices": [{"index": 0, delta_key: ({"role": "assistant", "content": content} if is_chat else content), "finish_reason": None}]}
            last = {"id": rid, "object": "chat.completion.chunk" if is_chat else "text_completion", "created": created, "model": model,
                    "choices": [{"index": 0, delta_key: ({} if is_chat else ""), "finish_reason": "stop"}]}
            try:
                self.wfile.write(f"data: {json.dumps(first)}\n\n".encode())
                self.wfile.write(f"data: {json.dumps(last)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        choice = ({"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"} if is_chat
                  else {"index": 0, "text": content, "finish_reason": "stop"})
        body = self._json({"id": rid, "object": "chat.completion" if is_chat else "text_completion", "created": created, "model": model,
                            "choices": [choice], "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/v1/models":
            body = self._json({"object": "list", "data": [{"id": "stub-model", "object": "model", "owned_by": "aegis-local-stub"}]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._reply_404()

    def _reply_404(self):
        body = self._json({"error": {"message": "not found", "type": "invalid_request_error"}})
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"[sandbox_web control] listening on 0.0.0.0:{CONTROL_PORT}, app port {APP_PORT}, local-openai stub on {STUB_PORT}", flush=True)
    threading.Thread(
        target=lambda: http.server.ThreadingHTTPServer(("0.0.0.0", STUB_PORT), StubOpenAIHandler).serve_forever(),  # nosec B104 -- same binding rationale as the control port: must be reachable by name from sibling containers on aegis-net
        daemon=True,
    ).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), Handler).serve_forever()  # nosec B104 -- must bind non-loopback so sibling containers on aegis-net can reach the control plane by name
