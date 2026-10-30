"""Red-team tool server: the source-level scanners (gitleaks, Semgrep, Bandit, pip-audit, npm audit, Trivy) and OWASP ZAP, as a small bearer-token
API the chat loop in backend/ calls. --network host is only needed for pip-audit/npm-audit's advisory-database lookups and ZAP's own HTTP traffic;
every scanner here reads only the read-only source mounts (/src_self/self, /src_dynamic/<name>) -- nothing accepts an arbitrary filesystem path.

Targets, two kinds:
  - "self": Aegis scanning its own source. install.sh rsyncs it into src/self (the pristine copy, read-only from the sandbox container at
    /self_pristine) and seeds the working copy self_target/self from it -- read-only HERE at /src_self/self, read-write from the sandbox
    container at /self_target/self, so the sandbox's fixes are exactly what the next scan of "self" sees.
  - a dynamically CLONED public (or, with GITHUB_CLONE_TOKEN, private) GitHub repo, added at runtime via /clone_target with no container restart --
    see _dynamic_targets() below. Point Aegis at any repo with "run redteam on github repo: <url>".

ZAP's active (attacking) scanner is gated by the OPERATOR naming a real URL to /zap, not by a fixed allow-list of known-safe names -- this is a
single-operator, bring-your-own-key tool: typing a URL into `pentest <target> and fix it` IS the operator's explicit, scoped consent, the same way
running Strix against your own target is. The one thing this never skips is the cloud-metadata address (169.254.169.254) -- see _zap_target_ok."""
import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import uuid
from urllib.parse import urlparse

import httpx

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

TOKEN = os.environ.get("REDTEAM_TOKEN", "")
_SELF_DIR = "/src_self/self"
TARGETS = {"self": _SELF_DIR} if os.path.isdir(_SELF_DIR) else {}
def _image_targets() -> dict:
    """Any image tarball under /images/, by filename -- generalized 2026-10-27 from a fixed 4-name list so a
    dynamically-cloned repo's own built-and-saved image (same operator `docker build && docker save` pattern
    install.sh already uses for cyberJiina's own 4 images) is scannable the moment its tar appears in the
    read-only /images mount, with no code change and no container restart -- same refresh-per-call pattern as
    _dynamic_targets() below."""
    if not os.path.isdir("/images"):
        return {}
    return {fn[:-4]: f"/images/{fn}" for fn in os.listdir("/images") if fn.endswith(".tar")}
_MAX_FINDINGS = 25
_TIMEOUT_S = 240

# Arbitrary-repo targets: CLONE_STAGING_DIR is writable here and read-only from the sandbox container at /dynamic_pristine (the clone step below
# writes there); DYNAMIC_POOL_DIR is read-only HERE and read-write from the sandbox container at /dynamic_target -- the same host directory, just
# under a parent-directory mount so a newly-cloned repo becomes a valid target immediately, no restart. The chat loop clones with /clone_target,
# then copies the clone into the dynamic target's working copy (the same reset-pattern move it already does for "self") before scanning/fixing it.
CLONE_STAGING_DIR = "/dynamic_pristine_rw"
DYNAMIC_POOL_DIR = "/src_dynamic"
_SAFE_TARGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
GITHUB_CLONE_TOKEN = os.environ.get("GITHUB_CLONE_TOKEN", "")   # optional: only needed to clone a PRIVATE repo; a public repo clones with no token at all
ZAP_PORT = 8090
ZAP_API_KEY = os.environ.get("ZAP_API_KEY") or uuid.uuid4().hex
ZAP_HOME = tempfile.mkdtemp(prefix="zap_")   # one stable dir for ZAP's own process lifetime, not a fresh one per call
_zap_proc = {"p": None}

app = FastAPI()


def _dynamic_targets() -> dict:
    """Every already-cloned repo under DYNAMIC_POOL_DIR, as {name: path} -- re-scanned on every call (unlike TARGETS, fixed at container start)
    so a repo cloned a moment ago is immediately a valid target with no restart."""
    if not os.path.isdir(DYNAMIC_POOL_DIR):
        return {}
    out = {}
    for name in os.listdir(DYNAMIC_POOL_DIR):
        p = os.path.join(DYNAMIC_POOL_DIR, name)
        if os.path.isdir(p):
            out[name] = p
    return out


def _slug_from_url(url: str) -> str:
    """owner/repo from a github.com URL (https or git@), lowercased and joined with a single underscore -- a safe, readable default target name."""
    m = re.search(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", url.strip())
    return f"{m.group(1)}_{m.group(2)}".lower() if m else ""


def _check_repo_access(url: str) -> dict:
    """Check if a git repo is accessible without cloning. Returns {"accessible": bool, "error_type": str, "error": str}.
    error_type can be: "network", "auth", "invalid", or "unknown"."""
    code, raw = _run(["git", "ls-remote", url], timeout=15)

    if code == 0:
        return {"accessible": True, "error_type": None, "error": ""}

    stderr = raw.lower()

    # Check for network issues FIRST (before auth issues)
    if any(phrase in stderr for phrase in [
        "could not resolve host",
        "failed to connect",
        "connection timed out",
        "network is unreachable",
        "temporary failure in name resolution"
    ]):
        return {"accessible": False, "error_type": "network", "error": raw[:400]}

    # Check for authentication/private repo issues
    if any(phrase in stderr for phrase in [
        "could not read username",
        "authentication failed",
        "repository not found",
        "requested url returned error: 403",
        "fatal: could not read password"
    ]):
        return {"accessible": False, "error_type": "auth", "error": raw[:400]}

    # Check for invalid URL
    if "not a git repository" in stderr or "does not appear to be a git repo" in stderr:
        return {"accessible": False, "error_type": "invalid", "error": raw[:400]}

    # Unknown error
    return {"accessible": False, "error_type": "unknown", "error": raw[:400]}


def _auth(authorization: str = Header(default="")):
    if not TOKEN or authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


class TargetReq(BaseModel):
    target: str


class CloneReq(BaseModel):
    url: str
    name: str = ""


class CloneWithTokenReq(BaseModel):
    url: str
    token_file: str
    name: str = ""


class CheckRepoReq(BaseModel):
    url: str


class ZapReq(BaseModel):
    target_url: str


def _target(name: str) -> str:
    all_targets = {**TARGETS, **_dynamic_targets()}
    path = all_targets.get(name)
    if not path:
        raise HTTPException(status_code=400, detail=f"unknown target; choose one of {sorted(all_targets)}")
    return path


def _image_target(name: str) -> str:
    path = _image_targets().get(name)
    if not path:
        raise HTTPException(status_code=400, detail=f"unknown image target; choose one of {sorted(_image_targets())}")
    return path


def _run(cmd: list, cwd: str = None, timeout: int = _TIMEOUT_S) -> tuple:
    """(exit_code, stdout). Never raises on a non-zero exit (every one of these tools uses that to mean 'findings exist')."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or p.stderr
    except subprocess.TimeoutExpired:
        return -1, "(timed out)"
    except FileNotFoundError as exc:
        return -1, f"(tool not found: {exc})"


@app.get("/health")
async def health():
    return {"status": "ok", "targets": sorted({**TARGETS, **_dynamic_targets()})}


@app.get("/targets", dependencies=[Depends(_auth)])
async def targets():
    return {"targets": sorted({**TARGETS, **_dynamic_targets()}), "image_targets": sorted(_image_targets())}


@app.post("/clone_target", dependencies=[Depends(_auth)])
async def clone_target(r: CloneReq):
    """Clones a git repo (public with no token, or private if GITHUB_CLONE_TOKEN is configured) into the dynamic target pool so it can be
    scanned/fixed exactly like "self". Returns the target NAME to use for every later redteam_*/export_project call. Only ever reads a URL and
    an optional caller-chosen name -- never a path, never a command; the clone itself is a fixed `git clone --depth 1` with nothing from the
    caller reaching the shell beyond the URL and the sanitized name below."""
    url = r.url.strip()
    if not re.match(r"^(https://|git@)[\w.-]+[:/][\w./-]+$", url):
        raise HTTPException(status_code=400, detail="that does not look like a real git URL (https://... or git@...)")
    name = r.name.strip() or _slug_from_url(url)
    if not name or not _SAFE_TARGET_NAME.match(name):
        raise HTTPException(status_code=400, detail="could not derive a safe target name from that URL -- pass one explicitly (letters, digits, _, - only)")
    if name in TARGETS:
        raise HTTPException(status_code=400, detail=f"{name!r} is already one of our own named targets -- choose a different name")
    os.makedirs(CLONE_STAGING_DIR, exist_ok=True)
    dest = os.path.join(CLONE_STAGING_DIR, name)
    if os.path.isdir(dest):   # a prior clone under this name may be stale -- always re-clone fresh rather than reuse it
        _run(["rm", "-rf", dest])
    # Also clear any old target copy from a previous clone of this same repo -- the user wants to scan the CURRENT version, not a stale fixed one
    target_path = os.path.join(DYNAMIC_POOL_DIR, name)
    if os.path.isdir(target_path):
        _run(["rm", "-rf", target_path])
    clone_url = url
    if GITHUB_CLONE_TOKEN and url.startswith("https://github.com/"):
        clone_url = url.replace("https://github.com/", f"https://x-access-token:{GITHUB_CLONE_TOKEN}@github.com/", 1)
    code, raw = _run(["git", "clone", "--depth", "1", clone_url, dest], timeout=120)
    if code != 0 or not os.path.isdir(dest):
        safe_raw = raw.replace(GITHUB_CLONE_TOKEN, "***") if GITHUB_CLONE_TOKEN else raw
        return {"ok": False, "error": f"clone failed: {safe_raw[:400]}", "note": "If this is a PRIVATE repo, GITHUB_CLONE_TOKEN is not configured on this host (or lacks access)."}
    _run(["rm", "-rf", os.path.join(dest, ".git")])   # the clone's own history/config never needs to be scanned or exported, and may carry the token in its remote URL
    return {"ok": True, "name": name, "note": f"Cloned to the dynamic pool as target {name!r}. Next: bash_run `rm -rf /dynamic_target/{name} && cp -r /dynamic_pristine/{name} /dynamic_target/{name}` "
                                               f"to populate the scannable/fixable working copy, then use target {name!r} with every redteam_*/export_project call from here on."}


def _dir_bytes(path: str) -> int:
    total = 0
    for root, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


@app.post("/cleanup_targets", dependencies=[Depends(_auth)])
async def cleanup_targets():
    """Deletes every CLONE DIRECTORY currently sitting in CLONE_STAGING_DIR (/dynamic_pristine_rw) -- nothing in here is ever reused across a
    browser session (new_session() starts fresh every time the page connects), so any clone found here on startup is an orphan left behind by
    a previous session that never got cleaned up. "self" is not stored here (it's install.sh's own src/self seed, untouched by this) so it is
    never at risk. Only directories are removed: github_token.txt (the fixed, predetermined credential the system prompt tells the model to
    pass as token_file for self-scanning a private Musiac/Aegis -- see system_prompt.py) lives at this same top level and is deliberately left
    alone, a real regression caught live 2026-10-29 when an earlier version of this endpoint deleted it along with the clones and broke
    self-scan's own private-repo clone step. Called once, deterministically in code (not an LLM tool call) right where the chat loop's own
    check_scanner_versions runs, so a full host disk from months of accumulated clones can never silently block a brand-new session."""
    before = _dir_bytes(CLONE_STAGING_DIR) if os.path.isdir(CLONE_STAGING_DIR) else 0
    removed = []
    if os.path.isdir(CLONE_STAGING_DIR):
        for name in os.listdir(CLONE_STAGING_DIR):
            p = os.path.join(CLONE_STAGING_DIR, name)
            if not os.path.isdir(p):
                continue                                 # credential files (github_token.txt) live here too -- never delete anything but a clone directory
            removed.append(name)
            _run(["rm", "-rf", p])
    after = _dir_bytes(CLONE_STAGING_DIR) if os.path.isdir(CLONE_STAGING_DIR) else 0
    return {"ok": True, "removed": sorted(removed), "freed_bytes": before - after}


@app.post("/check_repo_access", dependencies=[Depends(_auth)])
async def check_repo_access(r: CheckRepoReq):
    """Check if a git repository is accessible without cloning it. Returns accessibility status and error type (network/auth/invalid)."""
    url = r.url.strip()
    if not re.match(r"^(https://|git@)[\w.-]+[:/][\w./-]+$", url):
        raise HTTPException(status_code=400, detail="that does not look like a real git URL (https://... or git@...)")

    result = _check_repo_access(url)
    return result


async def _check_repo_size(url: str) -> dict:
    """Real size of a github.com repo's git database, in KB, straight from the GitHub API's own `size` field on the repo object -- never
    estimated, never cloned first just to measure. This is the full repo's size (GitHub does not expose a shallow-clone-size figure), so a
    `--depth 1` clone (what clone_target actually does) is very often smaller than this for a repo with deep history -- note that honestly in
    the result rather than implying this IS what a clone will use. Only github.com URLs are supported (the API this calls is GitHub-specific);
    any other host returns ok:false with a plain reason, never a guess."""
    m = re.search(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", url.strip())
    if not m:
        return {"ok": False, "error": "not a github.com URL -- repo size can only be checked via GitHub's own API"}
    repo = f"{m.group(1)}/{m.group(2)}"
    headers = {"Authorization": f"Bearer {GITHUB_CLONE_TOKEN}"} if GITHUB_CLONE_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"https://api.github.com/repos/{repo}", headers=headers)
    except Exception as e:                                                      # noqa: BLE001
        return {"ok": False, "error": f"could not reach GitHub: {type(e).__name__}: {e}"}
    if r.status_code == 404:
        return {"ok": False, "error": f"{repo!r} not found (private without a working token, or a typo)"}
    if r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0":
        reset = r.headers.get("x-ratelimit-reset")
        return {"ok": False, "error": f"GitHub API rate limit reached (resets {reset})" + ("" if GITHUB_CLONE_TOKEN else " -- set GITHUB_CLONE_TOKEN to raise the limit")}
    if r.status_code != 200:
        return {"ok": False, "error": f"GitHub API returned HTTP {r.status_code}"}
    data = r.json()
    size_kb = int(data.get("size") or 0)
    return {"ok": True, "repo": repo, "size_kb": size_kb, "size_mb": round(size_kb / 1024, 1),
            "note": "size is the full git database (GitHub does not report shallow-clone size); a --depth 1 clone is often smaller, "
                    "especially for a repo with long history, but can still be close to this for a repo with large tracked binaries/LFS."}


@app.post("/check_repo_size", dependencies=[Depends(_auth)])
async def check_repo_size(r: CheckRepoReq):
    """Checks a github.com repo's real size via the GitHub API, with NO clone performed. Call this before clone_target for any repo you are
    not already confident is small -- the result tells the caller whether it's likely to fit the sandbox's current /REPL scratch quota."""
    url = r.url.strip()
    if not re.match(r"^(https://|git@)[\w.-]+[:/][\w./-]+$", url):
        raise HTTPException(status_code=400, detail="that does not look like a real git URL (https://... or git@...)")
    return await _check_repo_size(url)


@app.post("/clone_with_token", dependencies=[Depends(_auth)])
async def clone_with_token(r: CloneWithTokenReq):
    """Clones a private git repo using a token read from a file path. The token is read once and not stored."""
    url = r.url.strip()
    token_file = r.token_file.strip()

    if not re.match(r"^(https://|git@)[\w.-]+[:/][\w./-]+$", url):
        raise HTTPException(status_code=400, detail="that does not look like a real git URL (https://... or git@...)")

    # Read token from file
    if not os.path.isfile(token_file):
        return {"ok": False, "error": f"Token file not found: {token_file}"}

    try:
        with open(token_file, 'r') as f:
            token = f.read().strip()
    except Exception as e:
        return {"ok": False, "error": f"Could not read token file: {str(e)}"}

    if not token:
        return {"ok": False, "error": "Token file is empty"}

    # Prepare clone
    name = r.name.strip() or _slug_from_url(url)
    if not name or not _SAFE_TARGET_NAME.match(name):
        raise HTTPException(status_code=400, detail="could not derive a safe target name from that URL -- pass one explicitly (letters, digits, _, - only)")
    if name in TARGETS:
        raise HTTPException(status_code=400, detail=f"{name!r} is already one of our own named targets -- choose a different name")

    os.makedirs(CLONE_STAGING_DIR, exist_ok=True)
    dest = os.path.join(CLONE_STAGING_DIR, name)
    if os.path.isdir(dest):
        _run(["rm", "-rf", dest])
    target_path = os.path.join(DYNAMIC_POOL_DIR, name)
    if os.path.isdir(target_path):
        _run(["rm", "-rf", target_path])

    # Clone with token (GitHub format)
    clone_url = url
    if url.startswith("https://github.com/"):
        clone_url = url.replace("https://github.com/", f"https://x-access-token:{token}@github.com/", 1)
    elif url.startswith("https://"):
        # Generic HTTPS git URL - insert token before the hostname
        clone_url = url.replace("https://", f"https://x-access-token:{token}@", 1)

    code, raw = _run(["git", "clone", "--depth", "1", clone_url, dest], timeout=120)

    # Clear token from memory
    token = None
    clone_url = None

    if code != 0 or not os.path.isdir(dest):
        # Don't include any part of the URL that might have the token
        return {"ok": False, "error": f"Clone failed. The token may be invalid or lack required permissions. Error: {raw[:200]}"}

    _run(["rm", "-rf", os.path.join(dest, ".git")])
    return {"ok": True, "name": name, "note": f"Cloned to the dynamic pool as target {name!r}. Next: bash_run `rm -rf /dynamic_target/{name} && cp -r /dynamic_pristine/{name} /dynamic_target/{name}` "
                                               f"to populate the scannable/fixable working copy, then use target {name!r} with every redteam_*/export_project call from here on."}


@app.post("/trivy", dependencies=[Depends(_auth)])
async def run_trivy(r: TargetReq):
    """Scans a LOCAL image tarball (docker save'd outside this container by a deploy step, mounted read-only at /images/<name>.tar) -- never the Docker socket, never a live registry pull."""
    path = _image_target(r.target)
    # 1200s: Aegis's own `redteam` image bundles a full JRE (for ZAP) + Node + several Python scanners' own
    # dependencies -- 627MB and many packages to check against the vuln DB, confirmed to exceed the previous 600s
    # on a real run. Not app-code bloat (server.py + custom_rules.yml together are under 50KB) -- genuine
    # third-party tooling size, so the fix is headroom, not a smaller image.
    # --timeout is TRIVY'S OWN internal deadline (default 5m0s), separate from and tighter than the subprocess
    # wrapper's `timeout` kwarg below -- confirmed live: Aegis's own 627MB redteam image (a full JRE + Node +
    # several Python scanners' deps) hit trivy's own 5-minute internal "context deadline exceeded" well before
    # the subprocess's 1200s ever had a chance to fire. Set both explicitly so one real number governs the scan.
    code, raw = _run(["trivy", "image", "--input", path, "--cache-dir", "/trivy-cache", "--timeout", "20m", "--format", "json", "--severity", "HIGH,CRITICAL", "--scanners", "vuln,secret"], timeout=1260)
    try:
        data = json.loads(raw)
    except Exception:
        return {"ok": False, "tool": "trivy", "target": r.target, "error": raw[:500]}
    findings = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            findings.append({"kind": "vuln", "target": res.get("Target"), "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"), "id": v.get("VulnerabilityID"), "severity": v.get("Severity")})
        for sec in res.get("Secrets", []) or []:
            findings.append({"kind": "secret", "target": res.get("Target"), "rule": sec.get("RuleID"), "line": sec.get("StartLine")})
    return {"ok": True, "tool": "trivy", "target": r.target, "count": len(findings), "findings": findings[:_MAX_FINDINGS]}


@app.post("/gitleaks", dependencies=[Depends(_auth)])
async def run_gitleaks(r: TargetReq):
    path = _target(r.target)
    out_file = os.path.join(tempfile.gettempdir(), f"gitleaks_{uuid.uuid4().hex}.json")     # a unique path per call: two scans can run concurrently
    code, raw = _run(["gitleaks", "detect", "--source", path, "--no-git", "--report-format", "json", "--report-path", out_file, "--exit-code", "0"])
    try:
        findings = json.load(open(out_file))
    except Exception:
        findings = []
    finally:
        try:
            os.remove(out_file)
        except OSError:
            pass
    items = [{"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine")} for f in findings[:_MAX_FINDINGS]]
    return {"ok": True, "tool": "gitleaks", "target": r.target, "count": len(findings), "findings": items}


@app.post("/bandit", dependencies=[Depends(_auth)])
async def run_bandit(r: TargetReq):
    path = _target(r.target)
    cmd = ["bandit", "-r", path, "-f", "json", "-q", "-ll"]  # -ll: medium+ severity only (keeps the count meaningful)
    # Bandit has NO auto-discovery of a scanned project's own pyproject.toml -- it only reads [tool.bandit] (e.g. exclude_dirs) when
    # explicitly passed `-c <path>`, confirmed in its own source (bandit/core/config.py). Without this, a target's own, often deliberate,
    # exclusions (most commonly exclude_dirs = ["tests"], since test fixtures legitimately exercise "insecure" patterns on purpose) are
    # silently ignored, producing noisy findings the project itself already waives -- a real run against usestrix_strix reported all 7
    # findings from tests/ despite its pyproject.toml explicitly excluding that directory.
    pyproject = os.path.join(path, "pyproject.toml")
    if os.path.isfile(pyproject):
        cmd += ["-c", pyproject]
    code, raw = _run(cmd)
    try:
        data = json.loads(raw)
    except Exception:
        return {"ok": False, "tool": "bandit", "target": r.target, "error": raw[:500]}
    results = data.get("results", [])
    items = [{"rule": f.get("test_id"), "severity": f.get("issue_severity"), "file": f.get("filename", "").replace(path, ""), "line": f.get("line_number"), "issue": f.get("issue_text", "")[:140]} for f in results[:_MAX_FINDINGS]]
    return {"ok": True, "tool": "bandit", "target": r.target, "count": len(results), "findings": items}


@app.post("/semgrep", dependencies=[Depends(_auth)])
async def run_semgrep(r: TargetReq):
    path = _target(r.target)
    code, raw = _run(["semgrep", "scan", "--config", "p/owasp-top-ten", "--config", "p/security-audit", "--config", "/app/custom_rules.yml", "--json", "--quiet", path])
    try:
        data = json.loads(raw)
    except Exception:
        return {"ok": False, "tool": "semgrep", "target": r.target, "error": raw[:500]}
    results = data.get("results", [])
    items = [{"rule": f.get("check_id"), "severity": (f.get("extra", {}) or {}).get("severity"), "file": f.get("path", "").replace(path, ""), "line": (f.get("start", {}) or {}).get("line"),
              "message": ((f.get("extra", {}) or {}).get("message") or "")[:140]} for f in results[:_MAX_FINDINGS]]
    return {"ok": True, "tool": "semgrep", "target": r.target, "count": len(results), "findings": items}


@app.post("/pip_audit", dependencies=[Depends(_auth)])
async def run_pip_audit(r: TargetReq):
    path = _target(r.target)
    reqs = []
    proj_dirs = []
    for root, _dirs, files in os.walk(path):
        if "node_modules" in root:
            continue
        if "requirements.txt" in files:
            reqs.append(os.path.join(root, "requirements.txt"))
        if "pyproject.toml" in files:
            # pip-audit's --locked flag ONLY recognizes PEP 751 pylock.toml/pylock.*.toml files -- NOT uv.lock or
            # poetry.lock (confirmed in its own source: _dep_source_from_project_path globs pylock.*.toml only).
            # Passing --locked for a uv.lock/poetry.lock project makes it fail outright ("no lockfiles found")
            # even though pip-audit can resolve and audit that same project fine unlocked -- a real regression
            # found in a real run (strix, a uv.lock project, falsely reported as "could not complete"). So only
            # ever use --locked for an actual pylock file; a uv.lock/poetry.lock project is just audited unlocked.
            locked = any(f == "pylock.toml" or (f.startswith("pylock.") and f.endswith(".toml")) for f in files)
            proj_dirs.append((root, locked))
    findings, errors, checked = [], [], 0
    for req in reqs[:10]:
        code, raw = _run(["pip-audit", "-r", req, "--format", "json", "--progress-spinner", "off"])
        try:
            data = json.loads(raw)
        except Exception:
            errors.append(f"{req.replace(path, '')}: {raw[:250]}")
            continue
        checked += 1
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            for v in dep.get("vulns", []):
                findings.append({"package": dep.get("name"), "installed": dep.get("version"), "id": v.get("id"), "fix_versions": v.get("fix_versions"), "file": req.replace(path, "")})
    for proj_dir, locked in proj_dirs[:10]:
        cmd = ["pip-audit", proj_dir, "--format", "json", "--progress-spinner", "off"]
        if locked:
            cmd.append("--locked")
        code, raw = _run(cmd)
        label = os.path.join(proj_dir, "pyproject.toml").replace(path, "")
        try:
            data = json.loads(raw)
        except Exception:
            errors.append(f"{label}: {raw[:250]}")
            continue
        checked += 1
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            for v in dep.get("vulns", []):
                findings.append({"package": dep.get("name"), "installed": dep.get("version"), "id": v.get("id"), "fix_versions": v.get("fix_versions"), "file": label})
    if checked == 0 and (reqs or proj_dirs):
        return {"ok": False, "tool": "pip_audit", "target": r.target, "error": "every requirements.txt/pyproject.toml failed to audit (likely no reachable vulnerability database); not a clean result", "details": errors[:3]}
    return {"ok": True, "tool": "pip_audit", "target": r.target, "requirements_files_checked": checked, "count": len(findings), "findings": findings[:_MAX_FINDINGS], "errors": errors}


@app.post("/npm_audit", dependencies=[Depends(_auth)])
async def run_npm_audit(r: TargetReq):
    path = _target(r.target)
    locks = []
    for root, _dirs, files in os.walk(path):
        if "node_modules" in root:
            continue
        if "package-lock.json" in files:
            locks.append(root)
    findings, errors, checked = [], [], 0
    for d in locks[:10]:
        code, raw = _run(["npm", "audit", "--json"], cwd=d)
        try:
            data = json.loads(raw)
        except Exception:
            errors.append(f"{d.replace(path, '')}: {raw[:250]}")
            continue
        if "error" in data or "vulnerabilities" not in data:    # npm's own error shape ({"message": "...", "error": {...}}) is valid JSON but not a real audit result
            errors.append(f"{d.replace(path, '')}: {json.dumps(data)[:250]}")
            continue
        checked += 1
        vulns = data.get("vulnerabilities", {})
        for name, v in vulns.items():
            findings.append({"package": name, "severity": v.get("severity"), "via": [x if isinstance(x, str) else x.get("title") for x in (v.get("via") or [])][:3], "directory": d.replace(path, "")})
    if checked == 0 and locks:
        return {"ok": False, "tool": "npm_audit", "target": r.target, "error": "every package-lock.json failed to audit (likely no reachable npm registry); not a clean result", "details": errors[:3]}
    return {"ok": True, "tool": "npm_audit", "target": r.target, "lockfiles_checked": checked, "count": len(findings), "findings": findings[:_MAX_FINDINGS], "errors": errors}


def _zap_target_ok(url: str) -> str:
    """Parses target_url, requires http/https + a host, resolves it and refuses only the cloud-metadata address -- this is a single-operator,
    bring-your-own-key tool: naming a URL to /zap at all IS the operator's explicit, scoped consent (same trust model as running Strix against
    your own target), so private/loopback/LAN addresses are allowed on purpose (the common case: "a target you've stood up" locally). Returns
    an error string, or "" if OK to scan."""
    try:
        u = urlparse(url)
    except ValueError:
        return "not a valid URL"
    if u.scheme not in ("http", "https") or not u.hostname:
        return "the URL must start with http:// or https:// and name a host"
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except OSError as e:
        return f"could not resolve {u.hostname}: {e}"
    for info in infos:
        addr = info[4][0].split("%")[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if str(ip) == "169.254.169.254" or ip.is_multicast:
            return f"{u.hostname} resolves to the cloud-metadata or a multicast address -- refused regardless of operator intent"
    return ""


async def _zap_start():
    if _zap_proc["p"] and _zap_proc["p"].poll() is None:
        return
    _zap_proc["p"] = subprocess.Popen(
        [_ACTIVE_ZAP["sh"], "-daemon", "-port", str(ZAP_PORT), "-host", "127.0.0.1", "-dir", ZAP_HOME, "-config", f"api.key={ZAP_API_KEY}",
         "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false", "-config", "api.disablekey=false"],
        cwd=ZAP_HOME, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    async with httpx.AsyncClient(timeout=5) as c:
        for _ in range(120):     # a cold start installs ~35 bundled add-ons into ZAP_HOME first, which alone can take 15-20s
            try:
                r = await c.get(f"http://127.0.0.1:{ZAP_PORT}/JSON/core/view/version/", params={"apikey": ZAP_API_KEY})
                if r.status_code == 200:
                    return
            except Exception:
                pass
            await asyncio.sleep(1)
    raise HTTPException(status_code=503, detail="ZAP did not start")


async def _zap_get(path: str, **params):
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"http://127.0.0.1:{ZAP_PORT}{path}", params={"apikey": ZAP_API_KEY, **params})
        return r.json()


# Keyword -> plain-English category, checked against the real rule NAMES ZAP's own /JSON/ascan/view/scanners/
# and /JSON/pscan/view/scanners/ return for THIS run -- never a hardcoded "what ZAP can do" list, so a category is
# only ever reported here when a rule that matches it is actually enabled right now.
_ZAP_CATEGORY_KEYWORDS = [
    ("sql injection", "SQL injection"), ("cross site scripting", "XSS (reflected/stored/DOM)"), ("xss", "XSS (reflected/stored/DOM)"),
    ("path traversal", "path/directory traversal"), ("remote file inclusion", "remote file inclusion"),
    ("command injection", "OS command injection"), ("server side request forgery", "SSRF"), ("ssrf", "SSRF"),
    ("csrf", "cross-site request forgery"), ("directory browsing", "directory listing exposure"),
    ("information disclosure", "information disclosure"), ("session", "session management"),
    ("cookie", "cookie security"), ("csp", "Content-Security-Policy checks"), ("clickjack", "clickjacking"),
    ("x-frame-options", "clickjacking"), ("open redirect", "open redirect"), ("code injection", "code injection"),
    ("xml external entity", "XXE"), ("xxe", "XXE"), ("buffer overflow", "buffer overflow"),
    ("format string", "format-string injection"), ("ldap injection", "LDAP injection"),
    ("padding oracle", "padding-oracle / crypto"), ("insecure http method", "insecure HTTP methods"),
    ("cors", "CORS misconfiguration"), ("cache", "cache-control / sensitive-data caching"),
    ("user agent fuzzer", "User-Agent fuzzing"), ("comment", "suspicious source comments"),
    ("version disclosure", "server/version disclosure"), ("timestamp", "timestamp disclosure"),
    ("hash disclosure", "hash disclosure"), ("parameter tampering", "parameter tampering"),
]


async def _zap_tested_categories() -> list:
    """Real rule names ZAP currently has enabled (active + passive), grouped into plain-English categories by
    keyword match. Returns [] (never invented) if the scanner-list calls fail for any reason."""
    try:
        active = (await _zap_get("/JSON/ascan/view/scanners/")).get("scanners", [])
        passive = (await _zap_get("/JSON/pscan/view/scanners/")).get("scanners", [])
    except Exception:
        return []
    names = [str(s.get("name", "")) for s in active if isinstance(s, dict)] + [str(s.get("name", "")) for s in passive if isinstance(s, dict)]
    seen, cats = set(), []
    for n in names:
        low = n.lower()
        for kw, label in _ZAP_CATEGORY_KEYWORDS:
            if kw in low and label not in seen:
                seen.add(label)
                cats.append(label)
    return cats


async def _zap_progress_lines(r: ZapReq):
    """Generator for /zap's streaming response: yields one NDJSON line ({"progress": "..."}) per real step as it actually happens, then exactly
    one final line ({"final": true, ...}). Spider + passive scan always run; the active (attacking) scan also runs, since naming a URL here at
    all is the operator's own consent -- see _zap_target_ok's docstring."""
    def line(obj):
        return json.dumps(obj) + "\n"
    url = r.target_url.strip()
    err = _zap_target_ok(url)
    if err:
        yield line({"final": True, "ok": False, "tool": "zap", "target_url": url, "error": err})
        return
    active_ran = False
    try:
        yield line({"progress": f"starting ZAP against {url} ..."})
        await _zap_start()
        tested_categories = await _zap_tested_categories()
        if tested_categories:
            yield line({"progress": f"Testing for: {', '.join(tested_categories)}", "tested_categories": tested_categories})
        yield line({"progress": "ZAP daemon ready; starting spider (crawl)"})
        await _zap_get("/JSON/core/action/newSession/", name="", overwrite="true")
        d = await _zap_get("/JSON/spider/action/scan/", url=url, maxChildren="25", recurse="true")
        scan_id = d.get("scan")
        if scan_id is None:
            yield line({"final": True, "ok": False, "tool": "zap", "target_url": url, "error": f"spider did not start: {d}"})
            return
        last_pct = -1
        for _ in range(_TIMEOUT_S):
            st = await _zap_get("/JSON/spider/view/status/", scanId=scan_id)
            pct = int(st.get("status", 0))
            if pct != last_pct:
                yield line({"progress": f"spider crawling: {pct}%"})
                last_pct = pct
            if pct >= 100:
                break
            await asyncio.sleep(1)
        yield line({"progress": "spider done; passive scan draining its queue"})
        for _ in range(60):     # the passive scanner finishes shortly after the spider does
            st = await _zap_get("/JSON/pscan/view/recordsToScan/")
            left = int(st.get("recordsToScan", 0))
            if left == 0:
                break
            await asyncio.sleep(1)
        yield line({"progress": "passive scan done"})
        yield line({"progress": "starting the ACTIVE (attacking) scan -- this sends real payloads, not pattern matches"})
        ad = await _zap_get("/JSON/ascan/action/scan/", url=url, recurse="true", inScopeOnly="false")
        ascan_id = ad.get("scan")
        if ascan_id is not None:
            active_ran = True
            last_pct = -1
            for _ in range(_TIMEOUT_S):
                st = await _zap_get("/JSON/ascan/view/status/", scanId=ascan_id)
                pct = int(st.get("status", 0))
                if pct != last_pct:
                    yield line({"progress": f"active scan attacking: {pct}%"})
                    last_pct = pct
                if pct >= 100:
                    break
                await asyncio.sleep(1)
            yield line({"progress": "active scan done"})
        else:
            yield line({"progress": "active scan did not start"})
        alerts = (await _zap_get("/JSON/core/view/alerts/", baseurl=url)).get("alerts", [])
    finally:
        try:
            await _zap_get("/JSON/core/action/shutdown/")
        except Exception:
            pass
    def _rel_url(full: str, base: str) -> str:
        if full and full != base and full.startswith(base):
            return full[len(base):]
        return full
    items = [{"risk": a.get("risk"), "name": a.get("alert"), "rule": a.get("pluginId"), "url": _rel_url(a.get("url") or "", url)} for a in alerts[:_MAX_FINDINGS]]
    note = ("Spider + passive + ACTIVE (attacking) scan. Any CONFIRMED alert below reflects a real payload ZAP actually sent and a real response "
            "it actually got back -- this is evidence of what she could really do, not a pattern match.") if active_ran \
        else "Spider + passive scan only -- the active scan did not start; report this as a real error, not a clean result."
    yield line({"final": True, "ok": True, "tool": "zap", "target_url": url, "count": len(alerts), "findings": items, "active_scan_ran": active_ran,
                "tested_categories": tested_categories, "note": note})


@app.post("/zap", dependencies=[Depends(_auth)])
async def run_zap(r: ZapReq):
    """Streams one NDJSON line per real step as the scan runs (see _zap_progress_lines), ending with one {"final": true, ...} line. A caller
    that only wants the end result can still just read the whole body and take the last line."""
    return StreamingResponse(_zap_progress_lines(r), media_type="application/x-ndjson")


class LateralMovementReq(BaseModel):
    target_url: str
    session_cookie: str   # "name=value" captured by the caller AFTER logging in through a (deliberately bypassed) auth check


async def _zap_lateral_movement_lines(r: LateralMovementReq):
    """The `ethical_hack` skill's dynamic half: given a real session cookie for a target that is ALREADY running, crawl it once WITHOUT the
    cookie (what a stranger with no account could reach) and once WITH it (what a logged-in session can reach), then report the DIFFERENCE --
    real evidence of how much extra surface a successful breach actually opens up, not a guess. The cookie is injected via ZAP's own HTTP
    Sender replacer rule (/JSON/replacer/...), so every request ZAP makes during the authenticated pass genuinely carries it -- this is a real
    authenticated crawl, not a header set on one request. The replacer rule is always removed in `finally`, so a later plain /zap call for the
    same target never accidentally runs with a stale cookie attached."""
    def line(obj):
        return json.dumps(obj) + "\n"
    url = r.target_url.strip()
    cookie = r.session_cookie.strip()
    err = _zap_target_ok(url)
    if err:
        yield line({"final": True, "ok": False, "tool": "lateral_movement", "target_url": url, "error": err})
        return
    if not cookie or "=" not in cookie:
        yield line({"final": True, "ok": False, "tool": "lateral_movement", "target_url": url,
                    "error": "session_cookie must be a real 'name=value' cookie captured after logging in"})
        return
    replacer_desc = "ethical_hack_cookie"

    async def _crawl(label: str) -> set:
        await _zap_get("/JSON/core/action/newSession/", name="", overwrite="true")
        d = await _zap_get("/JSON/spider/action/scan/", url=url, maxChildren="25", recurse="true")
        scan_id = d.get("scan")
        if scan_id is None:
            return set()
        for _ in range(_TIMEOUT_S):
            st = await _zap_get("/JSON/spider/view/status/", scanId=scan_id)
            if int(st.get("status", 0)) >= 100:
                break
            await asyncio.sleep(1)
        res = await _zap_get("/JSON/spider/view/results/", scanId=scan_id)
        return {u for u in (res.get("results") or []) if isinstance(u, str)}

    try:
        yield line({"progress": f"starting ZAP against {url} to measure lateral movement ..."})
        await _zap_start()
        yield line({"progress": "unauthenticated crawl: what a stranger with no account can reach"})
        unauth_urls = await _crawl("unauthenticated")
        yield line({"progress": f"unauthenticated crawl found {len(unauth_urls)} URL(s); now crawling WITH the session cookie"})
        await _zap_get("/JSON/replacer/action/addRule/", description=replacer_desc, enabled="true", matchType="REQ_HEADER",
                        matchString="Cookie", matchRegex="false", replacement=cookie)
        auth_urls = await _crawl("authenticated")
        new_urls = sorted(auth_urls - unauth_urls)
        yield line({"progress": f"authenticated crawl found {len(auth_urls)} URL(s); {len(new_urls)} only reachable after breach"})
        active_ran = False
        alerts = []
        if new_urls:
            yield line({"progress": "running the ACTIVE (attacking) scan against the authenticated session"})
            ad = await _zap_get("/JSON/ascan/action/scan/", url=url, recurse="true", inScopeOnly="false")
            ascan_id = ad.get("scan")
            if ascan_id is not None:
                active_ran = True
                for _ in range(_TIMEOUT_S):
                    st = await _zap_get("/JSON/ascan/view/status/", scanId=ascan_id)
                    if int(st.get("status", 0)) >= 100:
                        break
                    await asyncio.sleep(1)
                alerts = (await _zap_get("/JSON/core/view/alerts/", baseurl=url)).get("alerts", [])
    finally:
        try:
            await _zap_get("/JSON/replacer/action/removeRule/", description=replacer_desc)
        except Exception:
            pass
        try:
            await _zap_get("/JSON/core/action/shutdown/")
        except Exception:
            pass

    def _rel_url(full: str) -> str:
        return full[len(url):] if full and full != url and full.startswith(url) else full
    new_items = [{"risk": a.get("risk"), "name": a.get("alert"), "rule": a.get("pluginId"), "url": _rel_url(a.get("url") or "")}
                 for a in alerts if a.get("url") in new_urls][:_MAX_FINDINGS]
    note = ("Every URL in `new_pages_after_breach` was NOT reachable by the unauthenticated crawl and IS reachable by the authenticated one -- "
            "this is a real, measured difference, not an inference. An empty list is a genuine 'lateral movement gained nothing extra' result, "
            "not a sign the probe failed; report it plainly either way.")
    yield line({"final": True, "ok": True, "tool": "lateral_movement", "target_url": url,
                "unauthenticated_page_count": len(unauth_urls), "authenticated_page_count": len(auth_urls),
                "new_pages_after_breach": [_rel_url(u) for u in new_urls], "findings_on_new_pages": new_items,
                "active_scan_ran": active_ran, "note": note})


@app.post("/zap_lateral_movement", dependencies=[Depends(_auth)])
async def run_zap_lateral_movement(r: LateralMovementReq):
    """Streams one NDJSON line per real step (see _zap_lateral_movement_lines), ending with {"final": true, ...}. Call this ONLY after the
    `ethical_hack` skill has already patched the target's own auth code, restarted it, and logged in to get a real session_cookie -- this
    endpoint does not bypass anything itself, it only measures what a cookie you already hold can reach."""
    return StreamingResponse(_zap_lateral_movement_lines(r), media_type="application/x-ndjson")


async def _check_pypi_version(package: str, current: str) -> dict:
    """Check if a PyPI package has a newer version available."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"https://pypi.org/pypi/{package}/json")
            if r.status_code != 200:
                return {"name": package, "current": current, "latest": None, "status": "error", "error": "pypi unreachable"}
            data = r.json()
            latest = data.get("info", {}).get("version", "")
            is_latest = latest == current
            return {"name": package, "current": current, "latest": latest, "status": "latest" if is_latest else "update_available"}
    except Exception as e:
        return {"name": package, "current": current, "latest": None, "status": "error", "error": str(e)[:100]}


async def _check_github_release(repo: str, current: str) -> dict:
    """Check if a GitHub repo has a newer release. Unauthenticated GitHub API calls are capped at 60/hour per IP --
    real and genuinely hit live 2026-10-30 after repeated testing (confirmed via the response's own
    x-ratelimit-remaining: 0 header, not guessed). Authenticates with GITHUB_CLONE_TOKEN when it's configured
    (already present for private-repo cloning, reused here for free) -- that raises the cap to 5000/hour, which
    this check's own call volume never comes close to. Retries once, after a short pause, ONLY on a genuine
    transient failure (a network exception, or a 5xx from GitHub itself) -- retrying a 403 rate-limit immediately
    would just burn the same exhausted quota a second time for nothing, so that case fails straight through with
    a clear, honest reason instead."""
    name = repo.split("/")[1]
    headers = {"Authorization": f"Bearer {GITHUB_CLONE_TOKEN}"} if GITHUB_CLONE_TOKEN else {}
    last_error = "unknown error"
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    latest = data.get("tag_name", "")
                    return {"name": name, "current": current, "latest": latest, "status": "latest" if latest == current else "update_available"}
                if r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0":
                    reset = r.headers.get("x-ratelimit-reset")
                    when = f" (resets {reset})" if reset else ""
                    return {"name": name, "current": current, "latest": None, "status": "error",
                            "error": f"GitHub API rate limit reached{when}" + ("" if GITHUB_CLONE_TOKEN else " -- set GITHUB_CLONE_TOKEN to raise the limit from 60/hour to 5000/hour")}
                last_error = f"github api error (HTTP {r.status_code})"
                if r.status_code < 500:
                    break   # a non-rate-limit 4xx won't be fixed by retrying either
        except Exception as e:                                                   # noqa: BLE001 -- a genuinely transient failure, worth the one retry below
            last_error = str(e)[:100]
        if attempt == 0:
            await asyncio.sleep(1.5)
    return {"name": name, "current": current, "latest": None, "status": "error", "error": last_error}


async def _check_npm_version() -> dict:
    """Check npm version (system-installed via apt, not checked against npm registry)."""
    try:
        code, raw = _run(["npm", "--version"], timeout=3)
        version = raw.strip() if code == 0 else "unknown"
        return {"name": "npm", "current": version, "latest": version, "status": "system-managed"}
    except Exception:
        return {"name": "npm", "current": "unknown", "latest": None, "status": "error"}


# --- Live, same-session tool update (added 2026-10-30) ---
# This container's root filesystem is READ-ONLY and it runs as a non-root user (redteam/Dockerfile) -- a real
# security boundary, same spirit as the sandbox's own --network none. /tool_updates is a HOST BIND MOUNT (install.sh
# -v "$(pwd)/redteam_tool_updates:/tool_updates", owned by this container's own uid 1000, same pattern as
# dynamic_pristine_rw) -- not the ephemeral /tmp tmpfs this used on 2026-10-30's first cut, which lost every
# update on the next container restart/recreate and made the operator re-request the same update every session
# (owner's own catch, same day: "that will be cumbersome for the user"). Writing here instead means a live update
# IS permanent -- it persists exactly the same way a fix written into dynamic_target/<name> does -- with zero
# extra "restore on startup" step needed for the pip/binary tools: PATH is set to prefer _USER_BIN before this
# module finishes importing (below), so a process that starts fresh after a restart finds last session's updated
# binary already sitting there and uses it immediately. ZAP is the one exception (invoked by a fixed path, not
# found via PATH) -- see _restore_zap_from_disk() below for its own explicit startup check.
TOOL_UPDATES_DIR = os.environ.get("TOOL_UPDATES_DIR", "/tool_updates")
_USER_BIN = os.path.join(TOOL_UPDATES_DIR, "bin")
_ZAP_PERSIST_DIR = os.path.join(TOOL_UPDATES_DIR, "zap_latest")
_ACTIVE_ZAP = {"sh": "/opt/zap/zap.sh", "version": "v2.17.0"}   # no cheap `--version` without starting the whole
                                                                  # daemon, so the live-updated version is tracked
                                                                  # here instead of queried fresh each time; see
                                                                  # _restore_zap_from_disk() for how this is
                                                                  # repopulated from a PRIOR session's update


def _ensure_user_bin_on_path() -> None:
    os.makedirs(_USER_BIN, exist_ok=True)
    os.environ["PYTHONUSERBASE"] = TOOL_UPDATES_DIR   # redirects `pip install --user` here instead of $HOME/.local
                                                        # (which would be /tmp, ephemeral) -- PYTHONUSERBASE, unlike
                                                        # HOME, controls ONLY this, so nothing else about the
                                                        # process's environment needs to change for it.
    if _USER_BIN not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = _USER_BIN + ":" + os.environ.get("PATH", "")


def _restore_zap_from_disk() -> None:
    """Called once at module import (below) -- if a PRIOR session's _update_zap() left a real install sitting in
    _ZAP_PERSIST_DIR (host-mounted, survives this fresh process same as the pip/binary tools do via PATH), point
    _ACTIVE_ZAP at it immediately rather than starting this session back on the image's baked-in version."""
    sh = os.path.join(_ZAP_PERSIST_DIR, "zap.sh")
    version_file = os.path.join(_ZAP_PERSIST_DIR, ".version")
    if os.path.isfile(sh) and os.path.isfile(version_file):
        try:
            version = open(version_file, encoding="utf-8").read().strip()
        except OSError:
            return
        if version:
            _ACTIVE_ZAP["sh"], _ACTIVE_ZAP["version"] = sh, version


_ensure_user_bin_on_path()
_restore_zap_from_disk()


async def _live_cli_version(cmd: list, pattern: str, fallback: str) -> str:
    """The REAL version of whatever `cmd` resolves to on PATH right now -- so a re-check after a live update
    reflects what actually changed, never a baked-in pin that a real upgrade just made stale."""
    try:
        code, out = _run(cmd, timeout=10)
        m = re.search(pattern, out)
        if code == 0 and m:
            return m.group(1)
    except Exception:
        pass
    return fallback


def _dpkg_arch() -> str:
    code, out = _run(["dpkg", "--print-architecture"], timeout=5)
    return out.strip() if code == 0 else "arm64"


async def _update_pip_tool(name: str) -> dict:
    _ensure_user_bin_on_path()
    version_check = {"bandit": (["bandit", "--version"], r"bandit\s+([\d.]+)"),
                      "semgrep": (["semgrep", "--version"], r"([\d.]+)"),
                      "pip-audit": (["pip-audit", "--version"], r"pip-audit\s+([\d.]+)")}[name]
    from_version = await _live_cli_version(*version_check, "?")
    # No --no-cache-dir (removed 2026-10-30, found live: a real semgrep update hit this call's own 180s timeout
    # and never finished) -- it forced pip to re-download EVERY dependency from PyPI from scratch on every single
    # update attempt, with nothing to fall back on if that happened to be slow. HOME=/tmp here (redteam/Dockerfile),
    # so pip's default cache (~/.cache/pip) already lives on the container's own writable tmpfs -- letting pip use
    # it costs nothing extra and makes a retry (or a different tool sharing a dependency) meaningfully faster.
    code, out = _run(["pip", "install", "--user", "--upgrade", name], timeout=240)
    if code != 0:
        return {"name": name, "ok": False, "from": from_version, "to": None, "error": out[-400:]}
    to_version = await _live_cli_version(*version_check, "?")
    return {"name": name, "ok": True, "from": from_version, "to": to_version}


async def _update_github_binary(name: str, repo: str, extract_member: str) -> dict:
    """gitleaks/trivy: single static binary, same release-tarball shape redteam/Dockerfile already uses at build
    time -- downloaded here into _USER_BIN (ahead of /usr/local/bin on PATH once _ensure_user_bin_on_path runs),
    so every later subprocess call to the bare command name picks up the new one with no other code change."""
    _ensure_user_bin_on_path()
    rel = await _check_github_release(repo, "")
    latest = rel.get("latest")
    if not latest:
        return {"name": name, "ok": False, "from": None, "to": None, "error": "could not reach GitHub to find the latest release"}
    arch_raw = _dpkg_arch()
    arch = {"gitleaks": {"arm64": "arm64", "amd64": "x64"}, "trivy": {"arm64": "ARM64", "amd64": "64bit"}}[name].get(arch_raw)
    if not arch:
        return {"name": name, "ok": False, "from": None, "to": None, "error": f"unsupported architecture {arch_raw!r}"}
    ver_num = latest.lstrip("v")
    url = {"gitleaks": f"https://github.com/{repo}/releases/download/{latest}/gitleaks_{ver_num}_linux_{arch}.tar.gz",
           "trivy": f"https://github.com/{repo}/releases/download/{latest}/trivy_{ver_num}_Linux-{arch}.tar.gz"}[name]
    dest_tar = os.path.join(tempfile.gettempdir(), f"{name}_update_{uuid.uuid4().hex}.tar.gz")
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return {"name": name, "ok": False, "from": None, "to": None, "error": f"download failed: HTTP {r.status_code}"}
            with open(dest_tar, "wb") as f:
                f.write(r.content)
        code, raw = _run(["tar", "-xzf", dest_tar, "-C", _USER_BIN, extract_member], timeout=30)
        if code != 0:
            return {"name": name, "ok": False, "from": None, "to": None, "error": f"extract failed: {raw[:300]}"}
        os.chmod(os.path.join(_USER_BIN, extract_member), 0o755)
    finally:
        try:
            os.remove(dest_tar)
        except OSError:
            pass
    return {"name": name, "ok": True, "from": None, "to": latest}


async def _update_zap() -> dict:
    """Same official-distribution tarball Dockerfile uses at build time, extracted into a scratch dir first (so a
    failed download/extract never disturbs whatever is already working), then moved into _ZAP_PERSIST_DIR -- the
    host-mounted, persistent location _restore_zap_from_disk() reads back on a future fresh container start -- in
    one atomic rename. _ACTIVE_ZAP is updated only once the new install is verified present and in its final
    location, and _zap_start() (see there) always reads _ACTIVE_ZAP["sh"] rather than a hardcoded path, so a live
    update takes effect on the NEXT scan without needing anything else changed."""
    rel = await _check_github_release("zaproxy/zaproxy", "")
    latest = rel.get("latest")
    if not latest:
        return {"name": "zaproxy", "ok": False, "from": None, "to": None, "error": "could not reach GitHub to find the latest release"}
    ver_num = latest.lstrip("v")
    staging = os.path.join(TOOL_UPDATES_DIR, f"zap_staging_{uuid.uuid4().hex}")
    os.makedirs(staging, exist_ok=True)
    dest_tar = os.path.join(tempfile.gettempdir(), f"zap_update_{uuid.uuid4().hex}.tar.gz")
    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as c:
            r = await c.get(f"https://github.com/zaproxy/zaproxy/releases/download/{latest}/ZAP_{ver_num}_Linux.tar.gz")
            if r.status_code != 200:
                return {"name": "zaproxy", "ok": False, "from": None, "to": None, "error": f"download failed: HTTP {r.status_code}"}
            with open(dest_tar, "wb") as f:
                f.write(r.content)
        code, raw = _run(["tar", "-xzf", dest_tar, "-C", staging, "--strip-components=1"], timeout=60)
        if code != 0:
            return {"name": "zaproxy", "ok": False, "from": None, "to": None, "error": f"extract failed: {raw[:300]}"}
        new_sh = os.path.join(staging, "zap.sh")
        if not os.path.isfile(new_sh):
            return {"name": "zaproxy", "ok": False, "from": None, "to": None, "error": "downloaded archive did not contain zap.sh"}
        os.chmod(new_sh, 0o755)
        with open(os.path.join(staging, ".version"), "w", encoding="utf-8") as f:
            f.write(latest)
    finally:
        try:
            os.remove(dest_tar)
        except OSError:
            pass
    if _zap_proc["p"] and _zap_proc["p"].poll() is None:   # a currently-running ZAP is still the OLD binary -- stop it BEFORE
        _zap_proc["p"].terminate()                          # replacing the directory it's launched from
        _zap_proc["p"] = None
    old_version = _ACTIVE_ZAP["version"]
    shutil.rmtree(_ZAP_PERSIST_DIR, ignore_errors=True)
    os.rename(staging, _ZAP_PERSIST_DIR)   # atomic within the same filesystem (both under TOOL_UPDATES_DIR)
    _ACTIVE_ZAP["sh"], _ACTIVE_ZAP["version"] = os.path.join(_ZAP_PERSIST_DIR, "zap.sh"), latest
    return {"name": "zaproxy", "ok": True, "from": old_version, "to": latest}


_UPDATABLE = {"bandit", "semgrep", "pip-audit", "gitleaks", "trivy", "zaproxy"}


class UpdateToolsReq(BaseModel):
    tools: list[str]


@app.post("/update_tools", dependencies=[Depends(_auth)])
async def update_tools(r: UpdateToolsReq):
    """Updates exactly the named tools, live, persisted to the host-mounted /tool_updates (see the module comment
    above for why that's where this can safely happen without touching the read-only root, and why it survives a
    restart/recreate rather than just lasting this container's current life). Never silently
    skips a requested tool -- an unknown/non-updatable name (npm: status is already "system-managed" and never
    offered; ZAP sub-add-ons aren't a thing this tracks) comes back as its own ok:false entry with a real reason,
    same "never invent, always say what actually happened" discipline as every scan result. Finishes by
    re-running the exact same check scanner_versions() does, so the caller never has to guess whether a
    just-updated tool's OWN version check is now using the new binary or the old one."""
    attempted = []
    for name in r.tools:
        name = str(name).strip()
        if name not in _UPDATABLE:
            attempted.append({"name": name, "ok": False, "from": None, "to": None,
                               "error": "not a tool this endpoint can update (not in the known scanner set, or it's system-managed like npm)"})
            continue
        if name in ("bandit", "semgrep", "pip-audit"):
            attempted.append(await _update_pip_tool(name))
        elif name == "gitleaks":
            attempted.append(await _update_github_binary("gitleaks", "gitleaks/gitleaks", "gitleaks"))
        elif name == "trivy":
            attempted.append(await _update_github_binary("trivy", "aquasecurity/trivy", "trivy"))
        elif name == "zaproxy":
            attempted.append(await _update_zap())
    recheck = await scanner_versions()
    return {"ok": True, "attempted": attempted, "versions": recheck}


@app.get("/scanner_versions", dependencies=[Depends(_auth)])
async def scanner_versions():
    """Check current vs latest versions of all scanning tools. current is queried LIVE from whatever binary is
    actually on PATH right now (or _ACTIVE_ZAP for ZAP, which has no cheap --version check) -- never a hardcoded
    build-time pin -- so this always reflects reality, including right after /update_tools runs."""
    bandit_cur, semgrep_cur, audit_cur, gitleaks_cur, trivy_cur = await asyncio.gather(
        _live_cli_version(["bandit", "--version"], r"bandit\s+([\d.]+)", "1.9.4"),
        _live_cli_version(["semgrep", "--version"], r"([\d.]+)", "1.182.1"),
        _live_cli_version(["pip-audit", "--version"], r"pip-audit\s+([\d.]+)", "2.10.1"),
        _live_cli_version(["gitleaks", "version"], r"([\d.]+)", "8.30.1"),
        _live_cli_version(["trivy", "--version"], r"Version:\s*([\d.]+)", "0.76.1"),
    )
    tools = await asyncio.gather(
        _check_pypi_version("bandit", bandit_cur),
        _check_pypi_version("semgrep", semgrep_cur),
        _check_pypi_version("pip-audit", audit_cur),
        _check_github_release("gitleaks/gitleaks", f"v{gitleaks_cur}"),
        _check_github_release("aquasecurity/trivy", f"v{trivy_cur}"),
        _check_github_release("zaproxy/zaproxy", _ACTIVE_ZAP["version"]),
        _check_npm_version(),
        return_exceptions=True,
    )
    # Filter out any exceptions and convert to error entries
    results = []
    for tool in tools:
        if isinstance(tool, Exception):
            results.append({"name": "unknown", "current": "?", "latest": None, "status": "error", "error": str(tool)[:100]})
        else:
            results.append(tool)

    return {"ok": True, "tools": results}
