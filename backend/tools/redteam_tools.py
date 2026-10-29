"""Thin client in front of the `redteam` container (see ../../redteam/): a bearer-token API, --network none, which scans only a pre-mounted
READ-ONLY copy of source. The tool here only forwards a named target and the tool name; it cannot send a path, a command or anything else
the server would act on. Aegis is a single-operator tool (no accounts), so unlike a larger multi-account assistant there is no owner/admin role check here --
the only gate is whether the server is actually configured (a token present)."""
import json
import re
import os
from collections import Counter

import httpx

URL = os.environ.get("AEGIS_REDTEAM_URL", "http://127.0.0.1:7906")
TOKEN = os.environ.get("REDTEAM_TOKEN", "")   # written into .env by install.sh, read by both this process and the redteam container itself


def _gate():
    if not TOKEN:
        return json.dumps({"ok": False, "error": "The red-team tool server is not set up on this host. Say so in one short sentence."})
    return None


async def _call(path: str, target: str) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(1260.0, connect=5.0)) as c:   # trivy's first scan after a container restart can download a ~127MB vulnerability database,
                                                                                       # and Aegis's own `redteam` image (627MB, bundles a JRE+Node+several scanners) needs the
                                                                                       # full 1200s server-side timeout below plus margin -- the other 5 scanners finish in seconds
        r = await c.post(f"{URL}/{path}", json={"target": target}, headers={"Authorization": f"Bearer {TOKEN}"})
    if r.status_code != 200:
        return {"ok": False, "error": f"the scanner answered HTTP {r.status_code}"}
    return r.json()


def _note(data: dict) -> dict:
    data["note"] = ("These are the exact, recorded results of a real scanner run just now, not a description. Report the count and the top findings (rule, file, line) exactly as given. "
                     "Never invent a finding that is not in this list, and never say 'clean' or 'no issues' for a count greater than 0.")
    return data


def _tally(tool: str, data: dict) -> dict:
    """Exact counts, computed by code from the scanner's own result -- the model must copy these, never add anything up itself.
    `total` is the scanner's own `count`; the findings list is capped server-side, so `listed` can be smaller and then `truncated` is true
    (by_severity / by_rule only cover the listed items in that case)."""
    findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
    total = data["count"]
    sev_of = lambda f: str(f.get("risk") or f.get("severity") or "unrated")           # noqa: E731 -- ZAP says "risk", the others say "severity"
    rule_of = lambda f: str(f.get("rule") or f.get("name") or f.get("id") or "unknown")   # noqa: E731
    by_sev = Counter(sev_of(f) for f in findings)
    rules: dict = {}
    for f in findings:
        r = rules.setdefault(rule_of(f), {"rule": rule_of(f), "name": f.get("name") or f.get("message") or f.get("issue") or "", "severity": sev_of(f), "instances": 0})
        r["instances"] += 1
    summary = {"total": total, "listed": len(findings), "truncated": total > len(findings),
               "by_severity": dict(by_sev), "by_rule": sorted(rules.values(), key=lambda r: (-r["instances"], r["rule"]))}
    parts = ", ".join(f"{k} {v}" for k, v in sorted(by_sev.items(), key=lambda kv: -kv[1]))
    summary["tally_sentence"] = (f"{total} total" + (f" ({parts})" if parts and not summary["truncated"] else "")
                                 + (f"; only the first {len(findings)} are listed, so a breakdown beyond those is not available" if summary["truncated"] else ""))
    return summary


def _finish(tool: str, data: dict, ctx: dict) -> dict:
    """_note + exact tallies, and remembers the tally so create_word_document can check a report's numbers against what the scan really said."""
    data = _note(data)
    if data.get("ok") and isinstance(data.get("count"), int):
        data["summary"] = _tally(tool, data)
        data["note"] += (" Every number you state about this scan comes from `count`, `summary.total`, `summary.by_severity`, `summary.by_rule` or `summary.tally_sentence`"
                          " -- copy them exactly, never add up, recount or estimate yourself, and never leave a rule out of a report.")
        ctx.setdefault("tallies", {})[(tool, str(data.get("target") or data.get("target_url") or ""))] = data["summary"]
        if tool == "zap":
            ctx["last_zap"] = {"target": data.get("target_url"), **data["summary"], "active_scan_ran": bool(data.get("active_scan_ran")),
                               "tested_categories": data.get("tested_categories") or [],
                               "findings": [f for f in (data.get("findings") or []) if isinstance(f, dict)], "turn": ctx.get("turn_no")}
            data["note"] += (" Each finding has ONLY risk, name, rule and url. You were NOT given the evidence, the content of any flagged comment, the target's technology"
                              " or its server config -- if you want to say any of that, say 'the scan did not give me that detail' instead.")
    return data


def _populate_working_copy(name: str) -> str:
    """Right after a successful clone: copy the fresh pristine clone into the working copy the fixes are made in (and the static scanners re-scan).
    This is a fixed command that only differs by <name>; leaving it to the model cost a full round (17 s) at the start of every fix run. Returns
    a note for the model, or '' if it could not be done (the model then does it itself as before)."""
    from .sandbox_tools import _call as _sandbox_call
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name or ""):
        return ""
    out = _sandbox_call("POST", "/run", {"kind": "bash", "code": f"rm -rf /dynamic_target/{name} && cp -r /dynamic_pristine/{name} /dynamic_target/{name} && echo POPULATED", "name": "", "timeout": 30}, timeout=45)
    if "POPULATED" in json.dumps(out):
        tree = _source_tree(name)
        return (f"The working copy /dynamic_target/{name} is ALREADY populated from the fresh clone: do not run the cp yourself. "
                f"Go straight to reading the files you need and scanning target {name!r}. "
                + (f"Its source files (path, lines), so you do NOT need a find/ls round: {tree}" if tree else ""))
    return ""


def _source_tree(name: str, limit: int = 80) -> str:
    """A compact list of the clone's source files with line counts, so the model can go straight to `cat -n` of the files it needs (a real run spent a
    whole 47 s round on `find` just to learn the layout)."""
    from .sandbox_tools import _call as _sandbox_call
    code = (
        "import os\n"
        f"root = '/dynamic_target/{name}'\n"
        "skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.next'}\n"
        "ext = ('.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.css', '.conf', '.yml', '.yaml', '.json', '.sh', '.toml', '.txt', 'Dockerfile', '.env.example')\n"
        "rows = []\n"
        "for d, dirs, files in os.walk(root):\n"
        "    dirs[:] = sorted(x for x in dirs if x not in skip)\n"
        "    for f in sorted(files):\n"
        "        if f.endswith(ext) or f == 'Dockerfile':\n"
        "            p = os.path.join(d, f)\n"
        "            try:\n"
        "                n = sum(1 for _ in open(p, errors='replace'))\n"
        "            except OSError:\n"
        "                n = 0\n"
        "            rows.append('%s (%d)' % (os.path.relpath(p, root), n))\n"
        f"print('TREE', len(rows), '; '.join(rows[:{limit}]) + (' ...' if len(rows) > {limit} else ''))\n"
    )
    out = _sandbox_call("POST", "/run", {"kind": "python", "code": code, "name": "", "timeout": 20}, timeout=35)
    text = str(out.get("stdout") or "")
    return text.split("TREE", 1)[1].strip() if "TREE" in text else ""


def _with_populate(result_text: str) -> str:
    try:
        d = json.loads(result_text)
    except ValueError:
        return result_text
    if isinstance(d, dict) and d.get("ok") and d.get("name"):
        note = _populate_working_copy(str(d["name"]))
        if note:
            d["note"] = (str(d.get("note") or "") + " " + note).strip()
            d["working_copy_ready"] = True
        return json.dumps(d)
    return result_text


async def redteam_gitleaks(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("gitleaks", await _call("gitleaks", str(args.get("target") or "")), ctx))


async def redteam_bandit(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("bandit", await _call("bandit", str(args.get("target") or "")), ctx))


async def redteam_semgrep(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("semgrep", await _call("semgrep", str(args.get("target") or "")), ctx))


async def redteam_pip_audit(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("pip_audit", await _call("pip_audit", str(args.get("target") or "")), ctx))


async def redteam_npm_audit(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("npm_audit", await _call("npm_audit", str(args.get("target") or "")), ctx))


async def redteam_trivy(args: dict, ctx: dict) -> str:
    return _gate() or json.dumps(_finish("trivy", await _call("trivy", str(args.get("target") or "")), ctx))


async def redteam_clone_repo(args: dict, ctx: dict) -> str:
    """Clones a git repo (public or private) into the dynamic target pool so it can be scanned/fixed exactly like "self".

    For PUBLIC repos: just provide the URL.
    For PRIVATE repos: this will detect it's private and guide you through providing a GitHub Personal Access Token.

    Call this FIRST whenever the operator names a repo URL (not "self") -- it returns the target name to use for
    every later redteam_*/bash_run/export_project call afterward."""
    why = _gate()
    if why:
        return why
    url = str(args.get("url") or "").strip()
    if not url:
        return json.dumps({"ok": False, "error": "Say which repo URL to clone."})

    # First, check if repo is accessible
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0)) as c:
        check_r = await c.post(f"{URL}/check_repo_access", json={"url": url}, headers={"Authorization": f"Bearer {TOKEN}"})

    if check_r.status_code != 200:
        return json.dumps({"ok": False, "error": "Could not check repository accessibility"})

    check_result = check_r.json()

    if check_result.get("accessible"):
        # Public repo - clone directly
        async with httpx.AsyncClient(timeout=httpx.Timeout(130.0, connect=5.0)) as c:
            r = await c.post(f"{URL}/clone_target", json={"url": url, "name": str(args.get("name") or "")}, headers={"Authorization": f"Bearer {TOKEN}"})
        if r.status_code != 200:
            try:
                return json.dumps({"ok": False, "error": r.json().get("detail") or f"HTTP {r.status_code}"})
            except ValueError:
                return json.dumps({"ok": False, "error": f"the clone server answered HTTP {r.status_code}"})
        return _with_populate(r.text)

    # Handle different error types
    error_type = check_result.get("error_type")

    if error_type == "network":
        return json.dumps({"ok": False,
                          "error": "Cannot reach GitHub right now. Please check if GitHub is accessible or if there's a network issue on my server.",
                          "error_type": "network"})

    elif error_type == "auth":
        # Private repo or authentication needed
        msg = """This appears to be a private GitHub repository. To access it, I need a GitHub Personal Access Token (PAT) with READ access.

Create a PAT at: https://github.com/settings/tokens/new
Required scope: 'repo' (read-only access)

Once you have the token:
1. Write it to a file where my container can read it
2. Provide the full file path (e.g., /home/ubuntu/token.txt)

The token will be read once for this clone only.

After providing the token file, use the 'redteam_clone_private_repo' tool with the URL and token file path."""
        return json.dumps({"ok": False,
                          "error": "Private repository - authentication required",
                          "error_type": "auth",
                          "message": msg})

    elif error_type == "invalid":
        return json.dumps({"ok": False,
                          "error": "The repository URL appears to be invalid. Please verify the URL is correct.",
                          "error_type": "invalid"})

    else:
        return json.dumps({"ok": False,
                          "error": f"Could not access repository: {check_result.get('error', 'Unknown error')}",
                          "error_type": "unknown"})


async def redteam_clone_private_repo(args: dict, ctx: dict) -> str:
    """Clones a PRIVATE git repository using a GitHub Personal Access Token read from a file.

    Use this after redteam_clone_repo tells you a repo is private. You need:
    - url: The GitHub repository URL
    - token_file: Full path to a file containing your GitHub PAT (e.g., /home/ubuntu/token.txt)

    The token is read once and not stored."""
    why = _gate()
    if why:
        return why

    url = str(args.get("url") or "").strip()
    token_file = str(args.get("token_file") or "").strip()

    if not url:
        return json.dumps({"ok": False, "error": "Provide the repository URL"})
    if not token_file:
        return json.dumps({"ok": False, "error": "Provide the path to the token file"})

    async with httpx.AsyncClient(timeout=httpx.Timeout(130.0, connect=5.0)) as c:
        r = await c.post(f"{URL}/clone_with_token",
                        json={"url": url, "token_file": token_file, "name": str(args.get("name") or "")},
                        headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        try:
            return json.dumps({"ok": False, "error": r.json().get("detail") or f"HTTP {r.status_code}"})
        except ValueError:
            return json.dumps({"ok": False, "error": f"the clone server answered HTTP {r.status_code}"})

    return _with_populate(r.text)


async def _call_zap_streaming(target_url: str, emit) -> dict:
    """Like _call, but for /zap specifically: the server streams one NDJSON line per real step instead of one atomic result. Each {"progress": ...}
    line is relayed live via emit() the instant it arrives (the terminal pane); the one {"final": true, ...} line is the return value. emit may be
    None (no live channel, e.g. plain CLI use) -- progress lines are then just dropped, same end result."""
    final = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(620.0, connect=5.0)) as c:
        async with c.stream("POST", f"{URL}/zap", json={"target_url": target_url}, headers={"Authorization": f"Bearer {TOKEN}"}) as r:
            if r.status_code != 200:
                return {"ok": False, "error": f"the scanner answered HTTP {r.status_code}"}
            async for raw_line in r.aiter_lines():
                if not raw_line.strip():
                    continue
                try:
                    obj = json.loads(raw_line)
                except ValueError:
                    continue
                if obj.get("final"):
                    final = obj
                elif emit is not None:
                    try:
                        await emit("pentest_zap", str(obj.get("progress") or ""))
                    except Exception:
                        pass
    return final if final is not None else {"ok": False, "error": "the scanner stream ended with no final result"}


async def pentest_zap(args: dict, ctx: dict) -> str:
    """Spider + passive + active (attacking) OWASP ZAP scan against a target_url the operator names -- a target they've stood up themselves.
    Naming a URL here at all is the operator's own explicit, scoped consent (see redteam/server.py's _zap_target_ok); the only thing refused
    regardless of intent is the cloud-metadata address."""
    why = _gate()
    if why:
        return why
    return json.dumps(_finish("zap", await _call_zap_streaming(str(args.get("target_url") or ""), ctx.get("emit_terminal_progress")), ctx))


async def _call_lateral_movement_streaming(target_url: str, session_cookie: str, emit) -> dict:
    """Like _call_zap_streaming, for /zap_lateral_movement: part of the ethical_hack skill. Only call this AFTER you have already patched the
    target's own auth code, restarted it, and logged in to capture a real session_cookie -- this endpoint measures what that cookie can reach,
    it does not bypass anything itself."""
    final = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(620.0, connect=5.0)) as c:
        async with c.stream("POST", f"{URL}/zap_lateral_movement", json={"target_url": target_url, "session_cookie": session_cookie},
                             headers={"Authorization": f"Bearer {TOKEN}"}) as r:
            if r.status_code != 200:
                return {"ok": False, "error": f"the scanner answered HTTP {r.status_code}"}
            async for raw_line in r.aiter_lines():
                if not raw_line.strip():
                    continue
                try:
                    obj = json.loads(raw_line)
                except ValueError:
                    continue
                if obj.get("final"):
                    final = obj
                elif emit is not None:
                    try:
                        await emit("pentest_lateral_movement", str(obj.get("progress") or ""))
                    except Exception:
                        pass
    return final if final is not None else {"ok": False, "error": "the scanner stream ended with no final result"}


async def pentest_lateral_movement(args: dict, ctx: dict) -> str:
    """ethical_hack skill only: given target_url (the running sandboxed app) and session_cookie (a real "name=value" cookie you captured by
    logging in through your own auth-bypass patch), measures the real difference between what an unauthenticated crawl reaches and what the
    authenticated session reaches, then actively scans the newly-reachable pages. Never call this with a cookie you have not actually captured
    from a real login response -- a made-up cookie just proves nothing new is reachable, which is not evidence of anything."""
    why = _gate()
    if why:
        return why
    target_url = str(args.get("target_url") or "").strip()
    session_cookie = str(args.get("session_cookie") or "").strip()
    if not target_url or not session_cookie:
        return json.dumps({"ok": False, "error": "target_url and session_cookie (a real captured 'name=value' cookie) are both required."})
    result = await _call_lateral_movement_streaming(target_url, session_cookie, ctx.get("emit_terminal_progress"))
    result["note"] = (result.get("note", "") + " These are the exact, recorded results of a real crawl+scan just now. Report the counts and "
                       "the new_pages_after_breach list exactly as given; never invent a page not in that list.")
    return json.dumps(result)


async def check_scanner_versions(args: dict, ctx: dict) -> str:
    """Checks if any of the security scanning tools (gitleaks, Bandit, Semgrep, pip-audit, Trivy, ZAP, npm) have newer
    versions available. Returns current vs latest version for each tool. Call this during your initial greeting to report
    tool recency status."""
    why = _gate()
    if why:
        return why

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)) as c:
        r = await c.get(f"{URL}/scanner_versions", headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        return json.dumps({"ok": False, "error": f"version check failed: HTTP {r.status_code}"})

    return r.text


async def cleanup_redteam_scratch(args: dict, ctx: dict) -> str:
    """Deletes every clone currently sitting in the redteam container's own clone-staging directory (/dynamic_pristine_rw) -- nothing in
    there is reused across a browser session, so anything found here on startup is an orphan left behind by a previous session. Called
    deterministically in code at the start of every new session (see web.py), alongside cleanup_sandbox_scratch and check_scanner_versions,
    not something the model needs to call itself."""
    why = _gate()
    if why:
        return why

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0)) as c:
        r = await c.post(f"{URL}/cleanup_targets", headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        return json.dumps({"ok": False, "error": f"cleanup failed: HTTP {r.status_code}"})

    return r.text
