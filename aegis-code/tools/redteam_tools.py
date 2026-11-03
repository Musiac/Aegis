"""Thin client in front of the `aegis-libraries` container (see ../../aegis-libraries/): a bearer-token API, --network none, which scans only a pre-mounted
READ-ONLY copy of source. The tool here only forwards a named target and the tool name; it cannot send a path, a command or anything else
the server would act on. Aegis is a single-operator tool (no accounts), so unlike a larger multi-account assistant there is no owner/admin role check here --
the only gate is whether the server is actually configured (a token present)."""
import asyncio
import json
import re
import os
import time
from collections import Counter

import httpx

from .narration import narrate

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


async def _populate_working_copy(name: str, ctx: dict = None, force: bool = False) -> str:
    """Right after a successful clone: copy the fresh pristine clone into the working copy the fixes are made in (and the static scanners
    re-scan). This is a fixed command that only differs by <name>; leaving it to the model cost a full round (17 s) at the start of every fix
    run. Returns a note for the model, or '' if it could not be done (the model then does it itself as before).

    GUARDED against re-wiping real fix progress (added 2026-10-30, real incident: mid-run on aws/sagemaker-python-sdk, after hitting a real
    disk error, the model called redteam_clone_repo a second time for a name it had already been fixing for over an hour -- this unconditional
    rm -rf/cp -r silently discarded every edit_file fix already applied, and bandit's count reverted from 1 back to 334 with no warning at all.
    Now: if `name` is already marked populated in THIS session's ctx (set the first time this ever ran for it), the destructive repopulate is
    SKIPPED and the existing working copy -- real fixes included -- is kept, unless `force=True` is explicitly passed (meaning the caller
    asked for a genuine fresh reset, e.g. redteam_clone_repo was called with reset=true)."""
    from .sandbox_tools import _call as _sandbox_call
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name or ""):
        return ""
    populated = ctx.setdefault("dynamic_targets_populated", set()) if ctx is not None else None
    if populated is not None and name in populated and not force:
        return (f"NOTE: /dynamic_target/{name} already exists from an EARLIER clone this session and was NOT re-populated from pristine -- "
                f"any fixes already applied to it are preserved. Re-scan/continue working on it as-is. If you genuinely need a fresh, "
                f"unmodified copy (discarding any fixes already made), call redteam_clone_repo again with reset=true -- but that is a real, "
                f"irreversible loss of whatever work is there now, so only do it if the operator asked for a clean restart.")
    out = await _sandbox_call("POST", "/run", {"kind": "bash", "code": f"rm -rf /dynamic_target/{name} && cp -r /dynamic_pristine/{name} /dynamic_target/{name} && echo POPULATED", "name": "", "timeout": 30}, timeout=45)
    if "POPULATED" in json.dumps(out):
        if populated is not None:
            populated.add(name)
        tree = await _source_tree(name)
        return (f"The working copy /dynamic_target/{name} is ALREADY populated from the fresh clone: do not run the cp yourself. "
                f"Go straight to reading the files you need and scanning target {name!r}. "
                + (f"Its source files (path, lines), so you do NOT need a find/ls round: {tree}" if tree else ""))
    return ""


async def _source_tree(name: str, limit: int = 80) -> str:
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
    out = await _sandbox_call("POST", "/run", {"kind": "python", "code": code, "name": "", "timeout": 20}, timeout=35)
    text = str(out.get("stdout") or "")
    return text.split("TREE", 1)[1].strip() if "TREE" in text else ""


async def _with_populate(result_text: str, ctx: dict = None, force: bool = False) -> str:
    try:
        d = json.loads(result_text)
    except ValueError:
        return result_text
    if isinstance(d, dict) and d.get("ok") and d.get("name"):
        note = await _populate_working_copy(str(d["name"]), ctx, force)
        if note:
            d["note"] = (str(d.get("note") or "") + " " + note).strip()
            d["working_copy_ready"] = True
        return json.dumps(d)
    return result_text


async def _narrated_scan(tool: str, ctx: dict, target: str) -> str:
    """Shared body for every static scanner tool (added 2026-10-30): narrates the phase to the terminal pane before/after the real
    call, from the scanner's own result -- never the model's own words."""
    why = _gate()
    if why:
        return why
    await narrate(ctx, f"Now running the {tool} static scan on {target or 'the local clone'}.")
    data = _finish(tool, await _call(tool, target), ctx)
    ctx.pop("_fix_narrated_this_turn", None)   # a fresh result set to fix -- let "now fixing" announce again for it
    if data.get("ok"):
        summ = data.get("summary") or {}
        await narrate(ctx, f"Static scan ({tool}) results for {target or 'the local clone'}: {summ.get('tally_sentence', str(data.get('count', '?')) + ' total')}.")
        if data.get("count") == 0:
            await narrate(ctx, f"No {tool} findings to fix.")
    else:
        await narrate(ctx, f"Static scan ({tool}) on {target or 'the local clone'} failed: {data.get('error', 'unknown error')}.")
    return json.dumps(data)


async def redteam_gitleaks(args: dict, ctx: dict) -> str:
    return await _narrated_scan("gitleaks", ctx, str(args.get("target") or ""))


async def redteam_bandit(args: dict, ctx: dict) -> str:
    return await _narrated_scan("bandit", ctx, str(args.get("target") or ""))


async def redteam_semgrep(args: dict, ctx: dict) -> str:
    return await _narrated_scan("semgrep", ctx, str(args.get("target") or ""))


async def redteam_pip_audit(args: dict, ctx: dict) -> str:
    return await _narrated_scan("pip_audit", ctx, str(args.get("target") or ""))


async def redteam_npm_audit(args: dict, ctx: dict) -> str:
    return await _narrated_scan("npm_audit", ctx, str(args.get("target") or ""))


async def redteam_trivy(args: dict, ctx: dict) -> str:
    return await _narrated_scan("trivy", ctx, str(args.get("target") or ""))


async def redteam_check_repo_size(args: dict, ctx: dict) -> str:
    """Checks a github.com repo's real size via GitHub's own API -- NO clone performed. Call this BEFORE redteam_clone_repo for any repo you
    are not already confident is small. Then call check_sandbox_capacity (sandbox tool) to see the current /REPL quota and how much of it is
    already used. If the repo's size_mb would not comfortably fit (quota minus already-used scratch), you MUST stop and tell the operator the
    exact numbers (repo size, current quota, free headroom) and ask explicitly whether to raise the quota before cloning -- never clone
    anyway and hope, and never raise the quota yourself without them saying yes. If they say yes, call increase_sandbox_capacity with a
    reasonable size (comfortably above the repo's size_mb, but not wastefully large), then proceed with the clone. If they say no, stop this
    task entirely and do not clone. Only github.com URLs are supported; for any other host, say plainly that size cannot be pre-checked and
    ask the operator whether to proceed anyway, same spirit as the oversized-repo case."""
    why = _gate()
    if why:
        return why
    url = str(args.get("url") or "").strip()
    if not url:
        return json.dumps({"ok": False, "error": "Say which repo URL to check."})
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)) as c:
        r = await c.post(f"{URL}/check_repo_size", json={"url": url}, headers={"Authorization": f"Bearer {TOKEN}"})
    if r.status_code != 200:
        try:
            return json.dumps({"ok": False, "error": r.json().get("detail") or f"HTTP {r.status_code}"})
        except ValueError:
            return json.dumps({"ok": False, "error": f"the size check answered HTTP {r.status_code}"})
    return r.text


async def redteam_clone_repo(args: dict, ctx: dict) -> str:
    """Clones a git repo (public or private) into the dynamic target pool so it can be scanned/fixed exactly like "self".

    For PUBLIC repos: just provide the URL.
    For PRIVATE repos: this will detect it's private and guide you through providing a GitHub Personal Access Token.

    Call this FIRST whenever the operator names a repo URL (not "self") -- it returns the target name to use for
    every later redteam_*/bash_run/export_project call afterward. If you have not already checked this repo's size with
    redteam_check_repo_size + check_sandbox_capacity in THIS conversation, do that first -- a repo that doesn't fit the sandbox's current
    scratch quota will fail mid-work (fixes already applied can be lost to a "/REPL is full" error) rather than failing cleanly up front.

    If this exact repo was ALREADY cloned earlier in this conversation, calling this again does NOT wipe any fixes already applied to it --
    the existing working copy (with its real fixes) is kept as-is, you're just told its name again. Pass reset=true ONLY if the operator
    explicitly asked to discard existing work and start this repo completely fresh -- that genuinely and irreversibly throws away any fixes
    already made to it."""
    why = _gate()
    if why:
        return why
    url = str(args.get("url") or "").strip()
    if not url:
        return json.dumps({"ok": False, "error": "Say which repo URL to clone."})
    await narrate(ctx, f"Now cloning {url}.")

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
        return await _with_populate(r.text, ctx, force=bool(args.get("reset")))

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

    The token is read once and not stored. If this exact repo/name was already cloned earlier in this conversation, calling this again does
    NOT wipe any fixes already applied -- the existing working copy is kept. Pass reset=true only for a genuine, explicit, discard-and-start-
    over request."""
    why = _gate()
    if why:
        return why

    url = str(args.get("url") or "").strip()
    token_file = str(args.get("token_file") or "").strip()

    if not url:
        return json.dumps({"ok": False, "error": "Provide the repository URL"})
    if not token_file:
        return json.dumps({"ok": False, "error": "Provide the path to the token file"})
    # Refuse BEFORE cloning, not after (added 2026-10-30, the operator's own request: warn as early as possible --
    # ideally before any private code ever leaves the operator's control, ONLY falling back to a post-clone warning
    # when visibility becomes known some other way, e.g. mid-turn via a scanner call on "self"). This is the one
    # tool call that KNOWINGLY clones something private, so it is the one place a pre-clone refusal is possible at
    # all -- redteam_clone_repo itself never clones a private repo (it just detects one and asks for a token file).
    if ctx.get("force_model_override") == "muse-spark-1.3-contributor" and not ctx.get("_contributor_private_ok"):
        ctx["_pending_private_clone_warning"] = True
        # Sent directly as a real {"type":"warn"} message (red), not relayed through the model's own chat text (fixed
        # 2026-10-30, a real incident: the model reciting this itself goes out as plain chat, not styled, so the operator
        # only ever saw the real red warning -- and a working confirm gate -- on a SECOND attempt).
        emit_warn = ctx.get("emit_warn")
        if emit_warn:
            await emit_warn("WARNING: You have chosen the Contributor (cheapest) model for this private repo task. Your data "
                             "may be used for Meta's training. Should I go ahead?")
        return json.dumps({"ok": False, "error": "Do not clone this yet.",
                            "note": "STOP here -- do not call redteam_clone_private_repo or any other tool this round. The "
                                    "operator has already been shown the warning directly (in red) -- just say in ONE short "
                                    "sentence that you're waiting for their answer, then end your turn."})
    await narrate(ctx, f"Now cloning {url} (private repo).")

    async with httpx.AsyncClient(timeout=httpx.Timeout(130.0, connect=5.0)) as c:
        r = await c.post(f"{URL}/clone_with_token",
                        json={"url": url, "token_file": token_file, "name": str(args.get("name") or "")},
                        headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        try:
            return json.dumps({"ok": False, "error": r.json().get("detail") or f"HTTP {r.status_code}"})
        except ValueError:
            return json.dumps({"ok": False, "error": f"the clone server answered HTTP {r.status_code}"})

    return await _with_populate(r.text, ctx, force=bool(args.get("reset")))


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
    Naming a URL here at all is the operator's own explicit, scoped consent (see aegis-libraries/redteam_server.py's _zap_target_ok); the only thing refused
    regardless of intent is the cloud-metadata address."""
    why = _gate()
    if why:
        return why
    target_url = str(args.get("target_url") or "")
    await narrate(ctx, f"Now running the active pentest (ZAP spider, passive scan, and active attacking scan) on {target_url or 'the server'}.")
    data = _finish("zap", await _call_zap_streaming(target_url, ctx.get("emit_terminal_progress")), ctx)
    ctx.pop("_fix_narrated_this_turn", None)   # a fresh result set to fix -- let "now fixing" announce again for it
    if data.get("ok"):
        summ = data.get("summary") or {}
        await narrate(ctx, f"Active pentest results for {target_url or 'the server'}: {summ.get('tally_sentence', str(data.get('count', '?')) + ' total')}.")
        if data.get("count") == 0:
            await narrate(ctx, "All issues from the passive and active scans have been fixed.")
    else:
        await narrate(ctx, f"Active pentest on {target_url or 'the server'} did not complete: {data.get('error', 'unknown error')}.")
    return json.dumps(data)


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
    versions available -- and, if any are outdated, updates them immediately, live, with no operator confirmation
    needed (owner's own instruction, 2026-10-31: there is no real scenario where the operator would ever say no to
    a tool update, so asking first just adds a wasted round-trip). This is deterministic in CODE, not a model
    decision to call update_scanner_tools afterward -- same reason check_scanner_versions moved out of a
    prompt-only "also call this tool" instruction on 2026-10-30 (see _maybe_announce_muse_billing's own comment):
    a model-side "also do X" instruction has been observed live to simply not fire reliably, and this auto-update
    is exactly as load-bearing as that version check itself. Call this during your initial greeting, or whenever
    the operator asks about tool recency -- either way it already did the work by the time you see the result.
    update_scanner_tools stays separately callable too, for an explicit re-run on specific tools."""
    why = _gate()
    if why:
        return why

    # 120 s read timeout (was 15 s, 2026-11-03): on a first run, or on a slow machine, the scanner container is cold -- it is still
    # starting up or loading its tools -- and the old 15 s limit surfaced as a raw "ReadTimeout" in the chat. wait_for_scanner_tools
    # below retries around this call for the first-run case.
    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as c:
        r = await c.get(f"{URL}/scanner_versions", headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        return json.dumps({"ok": False, "error": f"version check failed: HTTP {r.status_code}"})

    before = r.json()
    # outdated_count/outdated_tools are computed by CODE, from the same list the model is about to read -- a
    # number for it to count its own reported lines against, the same "exact tally it must copy, never recount
    # or guess" pattern _tally() uses for scan findings elsewhere in this file. Found live 2026-10-30, right after
    # the automatic greeting was shortened: a prose-only instruction (no computed count to check against) reported
    # just the FIRST outdated tool with no version numbers at all when only one happened to be behind -- a plain
    # "report every outdated tool" instruction is easy to silently satisfy with one tool and still read as complete.
    outdated = [t for t in before.get("tools", []) if t.get("status") not in ("latest", "system-managed")]
    before["outdated_count"] = len(outdated)
    before["outdated_tools"] = [t.get("name") for t in outdated]

    if not outdated:
        before["note"] = (
            f"outdated_count is 0 -- computed by code from this SAME result, not your own count. Your reply MUST "
            "list EVERY tool from `tools`, one per line, in the order given, as '<name> <current> (latest)' or "
            "'<name> <current> (system-managed)'. Use the real current values from this result exactly, never "
            "invent, round or recall them from memory."
        )
        return json.dumps(before)

    ctx["_scanner_update_started"] = True     # a timeout from here on means the update is probably still running: wait for it, do not start another
    update_result = await update_scanner_tools({"tools": before["outdated_tools"]}, ctx)
    after = json.loads(update_result)
    ctx["_scanner_update_started"] = False
    after["before"] = before
    after["note"] = (
        f"Found {len(outdated)} outdated tool(s) ({before['outdated_tools']}) and updated them immediately, with "
        "no operator confirmation needed -- this already happened, it is not a plan. Your reply MUST, in order: "
        "(1) for EACH tool that was found outdated, one line in the shape 'Found <name> <old_version> to be "
        "outdated (latest is <new_version>) -- updating now.' using the REAL before-values from `before.tools` "
        "and after-values from `versions.tools` below, never invented; (2) then one line per tool from "
        "`versions.tools` (every tool, not just the ones just updated), each as '<name> <current> (latest)' or, "
        "for any tool `attempted` above marked ok:false, '<name> <current> -- update failed: <error>, still "
        "outdated'. Never claim a tool updated cleanly if its own `attempted` entry says ok:false."
    )
    return json.dumps(after)


class ScannerSetupTimeout(Exception):
    """The scanner container did not become ready within the allowed time."""


_RETRYABLE = (httpx.TimeoutException, httpx.TransportError)


async def _outdated_count() -> int:
    """GET-only look at how many scanner tools are still behind. Never starts an update."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as c:
        r = await c.get(f"{URL}/scanner_versions", headers={"Authorization": f"Bearer {TOKEN}"})
    if r.status_code != 200:
        raise httpx.TransportError(f"HTTP {r.status_code}")
    tools = r.json().get("tools", [])
    return len([t for t in tools if t.get("status") not in ("latest", "system-managed")])


async def wait_for_scanner_tools(ctx: dict, say=None, max_wait_s: float = 1500.0) -> str:
    """check_scanner_versions, made patient (2026-11-03). On a first run the scanner container can still be starting, or busy installing
    its first set of tool updates, for several minutes. This keeps trying, tells the operator once, in plain words, that the wait is
    normal, and reports progress through `say(text)` every ~20 s so the page never looks hung. It never starts a second update while the
    first is still running. Raises ScannerSetupTimeout only after max_wait_s (25 minutes)."""
    started = time.monotonic()
    last_tick = started
    told = False

    async def _say(text: str) -> None:
        if say:
            await say(text)

    attempt = 0
    watch_since = None
    while True:
        attempt += 1
        try:
            if ctx.get("_scanner_update_started"):
                # An update is already running on the server: only watch it, never start another -- but if it has not finished after
                # 10 minutes it most likely died, so allow one fresh attempt.
                watch_since = watch_since or time.monotonic()
                if await _outdated_count() == 0 or time.monotonic() - watch_since > 600:
                    ctx["_scanner_update_started"] = False
                    watch_since = None
                    continue
            else:
                return await check_scanner_versions({}, ctx)
        except _RETRYABLE:
            pass
        except json.JSONDecodeError:
            pass
        waited = time.monotonic() - started
        if waited > max_wait_s:
            raise ScannerSetupTimeout(f"scanner tools were not ready after {int(waited)} seconds")
        if not told:
            told = True
            await _say("First-time setup: I am getting my scanner tools ready. This only happens the first time and can take several minutes. "
                       "You do not need to refresh this page -- I will keep going and tell you when I am ready.")
        if time.monotonic() - last_tick >= 20:
            last_tick = time.monotonic()
            await _say(f"Still preparing my scanner tools ({int(waited)} s so far)...")
        await asyncio.sleep(min(3 + attempt * 2, 15))


async def prepare_scanner_databases() -> dict:
    """Asks the scanner container to download Trivy's vulnerability database now (see /prepare_databases there). Used by install-time first-run
    setup so the first real container scan does not have to. Returns the server's JSON answer; never raises on an HTTP error status."""
    why = _gate()
    if why:
        return json.loads(why)
    async with httpx.AsyncClient(timeout=httpx.Timeout(1300.0, connect=10.0)) as c:
        r = await c.post(f"{URL}/prepare_databases", headers={"Authorization": f"Bearer {TOKEN}"})
    if r.status_code != 200:
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    return r.json()


async def update_scanner_tools(args: dict, ctx: dict) -> str:
    """Actually upgrades the named tool(s), live, in the aegis-libraries container -- real pip installs / binary
    downloads into its host-mounted /tool_updates (see aegis-libraries/redteam_server.py's own module comment for
    why that's safe without touching its read-only root, AND why it's a real, permanent update, not a
    session-only one), never a claim without a real action behind it. check_scanner_versions already calls this
    itself the moment it finds anything outdated (2026-10-31, owner's own instruction: no operator confirmation
    needed first) -- this stays separately callable for an explicit re-run on specific tools, e.g. if the
    operator names one directly."""
    why = _gate()
    if why:
        return why
    tools = args.get("tools") or []
    if not isinstance(tools, list) or not tools:
        return json.dumps({"ok": False, "error": "tools must be a non-empty list of real tool names from outdated_tools"})

    # /update_tools processes tools ONE AT A TIME, not concurrently -- this must stay comfortably above the sum of
    # every tool's own worst-case time (aegis-libraries/redteam_server.py's own pip-install timeout is 240s per tool), or this
    # outer call times out first and masks the real per-tool error/result that endpoint would otherwise return.
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0 + 240.0 * len(tools), connect=5.0)) as c:
        r = await c.post(f"{URL}/update_tools", json={"tools": tools}, headers={"Authorization": f"Bearer {TOKEN}"})

    if r.status_code != 200:
        return json.dumps({"ok": False, "error": f"update failed: HTTP {r.status_code}"})

    data = r.json()
    attempted = data.get("attempted") or []
    all_ok = bool(attempted) and all(a.get("ok") for a in attempted)
    failed = [a.get("name") for a in attempted if not a.get("ok")]
    data["note"] = (
        "These are the exact, recorded results of a real update attempt just now, not a description. "
        + (
            "Every tool updated cleanly: reply with something short like \"Done. All updated. Ready for your next task.\""
            if all_ok else
            f"At least one tool did NOT update cleanly ({failed}). Do not claim success for those -- name which tool(s) "
            "failed and report the REAL current vs latest from `versions.tools` (the result of the automatic re-check "
            "this endpoint already ran) for whichever are still outdated, then say you're ready for the operator's "
            "task anyway, using the existing versions."
        )
    )
    return json.dumps(data)


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
