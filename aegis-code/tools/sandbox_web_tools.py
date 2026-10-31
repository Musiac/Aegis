"""sandbox_app_start / sandbox_app_restart / sandbox_app_stop / sandbox_app_status -- control the REAL server of a cloned-and-fixed project so an
active ZAP pentest has something genuinely running to attack. Added 2026-10-26 (see sandbox_web/control.py's own docstring for the full design and
why "start the cloned code's server and pentest it" was not actually possible before this).

Talks over plain HTTP to aegis-sandbox-web's control plane (sandbox_web/control.py), reachable on aegis-net by container name. That
container also answers to the alias www.sandbox.com on port 8900 -- the address pentest_zap's target_url should name once the app is running.
"""
import json

import httpx

from . import trio_client
from .narration import narrate

CONTROL_URL = "http://aegis-sandbox-web:7999"
APP_HOST = "www.sandbox.com"
APP_PORT = 8900
STUB_PORT = 8901


async def _raw_call(path: str, body: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=5.0)) as c:
        r = (await c.post(f"{CONTROL_URL}{path}", json=body or {})) if body is not None else (await c.get(f"{CONTROL_URL}{path}"))
    return r.json()


async def _call(path: str, body: dict = None) -> dict:
    try:
        result = await _raw_call(path, body)
        trio_client.touch()
        return result
    except httpx.HTTPError:
        # Same ephemeral-trio lazy-start as sandbox_tools.py's _call: aegis-sandbox-web not answering is the
        # normal state between tasks, not an error -- start the trio and retry exactly once.
        started = trio_client.start_trio()
        if not started.get("ok"):
            return {"ok": False, "error": f"Could not start the code sandbox: {started.get('error', 'unknown error')}"}
        try:
            result = await _raw_call(path, body)
            trio_client.touch()
            return result
        except httpx.HTTPError as e:
            return {"ok": False, "error": f"could not reach the sandbox-web control plane after starting it ({type(e).__name__})."}


def _note(d: dict, verb: str) -> dict:
    if d.get("ok") and "project" in d:
        d["note"] = (f"The app is now reachable INSIDE the sandbox network at http://{APP_HOST}:{APP_PORT}/ -- use that exact address as "
                      f"pentest_zap's target_url. {verb} succeeded; report it plainly, including any 'error' field here even when ok is true "
                      f"(e.g. it started but is not answering yet). A local OpenAI-compatible stub is already reachable at "
                      f"http://{APP_HOST}:{STUB_PORT}/v1 -- the app's OPENAI_API_KEY/OPENAI_BASE_URL env vars were automatically pointed at "
                      f"it (only when not already set to something real), so if its code calls the OpenAI SDK it gets a canned, schema-"
                      f"valid reply (plain or streaming) instead of failing on a missing/unreachable key -- no action needed unless the app "
                      f"hardcodes its own OpenAI client config and ignores those env vars, which you'd see as a startup/runtime error "
                      f"mentioning OpenAI auth or connectivity despite the stub being up.")
    return d


def _mark_running(ctx: dict, project: str, ok: bool) -> None:
    """Tracked so a Word report's own code (doc_tools._deliver) can guarantee the sandboxed app is stopped once the report is real, even if
    the model never calls sandbox_app_stop itself -- a real run (2026-10-26, Strix) stopped the app on its own initiative right after the last
    re-pentest, BEFORE export_project/create_word_document, instead of after the report as asked; wording alone did not reliably hold that
    ordering, so it is enforced here structurally instead."""
    if ok:
        ctx["sandbox_app_running"], ctx["sandbox_app_project"] = True, project
    ctx.pop("sandbox_app_turn", None)


async def sandbox_app_start(args: dict, ctx: dict) -> str:
    """Starts the REAL web server of a cloned (and possibly already-fixed) project, so pentest_zap has a live target at
    http://www.sandbox.com:8900/. project: the clone's name (from redteam_clone_repo/redteam_clone_private_repo's result), or "self". Stops
    whatever app was already running first -- only one runs at a time. Only works for a project shaped like Aegis's own convention
    (backend/web.py, `uvicorn backend.web:app`) unless you pass cmd with an explicit start command for that project instead.

    Before launching, this installs the project's OWN declared dependencies (requirements.txt, or an editable install if it has a
    pyproject.toml/setup.py instead) -- real pip install, real outbound internet, in the sandbox-web container (NOT the code sandbox).
    This happens automatically; pass install=false only if you already know the project needs no install step (e.g. you just confirmed its
    deps are already satisfied) and want to skip the time cost. The result's install_log field shows what pip actually did -- read it before
    concluding why a start failed; a ModuleNotFoundError after this means the install itself failed or the module isn't declared in
    requirements.txt/pyproject.toml, not that this step didn't run."""
    project = str(args.get("project") or "").strip()
    if not project:
        return json.dumps({"ok": False, "error": "Say which project to start (the clone's name, or \"self\")."})
    install = args.get("install")
    do_install = True if install is None else bool(install)
    await narrate(ctx, f"Now checking whether {project} has a server component.")
    if do_install:
        await narrate(ctx, f"Yes -- {project} has a server component. Now installing the dependencies it declares.")
    await narrate(ctx, f"Now starting {project}'s server in the locked sandbox.")
    result = _note(await _call("/start", {"project": project, "cmd": str(args.get("cmd") or ""), "install": do_install}), "start")
    if result.get("ok"):
        await narrate(ctx, f"{project}'s server is up. If it calls the OpenAI API, the simulated OpenAI API server already running in "
                           f"the locked sandbox (http://{APP_HOST}:{STUB_PORT}/v1) will answer it.")
    else:
        await narrate(ctx, f"No server component could be started for {project}: {result.get('error', 'unknown error')}.")
    _mark_running(ctx, project, bool(result.get("ok")))
    return json.dumps(result)


async def sandbox_app_restart(args: dict, ctx: dict) -> str:
    """Restarts the sandboxed app from the project's CURRENT working copy -- call this after writing a fix, right before re-running pentest_zap,
    so the re-scan is against the fixed code, not the one still in memory from before the edit. Same arguments as sandbox_app_start."""
    project = str(args.get("project") or "").strip()
    if not project:
        return json.dumps({"ok": False, "error": "Say which project to restart (the clone's name, or \"self\")."})
    install = args.get("install")
    await narrate(ctx, f"Now restarting {project}'s server in the locked sandbox with the fix applied.")
    result = _note(await _call("/restart", {"project": project, "cmd": str(args.get("cmd") or ""),
                                             "install": True if install is None else bool(install)}), "restart")
    if not result.get("ok"):
        await narrate(ctx, f"{project}'s server could not be restarted: {result.get('error', 'unknown error')}.")
    _mark_running(ctx, project, bool(result.get("ok")))
    return json.dumps(result)


async def sandbox_app_stop(args: dict, ctx: dict) -> str:
    """Stops the sandboxed app. You do NOT need to remember to call this before the Word report: create_word_document stops it automatically,
    in code, the moment the report is actually created, whether or not you call this yourself. Call it directly only if you want it stopped
    sooner than that (e.g. the operator asked you not to fix anything after all)."""
    ctx["sandbox_app_running"] = False
    await narrate(ctx, "Now stopping the sandbox environment.")
    return json.dumps(await _call("/stop", {}))     # {} (not None) so _call POSTs -- control.py only serves /stop under POST


async def ensure_stopped_after_report(ctx: dict) -> str:
    """Called by doc_tools._deliver right after a Word document is actually sent -- the one guaranteed stop point, independent of whether (or
    when) the model itself called sandbox_app_stop this turn. Returns a short note for the report's own 'what I made' block, or "" if there
    was nothing to stop."""
    if not ctx.get("sandbox_app_running"):
        return ""
    project = ctx.get("sandbox_app_project") or ""
    ctx["sandbox_app_running"] = False
    await narrate(ctx, "Now stopping the sandbox environment.")
    result = await _call("/stop", {})
    return (f"The temporary sandbox server ({project}, http://{APP_HOST}:{APP_PORT}/) has been stopped."
            if result.get("ok") else f"Tried to stop the temporary sandbox server ({project}) but it answered: {result.get('error', result)}")


async def sandbox_app_status(args: dict, ctx: dict) -> str:
    """Whether a sandboxed app is running right now, which project, and its recent output -- check this if a start/restart looked uncertain."""
    return json.dumps(await _call("/status"))
