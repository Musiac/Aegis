#!/usr/bin/env python3
"""Aegis's CLI: the thin chat loop that ties the 3 tool containers (redteam, sandbox, pentestlive) into an actual conversation. Reads
.env for the LLM provider (set AEGIS_PROVIDER, or it picks the first one with a key configured) and the tool-server tokens/URLs (read
directly by backend/tools/*.py via their own env vars). Shares its actual loop logic with the web UI -- see core.py."""
import asyncio
import base64
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .core import ProviderError, new_session, pick_provider, run_turn
from .tools.redteam_tools import cleanup_redteam_scratch
from .tools.sandbox_tools import cleanup_sandbox_scratch

# Where create_word_document's real files land -- no browser here to hand a download card to, so the CLI
# just writes them to a real path on disk and prints it, same end result (a real .docx the operator opens).
_REPORTS_DIR = os.environ.get("AEGIS_REPORTS_DIR", "./aegis_out")


async def _on_text(text: str) -> None:
    print(f"\nAegis: {text}")


async def _on_tool_call(name: str, args: dict, result: str) -> None:
    import json
    print(f"  -> {name}({json.dumps(args)[:200]})")


async def _emit_terminal_progress(name: str, text: str) -> None:
    print(f"  [{name}] {text}")


async def _emit_document(doc: dict) -> None:
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    path = os.path.join(_REPORTS_DIR, doc["filename"])
    with open(path, "wb") as f:
        f.write(base64.b64decode(doc["data_base64"]))
    print(f"\n[report ready] {os.path.abspath(path)} ({round(doc['size'] / 1024)} KB)")


async def main() -> None:
    try:
        # Just a startup sanity check (fails fast if nothing is configured at all) -- the real per-turn choice
        # happens inside the loop below, since a personal scan/fix provider split (AEGIS_SCAN_PROVIDER +
        # AEGIS_FIX_PROVIDER) can route different messages in the SAME session to different models.
        pick_provider()
    except ProviderError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    print("Aegis. Type a request (e.g. \"scan self\", \"scan self and fix any issue you find\", "
          "\"run redteam on github repo: https://github.com/owner/repo\"). Ctrl-D or \"exit\" to quit.")
    messages = new_session()
    ctx = {"emit_terminal_progress": _emit_terminal_progress, "emit_document": _emit_document}
    # Same deterministic, code-driven cleanup the web UI runs on every reconnect (see web.py's ws_endpoint) -- the CLI and web UI share
    # the exact same redteam/sandbox containers, so orphaned clones/scratch left by one are just as real from the other.
    for label, fn in (("sandbox", cleanup_sandbox_scratch), ("redteam", cleanup_redteam_scratch)):
        try:
            result = await fn({}, ctx)
            print(f"  -> cleanup_{label}_scratch() {result[:200]}")
        except Exception as e:                                                  # noqa: BLE001 -- startup cleanup must never block the CLI from starting
            print(f"  cleanup_{label}_scratch failed: {type(e).__name__}: {e}")
    loop = asyncio.get_running_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, input, "\n> ")
        except EOFError:
            break
        line = line.strip()
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        provider = pick_provider(user_text=line)
        print(f"  (provider: {provider})")
        messages.append({"role": "user", "content": line})
        try:
            await run_turn(provider, messages, ctx, _on_text, _on_tool_call)
        except Exception as e:                                                   # noqa: BLE001
            print(f"\n[error] {provider} call failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
