"""First-run setup, called by install.sh as its last step: `docker exec aegis-code python3 -m backend.first_run`.

On a brand-new install the scanner container can need several minutes to load its tools and bring them up to date. Doing that here, while
the installer is still running and showing progress, means the first time someone opens the page they find everything ready. It uses the
same code path as the page's own greeting (wait_for_scanner_tools), so there is one behaviour, not two. Exit code 0 = ready, 1 = not ready."""
import asyncio
import json
import sys

from .tools.redteam_tools import ScannerSetupTimeout, prepare_scanner_databases, wait_for_scanner_tools


async def _main() -> int:
    async def say(text: str) -> None:
        print(text, flush=True)

    try:
        result = await wait_for_scanner_tools({}, say=say)
    except ScannerSetupTimeout as e:
        print(f"The scanner tools were not ready in time ({e}). Open the page anyway; it keeps trying.", flush=True)
        return 1
    except Exception as e:                                                      # noqa: BLE001 -- report plainly, never a traceback at an installer
        print(f"Could not check the scanner tools: {type(e).__name__}: {e}", flush=True)
        return 1
    try:
        data = json.loads(result)
    except ValueError:
        print(result, flush=True)
        return 1
    tools = (data.get("versions") or data).get("tools") or []
    if not tools:
        print("The scanner tools did not report their versions.", flush=True)
        return 1
    print("Scanner tools ready:", flush=True)
    for t in tools:
        print(f"  {t.get('name')} {t.get('current')} ({t.get('status')})", flush=True)
    # The one scanner database that has to be on disk before the first container scan: download it now, while the installer is still showing progress.
    print("Downloading the vulnerability database (about 130 MB, first time only)...", flush=True)
    try:
        db = await prepare_scanner_databases()
    except Exception as e:                                                      # noqa: BLE001 -- a failed pre-download only means the first scan downloads it instead
        print(f"  Could not pre-download it ({type(e).__name__}); Aegis will download it on the first container scan instead.", flush=True)
        return 0
    if db.get("ok"):
        print(f"  Vulnerability database ready ({db.get('seconds')} s).", flush=True)
    else:
        print(f"  Could not pre-download it ({db.get('error') or db.get('detail')}); Aegis will download it on the first container scan instead.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
