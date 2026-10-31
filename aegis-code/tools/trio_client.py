"""Thin client for trio_control/server.py (../../trio_control/), the host-side process that creates/destroys the
ephemeral sandbox trio (aegis-sandbox, aegis-sandbox-proxy, aegis-sandbox-web). aegis-code has no docker.sock --
this is the ONLY path it has to affect any container's lifecycle, and it is narrow by design: exactly start/stop/
status, never a generic Docker API, reached over host.docker.internal (Docker Desktop's bridge-to-host DNS name)
since the control plane is a plain host process, not something on aegis-net."""
import http.client
import json
import os

_HOST = os.getenv("TRIO_CONTROL_HOST", "host.docker.internal")
_PORT = int(os.getenv("TRIO_CONTROL_PORT", "7929"))
_TOKEN = os.environ.get("TRIO_CONTROL_TOKEN", "")


def _call(method: str, path: str, timeout: float = 90.0) -> dict:
    try:
        conn = http.client.HTTPConnection(_HOST, _PORT, timeout=timeout)
        conn.request(method, path, headers={"Authorization": f"Bearer {_TOKEN}"})
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return data
    except Exception as e:                                                        # noqa: BLE001
        return {"ok": False, "error": f"trio_control did not answer ({type(e).__name__})."}


def start_trio() -> dict:
    return _call("POST", "/start", timeout=90.0)


def stop_trio() -> dict:
    return _call("POST", "/stop", timeout=30.0)


def trio_status() -> dict:
    return _call("GET", "/status", timeout=10.0)


def touch() -> None:
    # Refreshes the idle-reaper's clock on every real sandbox call. _call() already swallows every exception
    # and returns an error dict rather than raising, so a touch failure never breaks the real tool result
    # it's piggybacking on -- the return value here is simply ignored.
    _call("POST", "/touch", timeout=5.0)
