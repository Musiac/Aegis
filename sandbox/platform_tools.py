"""Call the platform's tools (web_search, calculate, get_weather, ...) from code running in the sandbox.

    from platform_tools import call, web_search
    hits = web_search("IBM quarterly revenue 2026")            # parsed JSON: {"results": [{"title", "url", "snippet"}, ...]}
    price = call("calculate", expression="2480 * 0.175")       # any tool the calling agent itself is allowed to use

The sandbox has no network, so this is the ONLY way to reach the web or any service: a request goes over /sock/tools.sock to the MCP server, which checks the
run's one-time token and the calling agent's tool list. Tools that change things (create/update/delete/send/book/pay/upload ...) are refused, and a run may make
at most 30 calls. Direct HTTP (urllib, requests, curl, wget) to a website does not work and is not allowed; use web_search."""
import json
import os
import socket

SOCK = os.getenv("REPL_TOOLS_SOCK", "/sock/tools.sock")


class ToolError(RuntimeError):
    pass


def call(tool: str, **args):
    """Call one platform tool. Returns the parsed JSON when the tool answers in JSON, else the text. Raises ToolError on a refusal or failure."""
    token = os.environ.get("REPL_TOOL_TOKEN", "")
    if not token:
        raise ToolError("This code run has no platform tools (the calling agent did not grant any).")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(75)
    try:
        s.connect(SOCK)
        s.sendall(json.dumps({"token": token, "tool": tool, "args": args}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        raise ToolError(f"The platform tool bridge is not reachable ({e}).")
    finally:
        s.close()
    reply = json.loads(buf or b"{}")
    if reply.get("error"):
        raise ToolError(reply["error"])
    text = reply.get("result", "")
    try:
        return json.loads(text)
    except ValueError:
        return text


def web_search(search_query: str, max_results: int = 5):
    """Search the web through the platform's web_search tool (the only way to get web content from the sandbox)."""
    return call("web_search", search_query=search_query, max_results=max_results)
