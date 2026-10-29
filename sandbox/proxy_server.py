"""CONNECT-only HTTP proxy on a unix socket, in the container that HAS internet. It lets the sandbox install packages and nothing else:
  * only CONNECT to host:443 where host is in REPL_ALLOWED_HOSTS (default pypi.org, files.pythonhosted.org, registry.npmjs.org);
  * the proxy resolves the name itself; IP literals and private/loopback/link-local results are refused (no way to reach the host or the cloud metadata IP);
  * plain HTTP requests and every other method get 403.
Honest limit: anything may still be sent TO an allowed host (a PyPI/npm URL can carry data), so this is install-only egress, not zero egress.
registry.npmjs.org added so a fixredteam npm-audit fix (`npm install <pkg>@<fix_version>` / `npm audit fix`) can actually run and be verified,
not just hand-edited -- npm serves package tarballs from this SAME host (unlike PyPI's separate files.pythonhosted.org CDN), so one host
covers both the registry metadata and the actual downloads."""
import asyncio
import ipaddress
import os
import socket

SOCK = os.getenv("REPL_PROXY_SOCK", "/sock/proxy.sock")
ALLOWED = {h.strip().lower() for h in os.getenv("REPL_ALLOWED_HOSTS", "pypi.org,files.pythonhosted.org,registry.npmjs.org").split(",") if h.strip()}
MAX_BYTES = int(os.getenv("REPL_PROXY_MAX_BYTES", str(400 * 1024 * 1024)))


def refuse_reason(host: str, port: int):
    if port != 443 or host.lower() not in ALLOWED:
        return "host not allowed"
    try:
        ipaddress.ip_address(host)
        return "IP literals are refused"
    except ValueError:
        pass
    return None


async def pipe(r, w, budget):
    try:
        while data := await r.read(65536):
            budget[0] -= len(data)
            if budget[0] < 0:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(cr, cw):
    try:
        line = await asyncio.wait_for(cr.readline(), 10)
        parts = line.decode("latin1").split()
        while (h := await asyncio.wait_for(cr.readline(), 10)) not in (b"\r\n", b"\n", b""):
            pass
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            cw.write(b"HTTP/1.1 403 Forbidden\r\n\r\n"); await cw.drain(); return
        host, _, port = parts[1].rpartition(":")
        why = refuse_reason(host, int(port or 0))
        if why:
            cw.write(f"HTTP/1.1 403 Forbidden\r\nX-Reason: {why}\r\n\r\n".encode()); await cw.drain(); return
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [i[4][0] for i in infos if not (ipaddress.ip_address(i[4][0]).is_private or ipaddress.ip_address(i[4][0]).is_loopback or ipaddress.ip_address(i[4][0]).is_link_local)]
        if not ips:
            cw.write(b"HTTP/1.1 403 Forbidden\r\n\r\n"); await cw.drain(); return
        ur, uw = await asyncio.wait_for(asyncio.open_connection(ips[0], 443), 15)
        cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n"); await cw.drain()
        budget = [MAX_BYTES]
        await asyncio.gather(pipe(cr, uw, budget), pipe(ur, cw, budget))
    except Exception:
        pass
    finally:
        try:
            cw.close()
        except Exception:
            pass


async def main():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    server = await asyncio.start_unix_server(handle, SOCK)
    os.chmod(SOCK, 0o600)   # both ends (sandbox + this proxy) run as the SAME uid 1001 (sandbox/Dockerfile), so owner-only is enough; 0o666 was world-writable, 0o660 still group-writable for no reason (bandit B103, fixed 2026-10-20)
    async with server:
        await server.serve_forever()


asyncio.run(main())
