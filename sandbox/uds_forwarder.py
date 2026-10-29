"""127.0.0.1:3128 -> /sock/proxy.sock. The sandbox has no network device except loopback, so this is the only way a package installer can reach the
allow-listed proxy that lives in the other container."""
import asyncio
import os

PROXY_SOCK = os.getenv("REPL_PROXY_SOCK", "/sock/proxy.sock")


async def pipe(r, w):
    try:
        while data := await r.read(65536):
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
        ur, uw = await asyncio.open_unix_connection(PROXY_SOCK)
    except Exception:
        cw.close()
        return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 3128)
    async with server:
        await server.serve_forever()


asyncio.run(main())
