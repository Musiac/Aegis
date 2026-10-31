# aegis-code (renamed from backend/ 2026-10-31): the chat loop, as a container so it can mount the same aegis-sock
# NAMED VOLUME the sandbox uses (a plain host process can't -- AF_UNIX sockets fail to bind inside a bind-mounted
# host dir on Docker Desktop/macOS). Reaches aegis-libraries (redteam on :7906, pentestlive on :7907) over aegis-net
# by container name, not 127.0.0.1 -- see AEGIS_REDTEAM_URL/AEGIS_PENTESTLIVE_URL in install.sh. Two commands:
#   cli (default) -- interactive, not a daemon:
#     docker run -it --rm --network aegis-net -v aegis-sock:/sock --env-file .env aegis-code:latest
#   web -- the browser UI, a real daemon on :8900:
#     docker run -d --name aegis-code --network aegis-net -v aegis-sock:/sock --env-file .env --restart unless-stopped aegis-code:latest web
FROM python:3.12-slim
# nodejs/npm (added 2026-10-30): this image is ALSO reused, unmodified, as sandbox-web's own runtime (sandbox_web/control.py's
# _install_deps) to install a cloned project's own npm dependencies before starting an npm/React/etc. UI, the same way it already
# installs Python deps via pip -- harmless addition to the real aegis-code container too, just unused binaries there.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
# uv (added 2026-10-31): sandbox_web/control.py (this image's own sandbox-web runtime, see the note above) now
# installs a cloned project's Python deps with `uv pip install --system` instead of plain pip, pointed at the
# SAME shared /REPL/.uvcache the code sandbox already uses (over aegis-work, a volume this container now also
# mounts) -- so a package either container already fetched is a cache hit for the other, not a second
# real PyPI download. Same install method sandbox/Dockerfile already uses.
RUN pip install --no-cache-dir uv
COPY . /app/backend/
ENV PYTHONPATH=/app
EXPOSE 8900
# Intentionally runs as root for socket access compatibility with sandbox-proxy (uid 1001).
# Real security boundary is the sandbox container (--network none, --cap-drop ALL, uid 1001).
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/app/backend/entrypoint.sh"]
# Reported on the CMD line specifically, not ENTRYPOINT -- needs its own suppression directly above it, on the
# line immediately before CMD (confirmed live 2026-10-28 against the real production semgrep config).
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["cli"]
