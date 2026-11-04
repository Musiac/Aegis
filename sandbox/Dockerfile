# REPL sandbox: where agents run Python and bash that they write themselves. Two containers run from this one image:
#   repl-sandbox  --network none (NO network device at all), read-only root, no mounts except the two volumes, non-root, cap-drop ALL, memory/pids capped
#                 command: sandbox   -> exec server on /sock/exec.sock + a 127.0.0.1:3128 -> /sock/proxy.sock forwarder (so uv/pip/npm can reach PyPI/npm)
#   repl-proxy    normal bridge networking, nothing mounted but the socket volume
#                 command: proxy     -> CONNECT-only proxy on /sock/proxy.sock that allows ONLY pypi.org, files.pythonhosted.org and registry.npmjs.org
# Aegis's backend mounts the same /sock volume (aegis-sock) and talks to /sock/exec.sock (the tools repl_run / repl_list / bash_run). Build: docker build -t aegis-sandbox sandbox/
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 UV_LINK_MODE=copy
# Slow or unreliable internet (2026-11-04): a timed-out download used to stop the whole build (a 15-second pip read timeout failed a real install on a weak
# Wi-Fi link). pip now waits up to 100 s per read and retries 10 times, apt retries 5 times, and the downloads below retry too.
ENV PIP_DEFAULT_TIMEOUT=100 PIP_RETRIES=10
RUN mkdir -p /etc/apt/apt.conf.d && echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils findutils grep sed gawk curl jq git ca-certificates procps tini zip unzip libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
# nodejs/npm: so a fixredteam npm-audit fix can actually run `npm install <pkg>@<fix_version>` / `npm audit fix` and be verified for real,
# instead of a hand-edited package.json/package-lock.json with no way to confirm it resolves. Debian bookworm's own apt nodejs package is
# v20, which a real run showed npm itself warning EBADENGINE against (several current packages, e.g. nanoid@6, require ^22/^24/>=26) --
# NodeSource's setup script instead, pinned to Node 24.x, the current Active LTS line as of 2026-10-26 (nodejs/release's own schedule;
# 26.x becomes Active LTS 2026-10-28). This curl runs at BUILD time only, on the host building the image -- it has nothing to do with the
# sandbox's own runtime network isolation (--network none) or the install-only egress proxy's allowlist below.
RUN curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /tmp/nodesource_setup.sh https://deb.nodesource.com/setup_24.x \
    && bash /tmp/nodesource_setup.sh && rm -f /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && pip install uv \
    && python -m venv /opt/base-venv \
    && /opt/base-venv/bin/pip install numpy pandas scipy sympy matplotlib openpyxl pyyaml beautifulsoup4 lxml python-dateutil pydantic tabulate pytest pyseccomp \
    && rm -rf /root/.cache
# libseccomp2 is the runtime library exec_server.py's _limits() loads via pyseccomp to deny setsid/setpgid in every run's child -- a caller that
# ran `env -u REPL_RUN_TAG setsid ...` could otherwise clear its run tag, leave the run's process group, and survive as an orphan once the shell
# exited and it was reparented to PID 1, which the ancestry-based cleanup (see _descendant_pids() in exec_server.py) cannot then trace.

RUN groupadd -g 1001 agent && useradd -u 1001 -g 1001 -m -d /home/agent -s /bin/bash agent \
    && mkdir -p /sock /REPL /opt/repl && chown 1001:1001 /sock /REPL
COPY exec_server.py proxy_server.py uds_forwarder.py platform_tools.py entrypoint.sh /opt/repl/
RUN chmod 755 /opt/repl/entrypoint.sh

USER 1001
WORKDIR /REPL
# user code: base libraries first, then anything the agent installed with `uv pip install --target /REPL/.pkgs <pkg>`
ENV PATH=/opt/base-venv/bin:/usr/local/bin:/usr/bin:/bin PYTHONPATH=/REPL/.pkgs:/opt/repl HOME=/tmp/home \
    UV_CACHE_DIR=/tmp/uv-cache UV_PYTHON_DOWNLOADS=never UV_PYTHON=/opt/base-venv/bin/python \
    HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128 NO_PROXY=
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/repl/entrypoint.sh"]
CMD ["sandbox"]
