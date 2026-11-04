# Aegis's library/tool server, folded from the old separate redteam/ and pentestlive/ containers
# (merged 2026-10-31 -- same image/network/volumes as redteam had, pentestlive added as a second process).
# redteam_server.py: static scanners (gitleaks, Semgrep, Bandit, pip-audit, npm audit, Trivy) plus OWASP ZAP,
# on :7906. Scans a READ-ONLY copy of the target source, mounted at /src_self/self (or a dynamically cloned
# repo under /src_dynamic/<name>). Only pip-audit, npm audit and a repo clone make an outbound connection; the
# scanners themselves take only a fixed target name, never an arbitrary path.
# pentestlive_server.py: the ACTIVE counterpart -- ONE active tool (pd-httpx's liveness/technology-detection
# probe) against a URL the owner names at request time, on :7907. A bearer token gates every call, and the
# full-featured version's voice_pentest_live.py refuses to call this server at all until the owner has typed
# PENTESTLIVE for that exact target_url -- this container trusts that gate and adds its own SSRF/scope check
# as a second, independent layer, not a replacement for it.
# Both processes run on aegis-net (a bridge network with real egress) -- neither one ever needed --network
# host; see install.sh's own note on why aegis-net was chosen over host networking on Docker Desktop.
FROM python:3.12-slim
# Slow or unreliable internet (2026-11-04): a timed-out download used to stop the whole build (a 15-second pip read timeout failed a real install on a weak
# Wi-Fi link). pip now waits up to 100 s per read and retries 10 times, apt retries 5 times, and the downloads below retry too.
ENV PIP_DEFAULT_TIMEOUT=100 PIP_RETRIES=10
RUN mkdir -p /etc/apt/apt.conf.d && echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git nodejs npm openjdk-21-jre-headless unzip \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx bandit==1.9.4 semgrep==1.170.0 pip-audit==2.10.1
# gitleaks: a single static binary, no runtime deps
RUN set -e; ARCH=$(dpkg --print-architecture); case "$ARCH" in arm64) GLARCH=arm64;; amd64) GLARCH=x64;; *) echo "unsupported arch $ARCH"; exit 1;; esac; \
    curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GLARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm -f /tmp/gitleaks.tgz \
    && chmod +x /usr/local/bin/gitleaks
# trivy: scans a LOCAL image tarball only (docker save'd outside this container by a deploy step) -- never the Docker socket, never a registry pull, so this tool needs no new privilege at all.
RUN set -e; ARCH=$(dpkg --print-architecture); case "$ARCH" in arm64) TRIVYARCH=ARM64;; amd64) TRIVYARCH=64bit;; *) echo "unsupported arch $ARCH"; exit 1;; esac; \
    curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-${TRIVYARCH}.tar.gz" \
    && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy && rm -f /tmp/trivy.tgz \
    && chmod +x /usr/local/bin/trivy
# OWASP ZAP (spider + passive + active/attacking scan, see redteam_server.py's _zap_target_ok): official distribution, Java-based.
RUN curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz -o /tmp/zap.tar.gz \
    && mkdir -p /opt/zap && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 && rm /tmp/zap.tar.gz
# ProjectDiscovery's httpx (a probe/recon tool -- a different thing from the Python httpx LIBRARY installed above): installed under its own name, pd-httpx, so there is never any
# ambiguity between the two in this image's PATH or in pentestlive_server.py's subprocess calls.
RUN set -e; ARCH=$(dpkg --print-architecture); case "$ARCH" in arm64) A=arm64;; amd64) A=amd64;; *) echo "unsupported arch $ARCH"; exit 1;; esac; \
    curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors "https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_${A}.zip" -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /tmp/httpx_extract && mv /tmp/httpx_extract/httpx /usr/local/bin/pd-httpx && chmod +x /usr/local/bin/pd-httpx && rm -rf /tmp/httpx.zip /tmp/httpx_extract
WORKDIR /app
COPY redteam_server.py pentestlive_server.py entrypoint.sh /app/
COPY custom_rules.yml /app/
RUN chmod +x /app/entrypoint.sh
# uid pinned (not left to useradd's next-free pick): install.sh hands the host's dynamic_pristine/ to exactly this uid so clones can be written there.
# Both processes run as this ONE user -- pentestlive's own uid was never a security boundary distinct from redteam's, just an artifact of being a
# separate image before the merge. /trivy-cache is pre-created and chowned HERE (not just at runtime) so a fresh `docker volume create` mount picks
# up this ownership from the image on first use (Docker's documented behavior: an empty named volume is seeded from the image's own content at its
# mountpoint, including permissions) -- a volume created with no prior content defaults to root:root otherwise, and trivy (running as this uid) could
# not write its downloaded vulnerability DB there, confirmed live: "mkdir /trivy-cache/db: permission denied".
RUN useradd -m -u 1000 redteam && mkdir -p /tmp/.cache /tmp/.local /dynamic_pristine_rw /src_dynamic /trivy-cache && chown -R redteam /tmp /dynamic_pristine_rw /src_dynamic /trivy-cache
USER redteam
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_DATA_HOME=/tmp/.local/share
CMD ["/app/entrypoint.sh"]
