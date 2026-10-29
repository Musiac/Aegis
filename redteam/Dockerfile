# Red-team tool server: the static scanners (gitleaks, Semgrep, Bandit, pip-audit, npm audit, Trivy) plus OWASP ZAP, callable by the backend's chat loop.
# Scans a READ-ONLY copy of the target source, mounted at /src_self/self (or a dynamically cloned repo under /src_dynamic/<name>); reachable at
# 127.0.0.1:7906 (--network host). Only pip-audit, npm audit and a repo clone make an outbound connection; the scanners themselves take only a
# fixed target name, never an arbitrary path.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git nodejs npm openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx bandit==1.9.4 semgrep==1.182.1 pip-audit==2.10.1
# gitleaks: a single static binary, no runtime deps
RUN set -e; ARCH=$(dpkg --print-architecture); case "$ARCH" in arm64) GLARCH=arm64;; amd64) GLARCH=x64;; *) echo "unsupported arch $ARCH"; exit 1;; esac; \
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GLARCH}.tar.gz" | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks
# trivy: scans a LOCAL image tarball only (docker save'd outside this container by a deploy step) -- never the Docker socket, never a registry pull, so this tool needs no new privilege at all.
RUN set -e; ARCH=$(dpkg --print-architecture); case "$ARCH" in arm64) TRIVYARCH=ARM64;; amd64) TRIVYARCH=64bit;; *) echo "unsupported arch $ARCH"; exit 1;; esac; \
    curl -sL "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-${TRIVYARCH}.tar.gz" | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy
# OWASP ZAP (spider + passive + active/attacking scan, see server.py's _zap_target_ok): official distribution, Java-based.
RUN curl -sL https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz -o /tmp/zap.tar.gz \
    && mkdir -p /opt/zap && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 && rm /tmp/zap.tar.gz
WORKDIR /app
COPY server.py /app/
COPY custom_rules.yml /app/
# uid pinned (not left to useradd's next-free pick): install.sh hands the host's dynamic_pristine/ to exactly this uid so clones can be written there.
# /trivy-cache is pre-created and chowned HERE (not just at runtime) so a fresh `docker volume create` mount picks up this ownership from the
# image on first use (Docker's documented behavior: an empty named volume is seeded from the image's own content at its mountpoint, including
# permissions) -- a volume created with no prior content defaults to root:root otherwise, and trivy (running as this uid) could not write its
# downloaded vulnerability DB there, confirmed live: "mkdir /trivy-cache/db: permission denied".
RUN useradd -m -u 1000 redteam && mkdir -p /tmp/.cache /tmp/.local /dynamic_pristine_rw /src_dynamic /trivy-cache && chown -R redteam /tmp /dynamic_pristine_rw /src_dynamic /trivy-cache
USER redteam
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_DATA_HOME=/tmp/.local/share
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "7906"]
