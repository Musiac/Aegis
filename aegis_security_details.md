# Aegis security details

The detailed record of how the Aegis sandbox was attacked and what happened. The short version is in the [README](README.md#security).

## Sandbox security: live-tested, not theorized (2026-10-27)

Pointing an AI agent at a stranger's public repo and letting it clone, run, and actively pentest that
repo's own server is itself a real attack surface — the cloned code could be malicious. So instead of
just asserting the sandbox is safe, we tried to break out of it ourselves. Think of the sandbox as a
padded room with the Wi-Fi cable cut: no doors to the host, no socket to phone home on, nothing sharp
within reach. We ran six real attacks directly against the live `aegis-sandbox` container (the exact
one `fixredteam`/`fixpentest` use to apply fixes), through the same `bash_run`/`export_project` code
paths the agent itself uses:

| # | Attack | Result |
|---|---|---|
| 1 | `rm -rf` outside the sandbox (e.g. the real Mac's `~/Downloads`) | **Blocked** — the real host filesystem is architecturally invisible; `ls /` inside the sandbox shows only its own mounted directories, nothing of the host. |
| 2 | Exfiltrate data to an external server (a real DGX address) | **Blocked** — `--network none` means no network device exists at all (`socket.gaierror: Temporary failure in name resolution`); even a "direct" attempt auto-routed through the install-only egress proxy, which returned `403 Forbidden` for a non-PyPI/npm destination. The legitimate path (PyPI, for installing dependencies) still returned `200 OK`. |
| 3 | Resource exhaustion (CPU spin, memory bomb, fork bomb) | **Contained** — memory bomb (tried ~20GB against a 4GB cap) was `SIGKILL`'d after 9.3s; fork bomb hit the 256-PID cap immediately; the sandbox answered the very next command in 0.01s in both cases — never crashed, never affected anything outside itself. |
| 4 | Read real credentials (`MUSE_API_KEY`, GitHub tokens) from inside the sandbox | **Blocked** — no real `.env` file is reachable anywhere in the sandbox's filesystem, only inert `.env.example` templates; `.env` is deliberately never copied in. |
| 5 | Container breakout (Docker socket, root, kernel writes) | **Blocked** — no Docker socket present; all Linux capabilities are zeroed at the kernel level (`CapEff: 0000000000000000`); running as non-root (`uid=1001`); root filesystem remount refused; `/proc/sys` writes refused (read-only). |
| 6 | Symlink/zip-slip attack on the exported fix zip | **Found, then fixed and re-verified live (2026-10-27)**: `export_project` originally dereferenced symlinks into the zip rather than storing the link — a planted `/etc/passwd` symlink was exported as 880 bytes of real content. Fixed by adding `-y` to the `zip` command (store symlinks as symlinks); re-ran the identical attack against the rebuilt sandbox and confirmed the exported zip now extracts `leaked_passwd.txt` as an actual 11-byte symlink pointing at `/etc/passwd`, not dereferenced content. |
