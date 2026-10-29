#!/bin/bash
# sandbox: start the proxy forwarder + the exec server;  proxy: the allow-listed CONNECT proxy.
set -e
mkdir -p /tmp/home /tmp/uv-cache /REPL/.pkgs 2>/dev/null || true
case "${1:-sandbox}" in
  sandbox) python /opt/repl/uds_forwarder.py & exec python /opt/repl/exec_server.py ;;
  proxy)   exec python /opt/repl/proxy_server.py ;;
  *)       exec "$@" ;;
esac
