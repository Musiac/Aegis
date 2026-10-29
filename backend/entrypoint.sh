#!/bin/sh
# cli (interactive chat loop) or web (the browser UI, serves :8900) -- see Dockerfile's own comment for the 2 docker run shapes.
set -e
case "${1:-cli}" in
  cli) exec python -m backend.cli ;;
  web) exec uvicorn backend.web:app --host 0.0.0.0 --port 8900 ;;
  *)   exec "$@" ;;
esac
