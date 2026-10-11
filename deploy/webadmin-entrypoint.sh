#!/bin/sh
set -eu
uvicorn main:app --host 127.0.0.1 --port 8000 &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM
nginx -g 'daemon off;' &
nginx_pid=$!
wait "$nginx_pid"
