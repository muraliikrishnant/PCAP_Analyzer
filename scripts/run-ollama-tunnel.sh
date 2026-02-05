#!/usr/bin/env bash
set -euo pipefail

origin="https://muraliikrishnant.github.io"

if pgrep -x ollama >/dev/null 2>&1; then
  echo "Stopping existing Ollama process..."
  pkill -x ollama || true
  sleep 1
fi

echo "Starting Ollama with CORS allowed for: ${origin}"
OLLAMA_ORIGINS="${origin}" ollama serve &
sleep 1

echo "Starting Cloudflare tunnel..."
cloudflared tunnel --url http://127.0.0.1:11434
