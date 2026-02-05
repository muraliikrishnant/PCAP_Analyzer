#!/usr/bin/env bash
set -euo pipefail

OLLAMA_ORIGINS="https://muraliikrishnant.github.io" ollama serve & cloudflared tunnel --url http://localhost:11434
