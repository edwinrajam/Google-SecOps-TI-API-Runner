#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

export PORT="${PORT:-8087}"
echo "Starting Google Threat Intelligence (GTI) API Runner on port $PORT..."
python3 app.py
