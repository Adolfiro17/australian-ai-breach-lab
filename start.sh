#!/usr/bin/env bash
# One command to run Adolfiro-Australia AI.
#
#   ./start.sh              open the lab in your browser (http://localhost:8501)
#   ./start.sh matrix       run every attack in both modes and print the result
#   ./start.sh run 3        run one module in the terminal (add: --mode vulnerable)
#   ./start.sh test         run the test suite
#   ./start.sh maestro      print the MAESTRO threat model for the lab
#   ./start.sh site         serve the course site at http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  "$PY" -m venv .venv 2>/dev/null || {
    echo "Could not create a virtual environment."
    echo "On Debian/Ubuntu run: sudo apt update && sudo apt install -y python3-venv"
    exit 1
  }
fi
# shellcheck disable=SC1091
. .venv/bin/activate
pip install -q -r requirements.txt

cmd="${1:-app}"
[ "$#" -gt 0 ] && shift
case "$cmd" in
  app)     echo "Opening the lab at http://localhost:8501 (Ctrl+C to stop)"; python -m streamlit run app.py ;;
  matrix)  python -m au.cli matrix ;;
  run)     python -m au.cli run "$@" ;;
  test)    python -m pytest -q ;;
  maestro) python -m au.cli maestro ;;
  site)    echo "Serving http://localhost:8000 (Ctrl+C to stop)"; python -m http.server 8000 --directory docs ;;
  *)       python -m au.cli "$cmd" "$@" ;;
esac
