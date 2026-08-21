#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

VENV_DIR=".venv"

# Detect Windows (Git Bash / MSYS) vs Unix
case "$OSTYPE" in
    msys*|cygwin*|win32*)
        VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
        VENV_ACTIVATE="$VENV_DIR/Scripts/activate"
        IS_WINDOWS=1
        ;;
    *)
        VENV_PYTHON="$VENV_DIR/bin/python3"
        VENV_ACTIVATE="$VENV_DIR/bin/activate"
        IS_WINDOWS=0
        ;;
esac

# Create venv if it doesn't exist
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[GUI] Creating virtual environment..."
    python3 -m venv "$VENV_DIR" 2>/dev/null || python -m venv "$VENV_DIR" || {
        echo ""
        echo "ERROR: Could not create virtual environment."
        echo "  Linux/Kali: sudo apt install python3-venv python3-tk"
        echo "  Windows:    install Python from python.org"
        read -r dummy
        exit 1
    }
fi

# Activate venv
# shellcheck disable=SC1090
. "$VENV_ACTIVATE"

# Check tkinter on Linux/Mac (not pip-installable there)
if [ "$IS_WINDOWS" = "0" ]; then
    if ! python3 -c "import tkinter" 2>/dev/null; then
        echo ""
        echo "WARNING: tkinter not found. Install it with:"
        echo "  sudo apt install python3-tk"
        echo "Then re-run this script."
        read -r dummy
        exit 1
    fi
fi

# Install / update dependencies inside venv
echo "[GUI] Checking dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q || {
    echo ""
    echo "WARNING: Some packages may not have installed correctly."
}

# Launch GUI
echo "[GUI] Launching..."
python3 gui.py 2>/dev/null || python gui.py
