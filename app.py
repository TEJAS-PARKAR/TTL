"""
SecureCodeGuard – Standalone Main Application Entrypoint
Run this file directly:
    python app.py
or with streamlit:
    streamlit run app.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

def main():
    """Launch the Streamlit app when executed via python app.py."""
    import subprocess
    ui_script = _PROJECT_ROOT / "ui" / "streamlit_app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(ui_script)] + sys.argv[1:]
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        pass

# If run directly via streamlit or python
if __name__ == "__main__":
    # Check if executed inside streamlit runtime
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        if get_script_run_ctx():
            # Executed via `streamlit run app.py` -> run the UI directly
            from ui.streamlit_app import *  # noqa: F401, F403
        else:
            main()
    except Exception:
        main()
