"""Restore only the installed app directory under isolated Python mode."""
from pathlib import Path
import runpy
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
runpy.run_path(str(root / "app.py"), run_name="__main__")
