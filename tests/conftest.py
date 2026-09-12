"""Configuración común de pytest: añade sensor/ y backend/ al sys.path."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

for sub in ("sensor", "backend", ""):
    path = str(REPO_ROOT / sub) if sub else str(REPO_ROOT)
    if path not in sys.path:
        sys.path.insert(0, path)
