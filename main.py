"""CLI entrypoint for ReverseShellStudy."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.suspicious_outbound import main

if __name__ == "__main__":
    main()
