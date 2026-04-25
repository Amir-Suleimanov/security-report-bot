from __future__ import annotations

import gzip
from pathlib import Path
from typing import Iterator


LOG_PATTERNS = ("access.log*", "scanner-drop.log*")


def iter_log_lines(base_dir: str = "/var/log/nginx") -> Iterator[str]:
    root = Path(base_dir)
    for pattern in LOG_PATTERNS:
        for path in sorted(root.glob(pattern)):
            if path.is_dir():
                continue
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                    yield from fh
            else:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    yield from fh
