New-Item -ItemType Directory -Force -Path .\detect_secrets\core | Out-Null
@'
from __future__ import annotations
import io
import gzip
from typing import IO

_TEXT_KW = dict(encoding="utf-8", errors="ignore")

def open_text_auto(path: str) -> IO[str]:
    """
    Open a file for text scanning. If the file ends with .json.gz, stream-decompress it.
    Otherwise, open as a regular text file. Always UTF-8 with errors ignored.
    """
    lower = path.lower()
    if lower.endswith(".json.gz"):
        gz = gzip.open(path, mode="rb")
        return io.TextIOWrapper(gz, **_TEXT_KW)
    return open(path, mode="r", **_TEXT_KW)

def iter_lines(path: str):
    """Yield lines from path using open_text_auto (always closes stream)."""
    f = open_text_auto(path)
    try:
        for line in f:
            yield line
    finally:
        try:
            f.close()
        except Exception:
            pass
'@ | Set-Content -Encoding UTF8 .\detect_secrets\core\fileutils.py
