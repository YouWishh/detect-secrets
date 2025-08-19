New-Item -ItemType Directory -Force -Path .\detect_secrets\filters | Out-Null
@'
import re

# If a candidate is in a context that looks like a hash field, ignore the line.
_CTX = re.compile(r'"\s*(sha1|sha256|sha512|checksum|digest)\s*"\s*:\s*"', re.IGNORECASE)

def is_hash_context(line: str) -> bool:
    """
    Return True to tell detect-secrets to ignore this line.
    Meant for JSON-ish logs densely populated with digests.
    """
    return bool(_CTX.search(line))
'@ | Set-Content -Encoding UTF8 .\detect_secrets\filters\ignore_hash_context.py
