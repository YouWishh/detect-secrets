@'
from __future__ import annotations
import re
from typing import ClassVar, Iterable
from .base import RegexBasedDetector

class SaaSExtraDetector(RegexBasedDetector):
    """
    Additional SaaS/API credentials not covered by core detectors:
      - Slack Incoming Webhooks
      - GitLab PAT
      - Google API key
      - MongoDB URI with creds
      - Telegram bot token
      - Mapbox secret token
      - GCP Service Account cues
    """
    secret_type: ClassVar[str] = "SaaS/API Secret"

    denylist: ClassVar[Iterable[re.Pattern[str]]] = (
        # Slack webhook
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
        # GitLab PAT
        re.compile(r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),
        # Google API key
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        # MongoDB URI (with credentials)
        re.compile(r"\bmongodb(?:\+srv)?:\/\/[^\/\s:@]+:[^\/\s@]+@[^\/\s]+"),
        # Telegram bot token
        re.compile(r"\b\d{6,}:[A-Za-z0-9_\-]{30,}\b"),
        # Mapbox secret token
        re.compile(r"\bsk\.[A-Za-z0-9._-]{60,}\b"),
        # GCP service account cues
        re.compile(r'"type"\s*:\s*"service_account"'),
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
    )
'@ | Set-Content -Encoding UTF8 .\detect_secrets\plugins\saas_extra.py
