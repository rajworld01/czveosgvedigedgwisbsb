"""Application configuration and environment validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Config:
    """Immutable runtime settings."""

    api_id: int
    api_hash: str
    bot_token: str
    session_string: str
    admin_id: Optional[int]
    max_duration: int = 600
    max_threads: int = 100
    scan_limit: int = 50
    scan_cooldown_seconds: int = 10
    log_file: str = "bot.log"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            api_id=32048578,                          # my.telegram.org wala ID
            api_hash="d1f8adcc7209f45c34e260d901945c98",          # my.telegram.org wala hash
            bot_token="8769464955:AAEOud3nVinIxe72IyNvM-7yqKDmq69ao8E",   # BotFather wala token
            session_string="BQHpBcIANWjCu9ga3fSuMIAu_id1JY-7qrfKuKcd-36KBHlJkdTDxuqBr_ZDvVhQXfwv9-R7xxzPNmpoFS97lw4ZDCnB9opz0wHNLQF7lYv1RlkCHj1ILZg44RlWnU74WqKHdgdXAL3rWeZgqNnXuhC2uyGC1caSoT22Is8v7Wzfx8EeWmzqBfl-vXGnFj8ikwDb40lYVse5cn9cEwHsKOGaY8YNe-BshGUiX3ffRj7ofIrPD6JPGDp52x5K_GNCD3vyN-nW2LQzVgNiD3CWt1c7R9KEMEvgCOivG2mJboPU00N2rRjiw8k7Hy5lTnPgGSCLadmhzqQMiPN-ku0sRNd4cO-fHQAAAAGBSvx9AA",  # gen.py se mila string
            admin_id=123456789,                      # tera Telegram ID (ya None)
            max_duration=600,
            max_threads=100,
            scan_limit=50,
        )