import json
import logging
import os
from logging.handlers import RotatingFileHandler
from utils.alert import Alert

# ── Constants ────────────────────────────────────────
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")
MAX_BYTES = 5 * 1024 * 1024   # 5MB per file
BACKUP_COUNT = 3               # keep 3 files max


# ── Setup ────────────────────────────────────────────
def _setup_logger() -> logging.Logger:
    """
    Create and configure the alert logger.
    Uses RotatingFileHandler — when alerts.json hits 5MB it rotates:
        alerts.json   → alerts.json.1
        alerts.json.1 → alerts.json.2
        alerts.json.2 → alerts.json.3  (oldest, gets deleted when full)
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("netpulse.alerts")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT
    )

    # No formatter — we write raw JSON ourselves
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)

    return logger


# Single logger instance shared across the whole app
_logger = _setup_logger()


# ── Public API ───────────────────────────────────────
def log_alert(alert: Alert) -> None:
    _logger.info(json.dumps(alert.to_dict()))