# core/logger.py

import os
from datetime import datetime


class AuditLogger:
    def __init__(self, log_dir="logs"):
        os.makedirs(log_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        self.log_path = os.path.join(log_dir, f"audit_{date_str}.log")

    def log(self, command: str, session_name: str = None, result: str = ""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sess = session_name or "no-session"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{sess}] CMD: {command}\n")
            if result:
                f.write(f"  RESULT: {result[:200]}\n")


_logger = AuditLogger()


def log(command, session_name=None, result=""):
    _logger.log(command, session_name, result)
