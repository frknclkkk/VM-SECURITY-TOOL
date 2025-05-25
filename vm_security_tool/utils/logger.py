import logging
import os
import datetime
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output"""
    COLORS = {
        'DEBUG': '\033[94m',  # Blue
        'INFO': '\033[92m',  # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',  # Red
        'CRITICAL': '\033[1;91m',  # Bold Red
        'SUCCESS': '\033[1;92m',  # Bold Green
        'RESET': '\033[0m'  # Reset
    }

    def format(self, record):
        message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{message}{self.COLORS['RESET']}"


class SecurityLogger:
    def __init__(self):
        self.log_dir = "../log_file/logs"
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging handlers and formatters"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(self.log_dir, f"security_log_{current_time}.log")

        self.logger = logging.getLogger("vm_security_tool")
        self.logger.setLevel(logging.DEBUG)

        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log(self, message: str, level: str = "INFO"):
        """Log a message with specified level"""
        level = level.upper()
        if level == "SUCCESS":
            # Custom level between INFO and WARNING
            self.logger.log(21, message)
        else:
            log_method = getattr(self.logger, level.lower(), self.logger.info)
            log_method(message)


# Singleton logger instance
logger = SecurityLogger()