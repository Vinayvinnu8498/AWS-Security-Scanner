import logging
import logging.handlers
import json
import os

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "time": self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        }
        return json.dumps(log_record)

def setup_logger(config):
    # Pull logging settings from config_loader.py
    log_settings = config.get_logging_settings()

    log_level = log_settings.get("level", "INFO").upper()
    log_file = log_settings.get("file", "./logs/scan.log")
    json_logs = log_settings.get("json_logs", False)

    rotation = log_settings.get("rotation", {})
    max_size = rotation.get("max_size_mb", 5) * 1024 * 1024
    backup_count = rotation.get("backups", 3)

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("scanner")
    logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    logger.addHandler(console_handler)

    # File handler (rotating)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_size, backupCount=backup_count
    )

    if json_logs:
        file_handler.setFormatter(JsonFormatter())
    else:
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(levelname)s - %(module)s - %(message)s"
        ))

    logger.addHandler(file_handler)

    return logger
