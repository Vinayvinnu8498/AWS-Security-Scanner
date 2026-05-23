import yaml
import os

class ConfigError(Exception):
    pass


class Config:
    def __init__(self, data):
        self.data = data

    def get_regions(self):
        try:
            return self.data["scan"]["regions"]["enabled"]
        except KeyError:
            raise ConfigError("Missing regions list in config.yaml")

    def get_enabled_modules(self):
        try:
            modules = self.data["modules"]
            return {k: v.get("enabled", False) for k, v in modules.items()}
        except KeyError:
            raise ConfigError("Missing modules section in config.yaml")

    def get_output_settings(self):
        return self.data.get("output", {})

    def get_logging_settings(self):
        return self.data.get("logging", {})

    def get_log_level(self):
        # Default to INFO if not provided
        return self.data.get("logging", {}).get("level", "INFO")


def load_config(path="config.yaml"):
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ConfigError(f"Failed to read config file: {e}")

    if not isinstance(data, dict):
        raise ConfigError("Invalid config format: expected YAML dictionary")

    return Config(data)
