import json
import os
from pathlib import Path


def get_user_data_dir():
    home = Path.home()
    data_dir = home / ".local" / "share" / "linuxav"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_program_files_dir():
    return Path("/opt/linuxav")


CONFIG = {
    "app_name": "LinuxAV",
    "version": "1.0.0",

    "data_dir": str(get_user_data_dir()),
    "program_dir": str(get_program_files_dir()),
    "log_dir": str(get_user_data_dir() / "logs"),
    "quarantine_dir": str(get_user_data_dir() / "quarantine"),
    "temp_dir": "/tmp/linuxav",

    "scan": {
        "quick_scan_paths": [
            "/bin",
            "/usr",
            "/home",
            "/etc",
            "/tmp"
        ],
        "excluded_paths": [
            "/proc",
            "/sys",
            "/dev",
            "/run"
        ]
    }
}


class ConfigManager:
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = get_user_data_dir() / "config.json"

        self.config_file = Path(config_file)
        self.config = CONFIG.copy()
        self.load()

    def load(self):
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config.update(json.load(f))

    def save(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)


config_manager = ConfigManager()