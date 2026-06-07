# quarantine.py
import os
import json
import shutil
import hashlib
from datetime import datetime


class QuarantineManager:
    """
    Linux-compatible quarantine manager
    """

    def __init__(self, quarantine_dir=None):
        self.quarantine_dir = quarantine_dir or os.path.join(
            os.path.expanduser("~"),
            ".antivirus_quarantine"
        )

        self.metadata_file = os.path.join(
            self.quarantine_dir,
            "metadata.json"
        )

        os.makedirs(self.quarantine_dir, exist_ok=True)

        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, "w") as f:
                json.dump({}, f)

    def quarantine_file(self, file_path, reason="Suspicious"):
        if not os.path.exists(file_path):
            return False, "File not found"

        try:
            file_hash = self._calculate_hash(file_path)

            quarantined_name = f"{file_hash}.quarantine"
            quarantined_path = os.path.join(
                self.quarantine_dir,
                quarantined_name
            )

            shutil.move(file_path, quarantined_path)

            metadata = self._load_metadata()

            metadata[file_hash] = {
                "original_path": file_path,
                "quarantined_path": quarantined_path,
                "reason": reason,
                "date": datetime.now().isoformat()
            }

            self._save_metadata(metadata)

            return True, quarantined_path

        except Exception as e:
            return False, str(e)

    def restore_file(self, file_hash):
        metadata = self._load_metadata()

        if file_hash not in metadata:
            return False, "File not found in quarantine"

        try:
            item = metadata[file_hash]

            os.makedirs(
                os.path.dirname(item["original_path"]),
                exist_ok=True
            )

            shutil.move(
                item["quarantined_path"],
                item["original_path"]
            )

            del metadata[file_hash]
            self._save_metadata(metadata)

            return True, item["original_path"]

        except Exception as e:
            return False, str(e)

    def delete_file(self, file_hash):
        metadata = self._load_metadata()

        if file_hash not in metadata:
            return False, "File not found"

        try:
            item = metadata[file_hash]

            if os.path.exists(item["quarantined_path"]):
                os.remove(item["quarantined_path"])

            del metadata[file_hash]
            self._save_metadata(metadata)

            return True, "Deleted"

        except Exception as e:
            return False, str(e)

    def list_quarantine(self):
        return self._load_metadata()

    def _load_metadata(self):
        try:
            with open(self.metadata_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_metadata(self, metadata):
        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f, indent=4)

    def _calculate_hash(self, file_path):
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        return sha256.hexdigest()