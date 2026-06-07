# updater.py
import os
import requests


class UpdateManager:
    """
    Linux-compatible signature updater
    """

    def __init__(self,
        update_url,
        local_db_path="signatures.db"
    ):
        self.update_url = update_url
        self.local_db_path = local_db_path

    def update_signatures(self):
        try:
            response = requests.get(
                self.update_url,
                timeout=15
            )

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }

            with open(self.local_db_path, "wb") as f:
                f.write(response.content)

            return {
                "success": True,
                "message": "Signatures updated"
            }

        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

    def signatures_exist(self):
        return os.path.exists(self.local_db_path)

    def get_signature_size(self):
        if not self.signatures_exist():
            return 0

        return os.path.getsize(self.local_db_path)