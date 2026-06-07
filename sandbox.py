# sandbox.py
import os
import subprocess
import tempfile
import shutil
import time


class Sandbox:
    """
    Simple Linux sandbox executor
    """

    def __init__(self, timeout=15):
        self.timeout = timeout

    def execute_file(self, file_path):
        if not os.path.exists(file_path):
            return {
                "success": False,
                "error": "File not found"
            }

        sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")

        try:
            isolated_file = os.path.join(
                sandbox_dir,
                os.path.basename(file_path)
            )

            shutil.copy2(file_path, isolated_file)

            os.chmod(isolated_file, 0o755)

            start_time = time.time()

            process = subprocess.Popen(
                [isolated_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=sandbox_dir,
                text=True
            )

            try:
                stdout, stderr = process.communicate(
                    timeout=self.timeout
                )

                execution_time = time.time() - start_time

                return {
                    "success": True,
                    "return_code": process.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "execution_time": execution_time
                }

            except subprocess.TimeoutExpired:
                process.kill()

                return {
                    "success": False,
                    "error": "Execution timeout"
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)