import os
import hashlib
import time
from datetime import datetime
import psutil


class LinuxAVScanner:
    def __init__(self, signature_manager):
        self.signature_manager = signature_manager
        self.max_file_size = 50 * 1024 * 1024  # 50 MB
        self.scan_depth = 0  # 0=quick, 1=normal, 2=deep

        self.scan_results = {
            "total_scanned": 0,
            "threats_found": 0,
            "threats": [],
            "scan_time": 0,
            "scan_type": ""
        }

        # Доверенные системные директории (исключения)
        self.trusted_system_dirs = {
            "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/lib", "/usr/lib64", "/lib", "/lib64",
            "/usr/share", "/usr/local/share", "/boot",
            "/etc/ssl", "/etc/ca-certificates", "/usr/include"
        }

        # Доверенные системные файлы (по паттернам)
        self.trusted_patterns = [
            "systemd", "init", "bash", "sh", "dash", "ls", "cp", "mv",
            "gcc", "g++", "python", "perl", "java", "grep", "awk",
            "sed", "find", "xargs", "which", "whereis", "ldd"
        ]

        # Легитимные команды в системных скриптах
        self.legitimate_command_patterns = [
            ("wget", "/usr/bin/wget"),
            ("curl", "/usr/bin/curl"),
            ("bash", "/bin/bash"),
            ("python", "/usr/bin/python"),
            ("apt-get", "/usr/bin/apt-get"),
            ("yum", "/usr/bin/yum"),
            ("dnf", "/usr/bin/dnf"),
            ("pip", "/usr/bin/pip"),
        ]

        # Системные пути Linux
        self.system_paths = [
            "/bin",
            "/usr/bin",
            "/usr/local/bin",
            "/etc",
            "/home",
            "/tmp"
        ]

        # Расширения исполняемых файлов
        self.executable_extensions = {
            "", ".sh", ".py", ".pl", ".so", ".run", ".bin"
        }

    def _is_trusted_system_file(self, file_path):
        """Проверка, является ли файл доверенным системным"""
        file_path = os.path.abspath(file_path)

        # Проверка по директориям
        for trusted_dir in self.trusted_system_dirs:
            if file_path.startswith(trusted_dir):
                # Проверяем, не является ли пользовательским файлом
                # в системной директории
                if "/home/" not in file_path and "/tmp/" not in file_path:
                    return True

        # Проверка по имени файла
        file_name = os.path.basename(file_path).lower()
        for pattern in self.trusted_patterns:
            if pattern in file_name or file_name == pattern:
                # Проверяем, что файл находится в стандартном месте
                if file_path.startswith(("/bin/", "/usr/bin/", "/sbin/")):
                    return True

        return False

    def _is_safe_script_content(self, content):
        """Проверка, является ли содержимое скрипта безопасным"""
        content_lower = content.lower()

        # Критические индикаторы реального вреда
        critical_indicators = [
            "rm -rf /",  # Удаление всей системы
            "mkfs.",     # Форматирование диска
            "dd if=/dev/zero of=/dev/sda",  # Уничтожение данных
            "> /etc/passwd",  # Повреждение важных файлов
            "chmod 777 /",  # Опасные права
            ":(){ :|:& };:",  # Fork bomb
        ]

        for indicator in critical_indicators:
            if indicator in content_lower:
                return False, indicator

        # Легитимные комбинации, которые не должны срабатывать
        legitimate_combinations = [
            ("wget", "apt-get"),
            ("wget", "dpkg"),
            ("curl", "apt-get"),
            ("curl", "yum"),
            ("bash", "install.sh"),
            ("python", "setup.py"),
            ("pip", "install"),
        ]

        # Проверяем, не является ли комбинация легитимной
        for cmd1, cmd2 in legitimate_combinations:
            if cmd1 in content_lower and cmd2 in content_lower:
                return True, None

        # Подозрительные, но не всегда опасные индикаторы
        suspicious_count = 0
        suspicious_indicators = []

        dangerous_patterns = [
            ("wget", "загрузка из сети"),
            ("curl", "загрузка из сети"),
            ("nc", "netcat обратная связь"),
            ("bash -i", "интерактивная оболочка"),
            ("/dev/tcp", "сетевое соединение"),
            ("xmrig", "майнер"),
            ("miner", "майнер"),
            ("crypt", "криптовалюта"),
        ]

        for pattern, desc in dangerous_patterns:
            if pattern in content_lower:
                suspicious_count += 1
                suspicious_indicators.append(desc)

        # Файл подозрителен, если много индикаторов
        if suspicious_count >= 3:
            return False, "; ".join(suspicious_indicators[:3])

        return True, None

    def scan_path(self, path, scan_type="quick", progress_callback=None):
        start_time = time.time()

        self.scan_results.update({
            "total_scanned": 0,
            "threats_found": 0,
            "threats": [],
            "scan_time": 0,
            "scan_type": scan_type
        })

        if scan_type == "quick":
            files = self._collect_files(self.system_paths, limit=1000)
        elif scan_type == "full":
            files = self._collect_files(["/"], limit=10000)
        else:
            files = self._collect_files([path], limit=2000)

        self._scan_file_list(files, progress_callback)

        self.scan_results["scan_time"] = time.time() - start_time
        return self.scan_results

    def _collect_files(self, paths, limit=1000):
        files = []

        for path in paths:
            if not os.path.exists(path):
                continue

            try:
                for root, dirs, filenames in os.walk(path):
                    # Исключаем виртуальные FS и системные директории с правами
                    if root.startswith(("/proc", "/sys", "/dev", "/run")):
                        dirs[:] = []
                        continue

                    # При быстром сканировании пропускаем системные библиотеки
                    if self.scan_results["scan_type"] == "quick":
                        if root.startswith(("/usr/share/doc", "/usr/share/man",
                                           "/usr/share/info")):
                            continue

                    # Ограничиваем глубину при быстром сканировании
                    if self.scan_results["scan_type"] == "quick":
                        depth = root.count(os.sep)
                        if depth > 5:  # Максимум 5 уровней вложенности
                            dirs[:] = []
                            continue

                    for f in filenames:
                        full = os.path.join(root, f)
                        files.append(full)

                        if len(files) >= limit:
                            return files
            except (PermissionError, OSError):
                continue

        return files

    def _scan_file_list(self, file_list, progress_callback):
        total = len(file_list)

        for i, file_path in enumerate(file_list):
            if progress_callback:
                progress_callback(i + 1, total, file_path)

            try:
                # Пропускаем доверенные системные файлы
                if self._is_trusted_system_file(file_path):
                    self.scan_results["total_scanned"] += 1
                    continue

                self._scan_file(file_path)
                self.scan_results["total_scanned"] += 1
            except (PermissionError, OSError):
                continue
            except Exception:
                continue

    def _scan_file(self, file_path):
        if not os.path.isfile(file_path):
            return

        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                return

            file_hash = self._calculate_hash(file_path)

            # Белый список (доверенные файлы)
            if self.signature_manager.is_whitelisted(file_path):
                return

            threat = self.signature_manager.check_hash(file_hash)

            if not threat:
                with open(file_path, "rb") as f:
                    data = f.read(512 * 1024)

                    # Для текстовых файлов делаем углубленный анализ
                    try:
                        text_data = data.decode('utf-8', errors='ignore')
                        is_safe, reason = self._is_safe_script_content(text_data)

                        if not is_safe:
                            threat = {
                                "name": "Подозрительный скрипт",
                                "type": "Trojan",
                                "severity": "High",
                                "description": f"Обнаружены опасные паттерны: {reason}"
                            }
                    except:
                        pass

                if not threat:
                    threat = self.signature_manager.check_content(data)

                if not threat and self.scan_depth >= 1:  # Глубокий анализ
                    threat = self._deep_analyze_linux_file(file_path, data)

            if threat:
                self.scan_results["threats_found"] += 1
                self.scan_results["threats"].append({
                    "path": file_path,
                    "name": threat.get("name", "Unknown"),
                    "type": threat.get("type", "Malware"),
                    "severity": threat.get("severity", "Medium"),
                    "description": threat.get("description", ""),
                    "date": datetime.now().strftime("%d.%m.%Y %H:%M"),
                    "hash": file_hash
                })

        except (PermissionError, OSError, IOError):
            pass
        except Exception:
            pass

    def _calculate_hash(self, file_path):
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return ""

    def _deep_analyze_linux_file(self, path, data):
        """Углубленный анализ Linux файлов"""
        text = data.decode(errors="ignore").lower()

        indicators = []

        # Проверка на критические угрозы
        if "rm -rf /" in text or "mkfs" in text:
            return {
                "name": "Деструктивный скрипт",
                "type": "Destructive",
                "severity": "Critical",
                "description": "Обнаружены команды уничтожения данных"
            }

        # Проверка на майнеры
        if any(miner in text for miner in ["xmrig", "cpuminer", "minerd", "stratum+tcp"]):
            return {
                "name": "Криптомайнер",
                "type": "Miner",
                "severity": "High",
                "description": "Обнаружен скрипт криптомайнера"
            }

        # Reverse shell detection (только явные паттерны)
        reverse_shell_patterns = [
            ("bash -i >& /dev/tcp/", "Reverse shell"),
            ("nc -e /bin/sh", "Reverse shell"),
            ("python -c 'import socket", "Reverse shell через Python"),
            ("perl -e 'use Socket", "Reverse shell через Perl"),
        ]

        for pattern, desc in reverse_shell_patterns:
            if pattern in text:
                indicators.append(desc)

        # Загрузчик вредоносного ПО
        downloader_patterns = [
            ("wget", "http", "chmod +x", "Загрузка и запуск"),
            ("curl", "http", "bash", "Загрузка и выполнение"),
        ]

        for patterns in downloader_patterns:
            if all(p in text for p in patterns):
                indicators.append("Автоматическая загрузка и выполнение кода")
                break

        if indicators:
            return {
                "name": "Подозрительный Linux скрипт",
                "type": "Trojan",
                "severity": "High",
                "description": "; ".join(indicators)
            }

        return None

    def scan_memory(self):
        threats = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()

                if any(miner in name for miner in ["xmrig", "cpuminer", "minerd"]):
                    threats.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "type": "CryptoMiner"
                    })

                # Проверка командной строки на запуск майнера
                if any(miner in cmdline for miner in ["stratum", "mining", "pool"]):
                    threats.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "type": "CryptoMiner (скрытый)"
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return threats