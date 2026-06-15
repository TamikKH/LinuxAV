from elftools.elf.elffile import ELFFile
from datetime import datetime
import math
import re


class BinaryAnalyzer:
    """Анализатор ELF файлов Linux"""

    def __init__(self):
        self.suspicious_symbols = {
            "system", "execve", "fork", "ptrace",
            "dlopen", "dlsym", "mprotect",
            "socket", "connect", "send", "recv"
        }

        self.anti_analysis_indicators = {
            "ptrace", "strace", "ltrace", "gdb"
        }

    def analyze(self, file_path, file_data=None):
        try:
            f = open(file_path, "rb") if not file_data else None
            elf = ELFFile(f if f else file_data)

            features = self._extract_features(elf)
            strings = self._extract_strings(file_path if not file_data else None, file_data)
            iocs = self._detect_iocs(strings)
            indicators = self._detect_indicators(features, strings)
            behaviors = self._correlate_behaviors(features, strings)
            score = self._calculate_score_v2(features, indicators, behaviors, iocs)

            if f:
                f.close()

            return {
                "is_elf": True,
                "info": self._get_basic_info(elf),
                "features": features,
                "strings_sample": strings[:50],
                "iocs": iocs,
                "indicators": indicators,
                "behaviors": behaviors,
                "score": score,
                "threat_level": self._determine_threat_level(score)
            }

        except Exception as e:
            return {
                "is_elf": False,
                "error": str(e),
                "score": 0,
                "threat_level": "Unknown"
            }

    def _extract_features(self, elf):
        features = {
            "symbols": set(),
            "sections": [],
            "high_entropy_sections": 0,
            "rwx_sections": 0,
            "entry_section": None
        }

        entry = elf.header["e_entry"]

        for section in elf.iter_sections():
            name = section.name
            features["sections"].append(name)

            try:
                data = section.data()
                entropy = self._calculate_entropy(data)
                if entropy > 7:
                    features["high_entropy_sections"] += 1
            except:
                pass

            flags = section["sh_flags"]

            # RWX detection
            if flags & 0x1 and flags & 0x2 and flags & 0x4:
                features["rwx_sections"] += 1

            addr = section["sh_addr"]
            size = section["sh_size"]

            if addr <= entry < (addr + size):
                features["entry_section"] = name

        # dynamic symbols
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            for sym in dynsym.iter_symbols():
                if sym.name:
                    features["symbols"].add(sym.name)

        return features

    # =========================
    # STRINGS EXTRACTION
    # =========================
    def _extract_strings(self, file_path=None, file_data=None, min_len=4):
        if file_data:
            data = file_data
        else:
            with open(file_path, "rb") as f:
                data = f.read()

        pattern = rb"[ -~]{%d,}" % min_len
        strings = re.findall(pattern, data)

        return [s.decode(errors="ignore") for s in strings]

    # =========================
    # IOC DETECTION
    # =========================
    def _detect_iocs(self, strings):
        iocs = {
            "urls": [],
            "ips": [],
            "commands": [],
            "paths": []
        }

        url_pattern = re.compile(r"https?://[^\s]+")
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        for s in strings:
            if url_pattern.search(s):
                iocs["urls"].append(s)

            if ip_pattern.search(s):
                iocs["ips"].append(s)

            if any(cmd in s.lower() for cmd in ["bash", "sh", "wget", "curl", "nc"]):
                iocs["commands"].append(s)

            if any(path in s for path in ["/tmp", "/dev/shm", "/etc/passwd"]):
                iocs["paths"].append(s)

        return iocs

    # =========================
    # INDICATORS
    # =========================
    def _detect_indicators(self, features, strings):
        indicators = []

        if features["rwx_sections"] > 0:
            indicators.append("RWX секции")

        if features["high_entropy_sections"] > 1:
            indicators.append("Высокая энтропия")

        if features["entry_section"] not in [".text", None]:
            indicators.append("Entry point вне .text")

        if any("debug" in s.lower() for s in strings):
            indicators.append("Anti-debug строки")

        return indicators

    # =========================
    # BEHAVIOR CORRELATION
    # =========================
    def _correlate_behaviors(self, features, strings):
        behaviors = []
        symbols = features["symbols"]

        if all(sym in symbols for sym in ["ptrace", "mprotect"]):
            behaviors.append("anti_analysis")

        if any(sym in symbols for sym in ["socket", "connect"]):
            behaviors.append("network_activity")

        if "system" in symbols or "execve" in symbols:
            behaviors.append("command_execution")

        if any("bash" in s.lower() and "/dev/tcp" in s for s in strings):
            behaviors.append("reverse_shell")

        if any("wget" in s.lower() and "/tmp" in s for s in strings):
            behaviors.append("downloader")

        return behaviors

    # =========================
    # SCORING
    # =========================
    def _calculate_score_v2(self, features, indicators, behaviors, iocs):
        score = 0

        score += len(indicators) * 3
        score += features["rwx_sections"] * 10
        score += features["high_entropy_sections"] * 5

        if iocs["urls"]:
            score += 10
        if iocs["ips"]:
            score += 10

        behavior_weights = {
            "anti_analysis": 15,
            "network_activity": 10,
            "command_execution": 20,
            "reverse_shell": 30,
            "downloader": 20
        }

        for b in behaviors:
            score += behavior_weights.get(b, 5)

        return min(score, 100)

    # =========================
    # BASIC INFO
    # =========================
    def _get_basic_info(self, elf):
        info = {}

        try:
            if elf.elfclass == 32:
                info["architecture"] = "x86"
            elif elf.elfclass == 64:
                info["architecture"] = "x64"

            info["num_sections"] = elf.num_sections()

        except:
            pass

        return info

    # =========================
    # ENTROPY
    # =========================
    def _calculate_entropy(self, data):
        if not data:
            return 0.0

        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0.0
        for c in freq.values():
            p = c / len(data)
            entropy -= p * math.log2(p)

        return entropy

    # =========================
    # THREAT LEVEL
    # =========================
    def _determine_threat_level(self, score):
        if score >= 40:
            return "Critical"
        elif score >= 25:
            return "High"
        elif score >= 15:
            return "Medium"
        elif score >= 5:
            return "Low"
        return "Clean"