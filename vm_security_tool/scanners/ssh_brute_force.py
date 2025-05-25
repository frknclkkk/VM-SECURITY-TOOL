import subprocess
import os
from ..utils.logger import logger


class SSHBruteForceScanner:
    def __init__(self):
        self.log_source = self._find_auth_log()
        self.ban_threshold = 10  # Block IPs after this many failed attempts

    def _find_auth_log(self):
        """Find the appropriate auth log location"""
        possible_logs = [
            "/var/log/auth.log",  # Ubuntu/Debian
            "/var/log/secure"  # CentOS/RHEL
        ]

        for log_file in possible_logs:
            if os.path.exists(log_file):
                return {"type": "file", "path": log_file}

        try:
            subprocess.check_output("command -v journalctl", shell=True)
            return {"type": "journalctl", "path": "journalctl"}
        except subprocess.CalledProcessError:
            return None

    def scan(self):
        """Scan for SSH brute force attempts"""
        if not self.log_source:
            logger.log("❌ No SSH auth logs found", "ERROR")
            return

        logger.log("\n=== SSH BRUTE FORCE SCAN ===", "INFO")

        if self.log_source["type"] == "file":
            self._scan_log_file(self.log_source["path"])
        else:
            self._scan_journalctl()

    def _scan_log_file(self, log_file):
        """Scan log file for failed attempts"""
        try:
            cmd = f"grep 'Failed password' {log_file} | awk '{{print $(NF-3)}}' | sort | uniq -c | sort -nr"
            result = subprocess.check_output(cmd, shell=True).decode()

            if result.strip():
                logger.log("\nSuspicious IPs and attempts:", "WARNING")
                logger.log(result, "INFO")
            else:
                logger.log("No suspicious IPs found", "SUCCESS")
        except Exception as e:
            logger.log(f"Failed to scan log file: {str(e)}", "ERROR")

    def _scan_journalctl(self):
        """Scan journalctl for failed attempts"""
        try:
            cmd = "journalctl -u sshd --no-pager | grep 'Failed password' | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr"
            result = subprocess.check_output(cmd, shell=True).decode()

            if result.strip():
                logger.log("\nSuspicious IPs and attempts:", "WARNING")
                logger.log(result, "INFO")
            else:
                logger.log("No suspicious IPs found", "SUCCESS")
        except Exception as e:
            logger.log(f"Failed to scan journalctl: {str(e)}", "ERROR")