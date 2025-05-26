import time
import re
from pathlib import Path
from collections import defaultdict
from ..utils.logger import logger
from .remediator import RemediationEngine
import os

class LiveSSHMonitor:
    def __init__(self, alert_sender=None, ban_threshold=10, check_interval=5):
        self.ban_threshold = ban_threshold
        self.check_interval = check_interval
        self.failed_attempts = defaultdict(int)
        self.log_file = self._determine_auth_log()
        self.last_position = 0
        self.alert_sender = alert_sender
        self.remediator = RemediationEngine()
        self.attack_pattern = re.compile(
            r'Failed password for (?:invalid user )?(.*?) from (\d+\.\d+\.\d+\.\d+)'
        )
        self.position_file = os.path.expanduser("~/.vm_security/ssh_monitor_position")
        self.last_position = self._save_last_position()
        os.makedirs(os.path.dirname(self.position_file), exist_ok=True)

    def _determine_auth_log(self):
        """Find the appropriate auth log file"""
        possible_logs = [
            '/var/log/auth.log',  # Ubuntu/Debian
            '/var/log/secure'  # CentOS/RHEL
        ]
        for log_file in possible_logs:
            if Path(log_file).exists():
                return log_file
        return None

    def _tail_log(self):
        """Read new log entries since last check with error handling"""
        if not self.log_file:
            logger.log("No log file configured", "ERROR")
            return []

        try:
            with open(self.log_file, 'r') as f:
                # Ensure we have a valid position
                if self.last_position is None:
                    self.last_position = 0

                # Handle file rotation (if file size < last position)
                current_size = os.path.getsize(self.log_file)
                if current_size < self.last_position:
                    logger.log("Log file rotated, resetting position", "INFO")
                    self.last_position = 0

                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                return new_lines
        except Exception as e:
            logger.log(f"Error reading log file: {str(e)}", "ERROR")
            return []

    def monitor(self, duration_minutes=None):
        """Start live monitoring of SSH attacks with visual feedback"""
        if not self.log_file:
            logger.log("Could not find SSH auth logs", "ERROR")
            return

        logger.log(f"🔍 Starting live SSH attack monitoring (watching {self.log_file})", "INFO")
        logger.log(f"IPs will be banned after {self.ban_threshold} failed attempts", "INFO")

        # Print header
        print("\n" + "=" * 80)
        print(f"{'IP Address':<20} | {'Username':<15} | {'Attempts':<10} | {'Status':<20}")
        print("=" * 80)

        start_time = time.time()
        try:
            while True:
                if duration_minutes and (time.time() - start_time) > duration_minutes * 60:
                    break

                for line in self._tail_log():
                    match = self.attack_pattern.search(line)
                    if match:
                        username, ip_address = match.groups()
                        self.failed_attempts[ip_address] += 1
                        attempts = self.failed_attempts[ip_address]

                        # Determine status
                        if attempts >= self.ban_threshold:
                            status = "🚨 UNBANNED"
                        elif attempts >= self.ban_threshold // 2:
                            status = "⚠️ WARNING"
                        else:
                            status = "👀 Monitoring"

                        # Clear line and print updated info
                        print(f"\r{ip_address:<20} | {username:<15} | {attempts:<10} | {status:<20}", end="",
                              flush=True)

                        # Take action if needed
                        if attempts >= self.ban_threshold and not self.remediator.is_blocked(ip_address):
                            self.remediator.block_ip(ip_address)
                            print(f"\n🔥 Banned IP {ip_address} after {attempts} attempts!")

                        self._save_last_position()

                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            print("\n" + "=" * 80)
            logger.log("Stopped live monitoring", "INFO")

    def _process_log_entry(self, line):
        """Process log entries for failed attempts"""
        match = self.attack_pattern.search(line)
        if match:
            username, ip_address = match.groups()

            if self.remediator.is_blocked(ip_address):
                return

            self.failed_attempts[ip_address] += 1
            attempts = self.failed_attempts[ip_address]

            logger.log(
                f"Failed SSH login: user={username} from {ip_address} "
                f"(attempt {attempts}/{self.ban_threshold})",
                "WARNING"
            )

            if self.alert_sender:
                if attempts == self.ban_threshold // 2:
                    self.alert_sender.send_alert(
                        "SSH Brute Force Attempt Detected",
                        f"Multiple failed SSH attempts from {ip_address}\n"
                        f"Current count: {attempts}\n"
                        f"System will auto-ban at {self.ban_threshold} attempts"
                    )
                elif attempts >= self.ban_threshold:
                    self.alert_sender.send_alert(
                        "SSH Brute Force Attack Blocked",
                        f"IP {ip_address} has been banned after {attempts} "
                        "failed SSH attempts"
                    )
                    self.remediator.block_ip(ip_address)

            time.sleep(self.check_interval)

    def _save_last_position(self):
        try:
            with open(self.position_file, "w") as f:
                f.write(str(self.last_position))
        except Exception as e:
            logger.log(f"Failed to save log position: {e}", "ERROR")



