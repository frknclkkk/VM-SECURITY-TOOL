import subprocess
import json
from pathlib import Path
from vm_security_tool.utils.logger import logger


class RemediationEngine:
    """Handles automated security remediation actions"""

    BLOCKED_IPS_FILE = Path("/var/lib/vm_security/blocked_ips.json")

    def __init__(self):
        self.blocked_ips = self._load_blocked_ips()

    def _load_blocked_ips(self):
        """Load previously blocked IPs from file"""
        try:
            if self.BLOCKED_IPS_FILE.exists():
                with open(self.BLOCKED_IPS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.log(f"Error loading blocked IPs: {str(e)}", "ERROR")
        return []

    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            self.BLOCKED_IPS_FILE.parent.mkdir(exist_ok=True, parents=True)
            with open(self.BLOCKED_IPS_FILE, 'w') as f:
                json.dump(self.blocked_ips, f)
        except Exception as e:
            logger.log(f"Error saving blocked IPs: {str(e)}", "ERROR")

    def block_ip(self, ip_address, method='iptables'):
        """Block an IP address and log the action"""
        if ip_address in self.blocked_ips:
            logger.log(f"IP {ip_address} already blocked", "INFO")
            return True

        try:
            if method == 'iptables':
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                    check=True
                )
                # Make rules persistent
                subprocess.run(
                    ['sudo', 'netfilter-persistent', 'save'],
                    stderr=subprocess.DEVNULL
                )

            self.blocked_ips.append(ip_address)
            self._save_blocked_ips()
            logger.log(f"Successfully blocked IP: {ip_address}", "SUCCESS")
            return True

        except subprocess.CalledProcessError as e:
            logger.log(f"Failed to block IP {ip_address}: {str(e)}", "ERROR")
            return False

    def is_blocked(self, ip_address):
        """Check if an IP is already blocked"""
        return ip_address in self.blocked_ips

    def unblock_ip(self, ip_address):
        """Unblock a previously blocked IP address"""
        try:
            subprocess.run(
                ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                check=True
            )
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self._save_blocked_ips()
            logger.log(f"Successfully unblocked IP: {ip_address}", "SUCCESS")
            return True
        except subprocess.CalledProcessError as e:
            logger.log(f"Failed to unblock IP {ip_address}: {str(e)}", "ERROR")
            return False

    def list_blocked_ips(self):
        """List all currently blocked IPs"""
        if not self.blocked_ips:
            logger.log("No IPs currently blocked", "INFO")
        else:
            logger.log("Blocked IP addresses:", "INFO")
            for ip in self.blocked_ips:
                logger.log(f"- {ip}", "INFO")