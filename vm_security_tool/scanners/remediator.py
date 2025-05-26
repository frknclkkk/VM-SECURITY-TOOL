import subprocess
import json
from pathlib import Path
from vm_security_tool.utils.logger import logger


class RemediationEngine:
    """Handles automated security remediation actions"""

    BLOCKED_IPS_FILE = Path("/var/lib/vm_security/blocked_ips.json")

    def __init__(self):
        self.blocked_ips = self._load_blocked_ips()

    def check_system_requirements(self):
        """Sistem gereksinimlerini kontrol et"""
        requirements = {
            'iptables': ['sudo', 'iptables', '--version'],
            'ufw': ['sudo', 'ufw', 'version']
        }

        available = []
        for name, cmd in requirements.items():
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                available.append(name)
            except:
                continue

        if not available:
            logger.log("Sistemde hiçbir güvenlik duvarı bulunamadı (iptables/ufw)", "CRITICAL")
            return False

        logger.log(f"Mevcut güvenlik duvarları: {', '.join(available)}", "INFO")
        return True
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
        """Daha sağlam IP bloklama metodu"""
        if not self._validate_ip(ip_address):
            return False

        if method == 'iptables':
            return self._block_with_iptables(ip_address)
        elif method == 'ufw':
            return self._block_with_ufw(ip_address)
        else:
            logger.log(f"Geçersiz bloklama metodu: {method}", "ERROR")
            return False

    def _validate_ip(self, ip_address):
        """IP adresi formatını doğrula"""
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            logger.log(f"Geçersiz IP formatı: {ip_address}", "ERROR")
            return False

    def _block_with_iptables(self, ip_address):
        """IPTables ile bloklama işlemi"""
        try:
            # 1. Kuralı ekle
            add_rule = subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'],
                capture_output=True,
                text=True
            )

            if add_rule.returncode != 0:
                logger.log(f"IPTables kural ekleme başarısız: {add_rule.stderr}", "ERROR")
                return False

            # 2. Kuralın eklendiğini doğrula
            check_rule = subprocess.run(
                ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )

            if check_rule.returncode != 0:
                logger.log("Kural doğrulama başarısız", "ERROR")
                return False

            # 3. Kalıcı hale getir (debian tabanlı sistemler için)
            self._make_rules_persistent()

            self.blocked_ips.append(ip_address)
            self._save_blocked_ips()
            logger.log(f"Başarıyla bloklandı: {ip_address}", "SUCCESS")
            return True

        except Exception as e:
            logger.log(f"Kritik IP bloklama hatası: {str(e)}", "ERROR")
            return False

    def _make_rules_persistent(self):
        """Kuralları kalıcı hale getir"""
        persistent_methods = [
            ['sudo', 'netfilter-persistent', 'save'],
            ['sudo', 'service', 'iptables-persistent', 'save'],
            ['sudo', '/etc/init.d/iptables-persistent', 'save']
        ]

        for cmd in persistent_methods:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.log("Kurallar kalıcı hale getirildi", "INFO")
                    return
            except FileNotFoundError:
                continue

        logger.log("Kalıcı kural kaydetme metodu bulunamadı", "WARNING")

    def _block_with_ufw(self, ip_address):
        """UFW ile bloklama işlemi"""
        try:
            result = subprocess.run(
                ['sudo', 'ufw', 'deny', 'from', ip_address],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                self.blocked_ips.append(ip_address)
                self._save_blocked_ips()
                return True

            logger.log(f"UFW bloklama hatası: {result.stderr}", "ERROR")
            return False
        except Exception as e:
            logger.log(f"UFW bloklama hatası: {str(e)}", "ERROR")
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
