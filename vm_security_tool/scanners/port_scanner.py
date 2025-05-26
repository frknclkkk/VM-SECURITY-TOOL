import psutil
import socket
from typing import Dict, List
from ..utils.logger import logger


class PortScanner:
    # Şüpheli portlar ve açıklamaları
    SUSPICIOUS_PORTS = {
        22: "SSH (Brute Force saldırıları)",
        23: "Telnet (Güvensiz)",
        80: "HTTP (Web saldırıları)",
        443: "HTTPS (SSL zafiyetleri)",
        3306: "MySQL (Yetkisiz erişim)",
        3389: "RDP (Uzak masaüstü)",
        5900: "VNC (Ekran paylaşımı)",
        27017: "MongoDB (NoSQL enjeksiyon)"
    }

    def scan(self, detailed: bool = False, check_external: bool = False) -> Dict[int, Dict]:
        """Gelişmiş port tarama fonksiyonu"""
        logger.log("\n🔍 === GELİŞMİŞ PORT TARAMASI ===", "INFO")

        try:
            # Yerel dinleme portları
            local_ports = self._scan_listening_ports(detailed)

            # Harici açık port kontrolü
            if check_external:
                self._scan_external_ports()

            # Şüpheli port analizi
            self._analyze_suspicious_ports(local_ports)

            return local_ports

        except Exception as e:
            logger.log(f"Port tarama hatası: {str(e)}", "ERROR")
            return {}

    def _scan_listening_ports(self, detailed: bool) -> Dict[int, Dict]:
        """Dinlemedeki portları tara"""
        ports = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                pid = conn.pid
                process_info = self._get_process_info(pid) if detailed else {"name": "N/A"}

                ports[port] = {
                    "process": process_info,
                    "protocol": self._get_port_protocol(port),
                    "local_address": conn.laddr.ip if hasattr(conn.laddr, 'ip') else "N/A"
                }

                log_msg = f"Port: {port} | " \
                          f"Process: {process_info.get('name', 'Unknown')} | " \
                          f"PID: {pid or 'N/A'}"

                if detailed:
                    log_msg += f" | Path: {process_info.get('exe', 'N/A')}"

                logger.log(log_msg, "INFO")

        return ports

    def _get_process_info(self, pid: int) -> Dict:
        """Proses detay bilgilerini getir"""
        if not pid:
            return {"name": "System"}

        try:
            proc = psutil.Process(pid)
            return {
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": " ".join(proc.cmdline()),
                "username": proc.username(),
                "status": proc.status()
            }
        except psutil.NoSuchProcess:
            return {"name": "Terminated Process"}

    def _get_port_protocol(self, port: int) -> str:
        """Portun kullandığı protokolü belirle"""
        try:
            return socket.getservbyport(port)
        except (OSError, socket.error):
            return "unknown"

    def _analyze_suspicious_ports(self, ports: Dict[int, Dict]):
        """Şüpheli portları analiz et"""
        suspicious_found = False

        for port, info in ports.items():
            if port in self.SUSPICIOUS_PORTS:
                suspicious_found = True
                alert_msg = f"🚨 ŞÜPHELİ PORT: {port} ({self.SUSPICIOUS_PORTS[port]}) | " \
                            f"Process: {info['process'].get('name', 'Unknown')} | " \
                            f"PID: {info['process'].get('pid', 'N/A')}"

                logger.log(alert_msg, "ALARM")

        if not suspicious_found:
            logger.log("✅ Şüpheli port bulunamadı", "SUCCESS")

    def _scan_external_ports(self, ports: List[int] = None, timeout: float = 1.0):
        """Harici port taraması"""
        target_ip = self._get_external_ip()
        if not target_ip:
            logger.log("Harici IP belirlenemedi", "WARNING")
            return

        ports = ports or list(self.SUSPICIOUS_PORTS.keys())
        logger.log(f"\n🌍 Harici Port Taraması ({target_ip}):", "INFO")

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target_ip, port))

                    if result == 0:  # Port açık
                        service = self._get_port_protocol(port)
                        logger.log(f"  🔓 PORT {port} ({service}): AÇIK (Dışarıdan erişilebilir)", "WARNING")
                    else:
                        logger.log(f"  🔒 PORT {port}: KAPALI", "INFO")
            except Exception as e:
                logger.log(f"Port {port} tarama hatası: {str(e)}", "DEBUG")

    def _get_external_ip(self) -> str:
        """Harici IP adresini öğren"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return None

    def check_port_security(self, port: int) -> Dict:
        """Belirli bir portun güvenlik durumunu kontrol et"""
        result = {
            "port": port,
            "status": "closed",
            "threat_level": "low"
        }

        try:
            # Yerel dinleme kontrolü
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.port == port:
                    result.update({
                        "status": "open",
                        "process": self._get_process_info(conn.pid),
                        "protocol": self._get_port_protocol(port)
                    })

                    # Tehdit seviyesi belirleme
                    if port in self.SUSPICIOUS_PORTS:
                        result["threat_level"] = "high"
                    elif port < 1024:
                        result["threat_level"] = "medium"

                    break
        except Exception as e:
            result["error"] = str(e)

        return result
