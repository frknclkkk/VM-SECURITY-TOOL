import socket
import psutil
import netifaces
from datetime import datetime
from ..utils.logger import logger


class NetworkScanner:
    def __init__(self):
        self.SUSPICIOUS_PORTS = [22, 23, 80, 443, 3389, 5900]  # İzlenmesi gereken portlar

    def scan(self, detailed=False, port_scan=False):
        """Gelişmiş ağ tarama fonksiyonu"""
        logger.log("\n🌐 === DETAYLI AĞ TARAMASI ===", "INFO")

        try:
            # Temel bilgiler
            self._scan_basic_info()

            # Ağ arabirimleri
            self._scan_interfaces(detailed)

            # Bağlantılar
            self._scan_connections()

            # İsteğe bağlı port tarama
            if port_scan:
                self.scan_ports()

        except Exception as e:
            logger.log(f"Ağ tarama hatası: {str(e)}", "ERROR")

    def _scan_basic_info(self):
        """Temel ağ bilgilerini tara"""
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
            logger.log(f"🏷️ Hostname: {hostname}", "INFO")
            logger.log(f"📡 IP Address: {hostname}: {ip_address}", "INFO")

            # DNS bilgileri
            dns_info = socket.getaddrinfo(hostname, None)
            logger.log(f"🔗 DNS Bilgileri: {dns_info[0][4][0]}", "INFO")

        except socket.gaierror:
            logger.log("DNS çözümleme hatası", "WARNING")

    def _scan_interfaces(self, detailed):
        """Ağ arabirimlerini tara"""
        interfaces = netifaces.interfaces()
        logger.log(f"\n📶 Ağ Arabirimleri ({len(interfaces)} adet):", "INFO")

        for interface in interfaces:
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        info = f"  - {interface}: {addr_info.get('addr', '?')}"
                        if detailed:
                            info += f" | Netmask: {addr_info.get('netmask', '?')}" \
                                    f" | MAC: {addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '?')}"
                        logger.log(info, "INFO")
            except ValueError as e:
                logger.log(f"Arabirim hatası {interface}: {str(e)}", "WARNING")

    def _scan_connections(self):
        """Aktif ağ bağlantılarını tara"""
        conns = psutil.net_connections()
        logger.log(f"\n🔌 Aktif Bağlantılar ({len(conns)} adet):", "INFO")

        suspicious = []
        for conn in conns:
            if conn.status == 'ESTABLISHED':
                info = (
                    f"{conn.laddr.ip}:{conn.laddr.port} ← "
                    f"{conn.raddr.ip if conn.raddr else '?'}:{conn.raddr.port if conn.raddr else '?'}"
                )

                # Şüpheli port kontrolü
                if conn.raddr and conn.raddr.port in self.SUSPICIOUS_PORTS:
                    suspicious.append(info)

                logger.log(f"  - {info} ({conn.pid})", "DETAIL")

        if suspicious:
            logger.log("\n🚨 Şüpheli Bağlantılar:", "ALARM")
            for conn in suspicious:
                logger.log(f"  - {conn}", "ALARM")

    def scan_ports(self, ports=None, timeout=1):
        """Belirli portları tara"""
        target_ip = socket.gethostbyname(socket.gethostname())
        ports = ports or [21, 22, 23, 80, 443, 3389, 8080]

        logger.log(f"\n🔎 Port Taraması ({target_ip}):", "INFO")

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                            logger.log(f"  ✅ PORT {port} ({service}): AÇIK", "WARNING")
                        except:
                            logger.log(f"  ✅ PORT {port}: AÇIK", "WARNING")
            except Exception as e:
                logger.log(f"Port {port} tarama hatası: {str(e)}", "DEBUG")

    def get_external_ip(self):
        """Harici IP adresini öğren"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            logger.log(f"Harici IP alınamadı: {str(e)}", "WARNING")
            return None
