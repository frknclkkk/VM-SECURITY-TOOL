import socket
from ..utils.logger import logger

class NetworkScanner:
    def scan(self):
        """Scan and log network information"""
        logger.log("\n=== NETWORK SCAN ===", "INFO")
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            logger.log(f"Hostname: {hostname}", "INFO")
            logger.log(f"IP Address: {ip_address}", "INFO")
        except Exception as e:
            logger.log(f"Failed to get network info: {str(e)}", "ERROR")