import psutil
from ..utils.logger import logger


class PortScanner:
    def scan(self):
        """Scan and log open ports"""
        logger.log("\n=== PORT SCAN ===", "INFO")
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    pid = conn.pid
                    process_name = "Unknown"

                    if pid:
                        try:
                            process_name = psutil.Process(pid).name()
                        except psutil.NoSuchProcess:
                            process_name = "Unknown Process"

                    logger.log(f"Port: {port}, Process: {process_name} (PID: {pid})", "INFO")
        except Exception as e:
            logger.log(f"Failed to scan ports: {str(e)}", "ERROR")