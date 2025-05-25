import psutil
from ..utils.logger import logger

class ProcessScanner:
    def scan(self):
        """Scan and log running processes"""
        logger.log("\n=== PROCESS SCAN ===", "INFO")
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                logger.log(str(proc.info), "INFO")
        except Exception as e:
            logger.log(f"Failed to scan processes: {str(e)}", "ERROR")