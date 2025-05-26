import psutil
from datetime import datetime
from ..utils.logger import logger


class ProcessScanner:
    SUSPICIOUS_NAMES = ['crypt', 'miner', 'backdoor', 'shell', 'bot']
    HIGH_CPU_THRESHOLD = 80  # % CPU kullanım eşiği
    HIGH_MEM_THRESHOLD = 20  # % RAM kullanım eşiği

    def scan(self, detailed=False):
        """Gelişmiş proses tarama fonksiyonu"""
        logger.log("\n🔍 === DETAYLI PROSES TARAMASI ===", "INFO")

        try:
            # Sistem genel kaynak kullanımı
            self._log_system_resources()

            # Tüm prosesler
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                             'memory_percent', 'create_time', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    self._check_suspicious(proc_info)

                    if detailed:
                        self._log_detailed_process(proc_info)
                    else:
                        logger.log(f"PID:{proc_info['pid']} {proc_info['name']} "
                                   f"(CPU: {proc_info['cpu_percent']}%, "
                                   f"MEM: {proc_info['memory_percent']:.1f}%)", "INFO")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logger.log(f"Proses tarama hatası: {str(e)}", "ERROR")

    def _log_system_resources(self):
        """Sistem kaynak kullanımını logla"""
        cpu_usage = psutil.cpu_percent(interval=1)
        mem_usage = psutil.virtual_memory().percent
        logger.log(f"Sistem Kaynakları - CPU: {cpu_usage}% | RAM: {mem_usage}%", "INFO")

    def _check_suspicious(self, proc_info):
        """Şüpheli prosesleri kontrol et"""
        # Yüksek kaynak kullanan prosesler
        if proc_info['cpu_percent'] > self.HIGH_CPU_THRESHOLD:
            logger.log(f"⚠️ Yüksek CPU kullanımı: PID:{proc_info['pid']} {proc_info['name']} "
                       f"({proc_info['cpu_percent']}%)", "WARNING")

        if proc_info['memory_percent'] > self.HIGH_MEM_THRESHOLD:
            logger.log(f"⚠️ Yüksek RAM kullanımı: PID:{proc_info['pid']} {proc_info['name']} "
                       f"({proc_info['memory_percent']:.1f}%)", "WARNING")

        # Şüpheli isimler
        if any(susp in proc_info['name'].lower() for susp in self.SUSPICIOUS_NAMES):
            logger.log(f"🚨 Şüpheli proses: PID:{proc_info['pid']} {proc_info['name']}", "ALARM")

        # Uzun süredir çalışan prosesler (1 günden fazla)
        if 'create_time' in proc_info and proc_info['create_time']:
            uptime = (datetime.now() - datetime.fromtimestamp(proc_info['create_time'])).days
            if uptime > 1:
                logger.log(f"⏳ Uzun süreli proses: PID:{proc_info['pid']} {proc_info['name']} "
                           f"({uptime} gündür çalışıyor)", "INFO")

    def _log_detailed_process(self, proc_info):
        """Detaylı proses bilgisi"""
        details = [
            f"PID: {proc_info['pid']}",
            f"İsim: {proc_info['name']}",
            f"Kullanıcı: {proc_info['username']}",
            f"CPU: {proc_info['cpu_percent']}%",
            f"RAM: {proc_info['memory_percent']:.1f}%",
            f"Yol: {proc_info.get('exe', 'Bilinmiyor')}",
            f"Başlatma Komutu: {' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else 'Bilinmiyor'}"
        ]
        logger.log(" | ".join(details), "DETAIL")

    def find_process_by_name(self, name_pattern):
        """İsimle proses bulma"""
        found = []
        for proc in psutil.process_iter(['name', 'pid', 'username']):
            if name_pattern.lower() in proc.info['name'].lower():
                found.append(proc.info)
        return found

    def get_process_tree(self, pid):
        """Proses ağacını görüntüleme"""
        try:
            parent = psutil.Process(pid)
            tree = []
            for child in parent.children(recursive=True):
                tree.append({
                    'pid': child.pid,
                    'name': child.name(),
                    'status': child.status()
                })
            return tree
        except psutil.NoSuchProcess:
            return None
