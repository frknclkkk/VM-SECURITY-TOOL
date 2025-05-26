import argparse
from vm_security_tool.scanners import (
    NetworkScanner,
    ProcessScanner,
    PortScanner,
    SSHBruteForceScanner
)
from vm_security_tool.utils.logger import logger
from vm_security_tool.utils.alert_sender import EmailAlertSender
from vm_security_tool.scanners.remediator  import RemediationEngine
from vm_security_tool.scanners.live_ssh_monitor import LiveSSHMonitor


class SecurityToolCLI:
    def __init__(self):
        self.scanner = SecurityScanner()
        self.config = self._load_config()
        self.remediator = RemediationEngine()
        self.alert_sender = self._init_alert_sender()

    def _load_config(self):
        """Load configuration from file"""
        try:
            # Burada gerçek config yükleme işlemi yapılmalı
            # Örnek bir config döndürüyoruz
            return {
                'email_alerts': {
                    'smtp_server': 'smtp.example.com',
                    'smtp_port': 587,
                    'sender_email': 'alerts@example.com',
                    'sender_password': 'password',
                    'recipient_emails': ['admin@example.com'],
                    'use_tls': True
                }
            }
        except Exception as e:
            logger.log(f"Failed to load config: {str(e)}", "ERROR")
            return {}

    def _init_alert_sender(self):
        """Initialize email alert sender if configured"""
        if 'email_alerts' in self.config and all(
                key in self.config['email_alerts'] for key in
                ['smtp_server', 'sender_email', 'sender_password', 'recipient_emails']
        ):
            return EmailAlertSender(self.config['email_alerts'])
        return None

    def list_blocked_ips(self):
        """List all currently blocked IPs"""
        self.remediator.list_blocked_ips()

    def show_menu(self):
        """Display interactive menu"""
        print("\n🔍 VM Security Scanner")
        print("1. Network Scan")
        print("2. Process Scan")
        print("3. Port Scan")
        print("4. SSH Brute Force Scan")
        print("5. Run All Scans")
        print("6. Live SSH Monitor")
        print("7. Exit")
        return input("\nSelect an option (1-7): ").strip()

    def interactive_mode(self):
        """Run in interactive menu mode with improved error handling"""
        while True:
            choice = self.show_menu()

            if choice == "1":
                self.scanner.run_selected(["network"])
            elif choice == "2":
                self.scanner.run_selected(["process"])
            elif choice == "3":
                self.scanner.run_selected(["ports"])
            elif choice == "4":
                self.scanner.run_selected(["ssh"])
            elif choice == "5":
                self.scanner.run_all()
            elif choice == "6":
                try:
                    duration = input("Enter monitoring duration in minutes (0 for continuous): ").strip()
                    monitor = LiveSSHMonitor(alert_sender=self.alert_sender)
                    if duration.isdigit():
                        monitor.monitor(duration_minutes=int(duration) if int(duration) > 0 else None)
                    else:
                        logger.log("Invalid duration. Please enter a number.", "ERROR")
                except Exception as e:
                    logger.log(f"Error in live monitoring: {str(e)}", "ERROR")
            elif choice == "7":
                logger.log("👋 Exiting...", "INFO")
                break
            else:
                logger.log("❌ Invalid choice! Please select 1-8", "ERROR")


class SecurityScanner:
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.process_scanner = ProcessScanner()
        self.port_scanner = PortScanner()
        self.ssh_scanner = SSHBruteForceScanner()

    def run_all(self):
        """Run all security scans"""
        logger.log("🔍 Running all security scans...", "INFO")
        self.network_scanner.scan()
        self.process_scanner.scan()
        self.port_scanner.scan()
        self.ssh_scanner.scan()
        logger.log("✅ All scans completed!", "SUCCESS")

    def run_selected(self, scan_types):
        """Run selected scan types"""
        logger.log("🔍 Running selected scans...", "INFO")
        if "network" in scan_types:
            self.network_scanner.scan()
        if "process" in scan_types:
            self.process_scanner.scan()
        if "ports" in scan_types:
            self.port_scanner.scan()
        if "ssh" in scan_types:
            self.ssh_scanner.scan()
        logger.log("✅ Selected scans completed!", "SUCCESS")


def main():
    parser = argparse.ArgumentParser(description="VM Security Scanner with Enhanced Remediation")

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument("--all", action="store_true", help="Run all security scans")
    scan_group.add_argument("--network", action="store_true", help="Run network scan")
    scan_group.add_argument("--process", action="store_true", help="Run process scan")
    scan_group.add_argument("--ports", action="store_true", help="Run port scan")
    scan_group.add_argument("--ssh", action="store_true", help="Run SSH brute force scan")
    scan_group.add_argument("--live-ssh", type=int, metavar='MINUTES',
                            help="Monitor SSH attacks live for specified minutes (0 for continuous)")

    # Enhanced remediation options
    remediation_group = parser.add_argument_group('Remediation Actions')
    remediation_group.add_argument(
        '--list-blocked',
        action='store_true',
        help='List all currently blocked IP addresses'
    )
    remediation_group.add_argument(
        '--unblock-ip',
        metavar='IP_ADDRESS',
        help='Remove block for a specific IP address'
    )
    remediation_group.add_argument(
        '--block-ip',
        metavar='IP_ADDRESS',
        help='Manually block a specific IP address'
    )
    remediation_group.add_argument(
        '--method',
        choices=['iptables', 'ufw'],
        default='iptables',
        help='Firewall method to use for blocking (iptables or ufw)'
    )

    args = parser.parse_args()
    cli = SecurityToolCLI()

    try:
        # Handle remediation actions first
        if args.list_blocked:
            cli.list_blocked_ips()
            return

        if args.unblock_ip:
            if cli.remediator.unblock_ip(args.unblock_ip):
                logger.log(f"Successfully unblocked {args.unblock_ip}", "SUCCESS")
            return

        if args.block_ip:
            if cli.remediator.block_ip(args.block_ip, method=args.method):
                logger.log(f"Successfully blocked {args.block_ip} using {args.method}", "SUCCESS")
            return

        # Then handle scan options
        if args.all:
            cli.scanner.run_all()
        elif args.live_ssh is not None:
            monitor = LiveSSHMonitor(alert_sender=cli.alert_sender)
            monitor.monitor(duration_minutes=args.live_ssh if args.live_ssh > 0 else None)
        elif any([args.network, args.process, args.ports, args.ssh]):
            selected = []
            if args.network: selected.append("network")
            if args.process: selected.append("process")
            if args.ports: selected.append("ports")
            if args.ssh: selected.append("ssh")
            cli.scanner.run_selected(selected)
        else:
            cli.interactive_mode()

    except KeyboardInterrupt:
        logger.log("\nOperation cancelled by user", "INFO")
    except Exception as e:
        logger.log(f"Critical error: {str(e)}", "CRITICAL")
        raise


if __name__ == "__main__":
    main()
