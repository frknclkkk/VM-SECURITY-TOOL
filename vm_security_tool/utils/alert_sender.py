# File: vm_security_tool/utils/alert_sender.py
import smtplib
from email.mime.text import MIMEText
from ..utils.logger import logger

class EmailAlertSender:
    def __init__(self, config):
        self.smtp_server = config.get('smtp_server')
        self.smtp_port = config.get('smtp_port', 587)
        self.sender_email = config.get('sender_email')
        self.sender_password = config.get('sender_password')
        self.recipient_emails = config.get('recipient_emails', [])
        self.use_tls = config.get('use_tls', True)

    def send_alert(self, subject, message):
        """Send security alert email"""
        if not all([self.smtp_server, self.sender_email, self.recipient_emails]):
            logger.log("Email alert configuration incomplete", "WARNING")
            return False

        try:
            msg = MIMEText(message)
            msg['Subject'] = f"[VM Security Alert] {subject}"
            msg['From'] = self.sender_email
            msg['To'] = ", ".join(self.recipient_emails)

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(
                    self.sender_email,
                    self.recipient_emails,
                    msg.as_string()
                )
            logger.log(f"Email alert sent: {subject}", "INFO")
            return True
        except Exception as e:
            logger.log(f"Failed to send email alert: {str(e)}", "ERROR")
            return False