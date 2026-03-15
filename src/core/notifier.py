import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class EmailNotifier:
    """
    Singleton utility to send scan alerts and bounty reports to the user.
    """
    _instance = None
    smtp_server: str
    smtp_port: int
    smtp_user: str | None
    smtp_pass: str | None
    target_email: str | None
    enabled: bool
    last_error: str | None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EmailNotifier, cls).__new__(cls)
            cls._instance._init_config()
        return cls._instance

    def _init_config(self):
        self.smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.environ.get("SMTP_PORT", 587))
        self.smtp_user = os.environ.get("SMTP_USER")
        self.smtp_pass = os.environ.get("SMTP_PASS")
        self.target_email = os.environ.get("TARGET_EMAIL")
        self.enabled = all([self.smtp_user, self.smtp_pass, self.target_email])
        
        if not self.enabled:
            logger.warning("Email notifications DISABLED: Missing SMTP_USER, SMTP_PASS, or NOTIFICATION_EMAIL secrets in Railway.")
        
        self.last_error = None

    def verify_smtp(self):
        """Diagnostic tool to check SMTP connectivity."""
        if not self.enabled:
            return False, "Configuration missing (SMTP_USER/PASS/NOTIFICATION_EMAIL)"
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.quit()
            return True, "SMTP connection successful."
        except Exception as e:
            self.last_error = str(e)
            return False, f"SMTP Error: {str(e)}"

    def send_alert(self, subject, message):
        if not self.enabled:
            logger.info(f"Notification (DRY RUN): {subject} - {message}")
            return True, "Dry run successful"

        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = self.target_email
            msg['Subject'] = f"[BugBounty] {subject}"

            msg.attach(MIMEText(message, 'plain'))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15)
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.send_message(msg)
            server.quit()
            logger.info(f"Email alert sent successfully: {subject}")
            return True, "Success"
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Failed to send email alert: {str(e)}")
            return False, str(e)

# Singleton access
notifier = EmailNotifier()
