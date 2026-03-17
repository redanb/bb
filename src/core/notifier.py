import smtplib
import os
import logging
import requests
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
    telegram_token: str | None
    telegram_chat_id: str | None
    enabled: bool
    telegram_enabled: bool
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
        
        self.telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        
        self.enabled = all([self.smtp_user, self.smtp_pass, self.target_email])
        self.telegram_enabled = all([self.telegram_token, self.telegram_chat_id])
        
        if not self.enabled:
            logger.warning("Email notifications DISABLED: Missing SMTP_USER, SMTP_PASS, or TARGET_EMAIL.")
        if not self.telegram_enabled:
            logger.warning("Telegram notifications DISABLED: Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID.")
        
        self.last_error = None

    def verify_smtp(self):
        """Diagnostic tool to check SMTP connectivity with fallback."""
        if not self.enabled:
            return False, "Configuration missing (SMTP_USER/PASS/TARGET_EMAIL)"
        
        # Try primary port (usually 587)
        try:
            logger.info(f"Connecting to SMTP {self.smtp_server}:{self.smtp_port}...")
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
                server.starttls()
            
            server.login(self.smtp_user, self.smtp_pass)
            server.quit()
            return True, f"SMTP Success on port {self.smtp_port}"
        except Exception as e1:
            logger.warning(f"SMTP Port {self.smtp_port} failed: {e1}. Trying fallback Port 465...")
            
            # Fallback to 465 SSL/TLS if not already using it
            if self.smtp_port != 465:
                try:
                    server = smtplib.SMTP_SSL(self.smtp_server, 465, timeout=10)
                    server.login(self.smtp_user, self.smtp_pass)
                    server.quit()
                    return True, "SMTP Success on fallback Port 465 (SSL)"
                except Exception as e2:
                    self.last_error = f"Primary failed: {e1}. Fallback failed: {e2}"
                    return False, f"SMTP Network Gate Block: {e2}"
            else:
                self.last_error = str(e1)
                return False, f"SMTP Error: {str(e1)}"

    def verify_telegram(self):
        if not self.telegram_enabled:
            return False, "Telegram config missing."
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return True, "Telegram Bot is active."
            return False, f"Telegram API Error: {resp.text}"
        except Exception as e:
            return False, str(e)

    def send_alert(self, subject, message):
        email_ok, email_msg = self._send_email(subject, message)
        tele_ok, tele_msg = self.send_telegram(f"*{subject}*\n{message}")
        
        return email_ok or tele_ok, f"Email: {email_msg} | Telegram: {tele_msg}"

    def _send_email(self, subject, message):
        if not self.enabled:
            return False, "Disabled"

        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = self.target_email
            msg['Subject'] = f"[BugBounty] {subject}"
            msg.attach(MIMEText(message, 'plain'))

            # Logic to handle port fallback
            try:
                if self.smtp_port == 465:
                    server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=15)
                else:
                    server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15)
                    server.starttls()
            except:
                server = smtplib.SMTP_SSL(self.smtp_server, 465, timeout=15)

            server.login(self.smtp_user, self.smtp_pass)
            server.send_message(msg)
            server.quit()
            return True, "Success"
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def send_telegram(self, message):
        if not self.telegram_enabled:
            return False, "Disabled"
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return True, "Success"
            return False, f"Error: {resp.status_code}"
        except Exception as e:
            return False, str(e)

# Singleton access
notifier = EmailNotifier()
