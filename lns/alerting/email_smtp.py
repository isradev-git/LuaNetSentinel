"""Email alert channel (smtplib + email, stdlib). Secrets from env."""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

NAME = "email"


def configured() -> bool:
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_TO"))


def send(text: str, subject: str = "LuaNetSentinel — alerta") -> bool:
    if not configured():
        return False
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", os.environ.get("SMTP_USER", "lns@localhost"))
    msg["To"] = os.environ["SMTP_TO"]
    msg["Subject"] = subject
    msg.set_content(text)

    host, port = os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.starttls()
        if os.getenv("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        s.send_message(msg)
    return True
