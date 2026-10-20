"""Outgoing email over SMTP (stdlib only). Used for password resets."""

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from . import config

log = logging.getLogger(__name__)


def configured() -> bool:
    return bool(config.SMTP_HOST and config.MAIL_FROM)


def _send(to: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = config.MAIL_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    if config.SMTP_PORT == 465:
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=context, timeout=20) as smtp:
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as smtp:
            smtp.starttls(context=context)
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)


async def send(to: str, subject: str, body: str) -> bool:
    """Returns True if the message was handed to the SMTP server."""
    if not configured():
        if config.ALLOW_PRIVATE_TARGETS:  # dev mode: print the email so you can click the link locally
            log.warning("Email not configured; dev-mode copy of message to %s:\n%s\n%s", to, subject, body)
        else:
            log.error("Email not configured (set SMTP_HOST and MAIL_FROM); message to %s was not sent", to)
        return False
    try:
        await asyncio.to_thread(_send, to, subject, body)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        log.error("Sending email failed: %s", exc)
        return False
