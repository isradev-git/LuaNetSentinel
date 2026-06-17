"""Telegram alert channel (Bot API via requests). Secrets from env."""
from __future__ import annotations

import os

import requests

NAME = "telegram"
API = "https://api.telegram.org/bot{token}/sendMessage"


def configured() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


def send(text: str) -> bool:
    if not configured():
        return False
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    resp = requests.post(API.format(token=token), timeout=10, data={
        "chat_id": os.environ["TELEGRAM_CHAT_ID"],
        "text": text, "parse_mode": "Markdown"})
    return resp.ok
