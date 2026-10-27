import json
from typing import Any

from backend.config import PAYLOADS_FILE


def load_payloads() -> list[dict[str, Any]]:
    with PAYLOADS_FILE.open("r", encoding="utf-8-sig") as file:
        payloads = json.load(file)
    if not isinstance(payloads, list) or not payloads:
        raise ValueError("payloads.json must contain a non-empty list")
    return payloads
