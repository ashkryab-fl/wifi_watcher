"""User-owned router credentials for the graphical application."""

import json
from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


def router_credentials(path=CONFIG_PATH):
    try:
        router = json.loads(Path(path).read_text(encoding="utf-8"))["router"]
        username, password = router["username"], router["password"]
        if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
            raise ValueError
        return {"username": username.strip(), "password": password}
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("Перевір config.json: потрібні router.username і router.password.") from None
