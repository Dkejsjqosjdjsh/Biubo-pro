import json
import os
from typing import Any
from src.config.settings import settings

_LOCALES = {}

def _load_locale():
    try:
        path = os.path.join(settings.PROJECT_ROOT, 'src', 'config', 'locale_zh_TW.json')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

_LOCALES = _load_locale()

def t(key: str, default: Any = None) -> Any:
    """Get translated value for `key`, fallback to `default` or the key itself."""
    if key in _LOCALES:
        return _LOCALES[key]
    return default if default is not None else key
