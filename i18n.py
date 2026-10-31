"""Language of the interface. The program's source texts are Russian: T("русский текст") returns the text in the language
in force (Russian as it is, any other from that language's catalog, falling back to the Russian text when a line is missing).
A catalog is a module `i18n_<code>` with a dict named `<CODE>` (source text -> text); to add a language, add that module and
an entry to LANGS. Texts with parts that change are templates: T("Нашлось {0} серверов").format(n).
No GUI, no network."""
import importlib
import json
import locale
import os
import subprocess
import sys

LANGS = {"ru": "Русский", "en": "English"}  # each in its own language
LANG = "ru"
_catalogs = {}
# People who read Russian: their system language is one of these, and they get the Russian interface by default.
RUSSIAN_READERS = ("ru", "be", "uk", "kk", "ky", "tg", "tk", "uz")


def catalog(lang):
    if lang not in _catalogs:
        try:
            _catalogs[lang] = getattr(importlib.import_module("i18n_" + lang), lang.upper())
        except Exception:  # noqa: BLE001
            _catalogs[lang] = {}
    return _catalogs[lang]


def set_language(lang):
    global LANG
    LANG = lang if lang in LANGS else "en"
    return LANG


def T(text):
    if LANG == "ru":
        return text
    return catalog(LANG).get(text, text)


def system_locale():
    """The user's locale as 'ru-RU' / 'en-US' / 'de-DE' (language-COUNTRY), '' when it cannot be told."""
    try:
        if sys.platform == "win32":
            import ctypes
            buf = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
                return buf.value
        elif sys.platform == "darwin":
            out = subprocess.run(["defaults", "read", "-g", "AppleLocale"], capture_output=True, text=True, timeout=5).stdout.strip()
            if out:
                return out.replace("_", "-")
        for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
            v = os.environ.get(var, "")
            if v and v not in ("C", "POSIX"):
                return v.split(".")[0].split(":")[0].replace("_", "-")
        loc = locale.getlocale()[0]
        return (loc or "").replace("_", "-")
    except Exception:  # noqa: BLE001
        return ""


def system_language():
    """'ru' for people who read Russian, 'en' for everyone else (until their language has a catalog)."""
    code = system_locale().split("-")[0].lower()
    return "ru" if code in RUSSIAN_READERS else "en"


def initial_language(settings_path):
    """The language to start in: FIMA_LANG (tests, support), else what the user chose, else Russian for an installation
    that existed before there was a choice, else the system's language for a new one."""
    env = os.environ.get("FIMA_LANG")
    if env in LANGS:
        return env
    try:
        with open(settings_path, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        return system_language()
    except Exception:  # noqa: BLE001
        return system_language()
    if isinstance(cfg, dict):
        return cfg["lang"] if cfg.get("lang") in LANGS else "ru"
    return system_language()
