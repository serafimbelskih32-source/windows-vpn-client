"""FimaVPN - VPN client for Windows, Linux and macOS on top of sing-box (TUN, system-wide).

Paste a subscription URL or share links (vless/vmess/trojan/ss/hysteria2/tuic),
pick a server, press Connect. The TUN adapter needs admin rights: on Windows the exe asks for them at start,
on Linux/macOS only the core is started as root (pkexec / the macOS admin prompt) when you press Connect.
"""
import base64
import ctypes
import json
import os
import queue
import re
import secrets
import shlex
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import font as tkfont
import urllib.error
import urllib.parse
import urllib.request
from tkinter import messagebox, ttk
from urllib.parse import parse_qs, unquote, urlparse, urlsplit
import http.client

import choice
import engines
import flags
import i18n
from i18n import T
import regions
import tray
import updater

updater.trust_certificates()  # a packaged program on a Mac has no certificates of its own: without this no https works

APP = "FimaVPN"  # settings folder name only
TITLE = "VPN"
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def data_dir():
    if IS_WIN:
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    elif IS_MAC:
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, APP)


DATA = data_dir()
try:
    os.makedirs(DATA, exist_ok=True)
except OSError:  # read-only or blocked profile folder: work from a temp folder instead of not starting at all
    import tempfile
    DATA = os.path.join(tempfile.gettempdir(), "FimaVPN")
STOPFILE = os.path.join(DATA, "stop")  # Linux/macOS: the root supervisor stops the core when this file appears
INSTANCE_FILE = os.path.join(DATA, "instance.port")  # loopback port of the running copy, so a 2nd launch can reach it
UPDATE_DIR = updater.update_dir(DATA)  # a downloaded, verified update waits here for the next start (one folder per program file)
SETTINGS = os.path.join(DATA, "settings.json")
i18n.set_language(i18n.initial_language(SETTINGS))  # before any text below is made
AUTO_LABEL = T("Быстрейший из списка")
AUTO_TAG = "fima-auto"  # the core's own "pick the best by itself" group, a member of the "proxy" selector (see build_config)
RUNCFG = os.path.join(DATA, "run.json")
LOGFILE = os.path.join(DATA, "sing-box.log")
TESTCFG = os.path.join(DATA, "test.json")
TESTLOG = os.path.join(DATA, "test.log")
CHECKCFG = os.path.join(DATA, "check.json")  # one server at a time, when the whole config is refused
HOMECFG = os.path.join(DATA, "home.json")  # a throw-away core that only asks which country this computer is really in
HOMELOG = os.path.join(DATA, "home.log")
SUBCACHE = os.path.join(DATA, "subs.json")
EXITFILE = os.path.join(DATA, "exit.json")  # "server:port" -> country the server really exits to (found by the test)
RULES_DIR = os.path.join(DATA, "rules")
os.makedirs(DATA, exist_ok=True)

BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
CORE_DIR = os.path.join(BASE, "core")
CORE = os.path.join(CORE_DIR, "sing-box.exe" if IS_WIN else "sing-box")
XRAY = os.path.join(CORE_DIR, "xray.exe" if IS_WIN else "xray")  # the companion for what the core cannot run (XHTTP...)
XRAYCFG = os.path.join(DATA, "xray.json")
XRAYLOG = os.path.join(DATA, "xray.log")
XRAYTESTCFG = os.path.join(DATA, "xray-test.json")
XRAYTESTLOG = os.path.join(DATA, "xray-test.log")
XRAY_PORT = engines.XRAY_BASE_PORT  # local ports of the companion while connected
XRAY_TEST_PORT = engines.XRAY_BASE_PORT + 300  # ... and while the servers are tested
NOWIN = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
MIXED_PORT = 2080
if not IS_WIN:
    try:
        os.chmod(CORE, 0o755)  # bundled data files may lose the executable bit
    except OSError:
        pass
    try:
        os.chmod(XRAY, 0o755)
    except OSError:
        pass

# Fonts: the window was designed around Bahnschrift (Windows); other systems get the closest installed face.
UI_FONTS = (("Bahnschrift SemiCondensed", "Bahnschrift", "Segoe UI") if IS_WIN else
            ("Helvetica Neue", "Arial") if IS_MAC else
            ("DejaVu Sans Condensed", "Noto Sans", "DejaVu Sans", "Liberation Sans"))
MONO = "Consolas" if IS_WIN else "Menlo" if IS_MAC else "DejaVu Sans Mono"


def FZ(n):
    """Font size: Tk on macOS counts points as pixels (72 dpi), so sizes need a boost to match Windows."""
    return int(round(n * 1.33)) if IS_MAC else n

RU_SUFFIXES = regions.suffixes("RU")
# Lists of the chosen country's addresses and sites: copies for Russia are bundled in core/ as the fallback; fresher ones (and
# those of every other country) are downloaded weekly into RULES_DIR and win while they are valid.
RULE_SETS = regions.rule_sets("RU")
LOCAL_DNS = "77.88.8.8"  # what resolves the chosen country's sites; '' = the system's resolver (set from the region at start)
RULES_EVERY = 7 * 24 * 3600
QUICK_TOP, QUICK_SECS = 6, 3.0  # the background test of the auto mode: this many servers, this many seconds of speed each
REVIEW_EVERY = 30 * 60  # speeds are measured again after this long
RULES_RETRY = 6 * 3600


_JOB = None


def make_job():
    """Windows job object that kills everything assigned to it when this process dies for any reason, so a
    crashed or killed window can never leave sing-box running with the TUN adapter and no internet."""
    try:
        from ctypes import wintypes

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("IoInfo", ctypes.c_uint64 * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k = ctypes.windll.kernel32
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        k.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        job = k.CreateJobObjectW(None, None)
        info = EXT()
        info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not job or not k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            return None
        return job
    except Exception:
        return None


def own(proc):
    """Tie a child process to our lifetime (see make_job). Windows only; Linux/macOS use the supervisor script."""
    global _JOB
    if not IS_WIN:
        return
    try:
        if _JOB is None:
            _JOB = make_job()
        if _JOB:
            ctypes.windll.kernel32.AssignProcessToJobObject(_JOB, int(proc._handle))
    except Exception:
        pass


def log_crash(exc_type, exc, tb):
    """--windowed builds have no console: keep unexpected errors in %APPDATA%\\FimaVPN\\crash.log."""
    try:
        import traceback
        path = os.path.join(DATA, "crash.log")
        if os.path.getsize(path) > 1024 * 1024:  # a repeating error must not fill the disk
            os.replace(path, path + ".old")
    except OSError:
        pass
    try:
        with open(os.path.join(DATA, "crash.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + "".join(traceback.format_exception(exc_type, exc, tb)) + "\n")
    except Exception:
        pass


def write_json(path, obj):
    """Write via a temp file so a crash never leaves half a file behind."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def srs_ok(data: bytes) -> bool:
    return data[:3] == b"SRS" and len(data) > 256


def rule_path(tag):
    """Freshest valid copy of a RU list: the downloaded one, else the bundled one, else None."""
    for p in (os.path.join(RULES_DIR, tag + ".srs"), os.path.join(CORE_DIR, tag + ".srs")):
        try:
            with open(p, "rb") as f:
                if srs_ok(f.read(512)):
                    return p
        except OSError:
            continue
    return None


def update_rule_sets(port, region="RU"):
    """Download fresh lists of the region's sites through the local proxy, i.e. through the VPN (port=None: directly, as a
    first try for a country whose lists are not on this computer yet). Returns how many updated."""
    os.makedirs(RULES_DIR, exist_ok=True)
    done = 0
    for tag, urls in regions.rule_sets(region).items():
        for url in urls:
            try:
                if port:
                    with _opener(port).open(url, timeout=30) as r:
                        data = r.read(20_000_000)
                else:
                    with updater.urlopen(urllib.request.Request(url, headers={"User-Agent": "FimaVPN"}), timeout=30) as r:
                        data = r.read(20_000_000)
            except Exception:
                continue
            if not srs_ok(data):
                continue
            dst = os.path.join(RULES_DIR, tag + ".srs")
            with open(dst + ".tmp", "wb") as f:
                f.write(data)
            os.replace(dst + ".tmp", dst)
            done += 1
            break
    return done


# ---------- link parsing: see sources.py ----------
from sources import (b64d, clean_outbound, parse_inline, parse_link, parse_text, parse_text_ex, skipped_note,  # noqa: E402,F401
                     source_lines, split_sources, valid_outbound, Unsupported)


UAS = ("v2rayN/7.0", "sing-box/1.13", "clash-verge/v2.2.3", "Hiddify/2.5.7")
MAX_SUB_BYTES = 8 * 1024 * 1024  # a real subscription is tens of kilobytes
REFRESH_DEFAULT_H = 12  # when the provider does not send profile-update-interval


def fetch(url: str, ua: str, via=None):
    """Returns (body, headers with lower-case names). `via` = 'http://host:port' of a proxy to go through. A provider
    whose DNS does not answer is bypassed: the address is then asked from a public DNS-over-HTTPS server."""
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with updater.urlopen(req, timeout=20, proxy=via) as r:
            body = r.read(MAX_SUB_BYTES + 1)
            headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:  # noqa: BLE001
        if via or not updater.is_dns_failure(e):
            raise
        raw, headers = updater.get_resolved(url, {"User-Agent": ua}, 20, MAX_SUB_BYTES)
        body = raw
    if len(body) > MAX_SUB_BYTES:
        raise ValueError(T("ответ слишком большой для подписки"))
    if body[:2] == b"\x1f\x8b":  # some panels compress even when not asked to
        import gzip
        body = gzip.decompress(body)
    return body.decode("utf-8-sig", "replace"), headers


def split_sources(src: str):
    """Subscription URLs and inline share links from the sources box."""
    urls, inline = [], []
    for line in src.splitlines():
        line = line.strip()
        if line:
            (urls if line.lower().startswith(("http://", "https://")) else inline).append(line)
    return urls, inline


def human_bytes(n):
    """12 ГБ, 1,5 ТБ, 340 МБ: what a person reads."""
    n = float(n)
    for unit, size in ((T("ТБ"), 1 << 40), (T("ГБ"), 1 << 30), (T("МБ"), 1 << 20)):
        if n >= size:
            v = n / size
            sep = "," if i18n.LANG == "ru" else "."  # the decimal mark
            return (f"{v:.0f}" if v >= 100 else f"{v:.1f}".replace(".", sep).removesuffix(sep + "0")) + " " + unit
    return T("{0:.0f} КБ").format(n / 1024) if n >= 1024 else T("{0:.0f} Б").format(n)


def usage_line(info, host, now=None):
    """('gamededio.com: осталось 120 ГБ из 300 ГБ, до 12.12.2026', needs attention) from what the provider reports about
    a subscription, or ('', False) if it reports nothing worth showing."""
    now = time.time() if now is None else now
    u = (info or {}).get("usage") or {}
    used = int(u.get("upload", 0)) + int(u.get("download", 0))
    total, expire = int(u.get("total", 0)), int(u.get("expire", 0))
    parts, warn = [], False
    if total > 0:
        left = max(0, total - used)
        parts.append(T("осталось {0} из {1}").format(human_bytes(left), human_bytes(total)))
        warn = warn or left <= total * 0.1
    elif used > 0:
        parts.append(T("использовано {0}").format(human_bytes(used)))
    if expire > 0:
        days = (expire - now) / 86400
        if days < 0:
            parts.append(T("срок вышел"))
            warn = True
        else:
            parts.append(T("до ") + time.strftime("%d.%m.%Y", time.localtime(expire)) + (T(" (ещё {0} дн.)").format(int(days) + (1 if days > int(days) else 0)) if days <= 7 else ""))
            warn = warn or days <= 3
    if not parts:
        return "", False
    name = str((info or {}).get("title") or host or T("подписка"))[:40]
    return f"{name}: " + ", ".join(parts), warn


def sub_info(headers):
    """Provider metadata from subscription response headers (interval in hours, usage, title)."""
    info = {}
    try:
        hours = float(headers.get("profile-update-interval", "").strip())
        if hours > 0:
            info["interval_h"] = hours
    except ValueError:
        pass
    usage = {}
    for part in headers.get("subscription-userinfo", "").split(";"):
        k, _, v = part.partition("=")
        if v.strip().isdigit():
            usage[k.strip().lower()] = int(v.strip())
    if usage:
        info["usage"] = usage
    title = headers.get("profile-title", "").strip()
    if title.lower().startswith("base64:"):
        try:
            title = b64d(title[7:]).strip()
        except Exception:
            title = ""
    if title:
        info["title"] = title
    return info


def server_key(o):
    """Identity of a server across formats: the same one listed for different clients has a different name but the same
    address, port and credentials."""
    tls = o.get("tls") or {}
    return (o.get("type"), o.get("server"), o.get("server_port"), o.get("uuid") or o.get("password") or o.get("auth_str") or o.get("private_key") or "",
            json.dumps(o.get("transport") or o.get("xray", {}).get("streamSettings") or "", sort_keys=True, default=str),  # many "servers" of one host differ only here
            tls.get("server_name"), (tls.get("reality") or {}).get("short_id"))


def fetch_source(url, prefer=None, via=None, merge=False):
    """Fetch one subscription, trying the UA that worked last time first, then (if a VPN of ours is up) through it.
    With `merge`, every User-Agent that gets an answer is used and the servers of all answers are kept (one provider gave
    81 servers to one client and 35, with Hysteria2, to another). Returns (outs, info, ua, errors)."""
    errors = []
    got = []  # (outs, info, ua) of each answer, when merging
    host = urlsplit(url).hostname or T("подписка")  # the path holds the user's key: never shown
    for route in ((None, via) if via else (None,)):
        for ua in sorted(UAS[:3] if merge else UAS, key=lambda u: u != prefer):
            try:
                body, headers = fetch(url, ua, route)
            except Exception as e:  # noqa: BLE001
                msg = f"{host}: {updater.explain(e)}"
                if msg not in errors:
                    errors.append(msg)
                if not updater.is_http_error(e):
                    break  # no connection at all: the other User-Agent would wait for the same timeout again
                continue  # the site answered "no": another User-Agent may please it
            outs, skipped = parse_text_ex(body)
            if outs:
                info = sub_info(headers)
                if skipped:
                    info["skipped"] = dict(skipped)
                if not merge:
                    return outs, info, ua, []
                got.append((outs, info, ua))
                continue
            if skipped:  # servers were there, none of them runnable
                msg = f"{host}: {skipped_note(skipped)}"
                if msg not in errors:
                    errors.append(msg)
                continue
            msg = T("{0}: в ответе нет серверов (ссылка устарела или это не подписка)").format(host)
            if msg not in errors:
                errors.append(msg)
        if got:
            break  # this route worked: no need to try the other
    if got:
        seen, outs = set(), []
        for group, _, _ in got:
            for o in group:
                k = server_key(o)
                if k not in seen:
                    seen.add(k)
                    outs.append(o)
        info = dict(got[0][1])
        skipped = Counter()
        for _, i, _ in got:
            skipped.update(i.get("skipped") or {})
        if skipped:
            info["skipped"] = dict(skipped)
        return _unique(outs), info, got[0][2], []
    return [], {}, None, errors


def _unique(outs):
    """Distinct tags across servers that came from different answers (names repeat between them)."""
    from sources import _unique_tags
    return _unique_tags([dict(o) for o in outs])


def merge_outs(groups):
    """Concatenate outbound lists with unique tags, leaving the cached originals untouched."""
    seen, res = set(), []
    for group in groups:
        for o in group:
            if not valid_outbound(o):
                continue
            o = dict(o)
            o["tag"] = o.get("tag") or f"{o['type']}-{o['server']}:{o['server_port']}"
            while o["tag"] in seen:
                o["tag"] += "*"
            seen.add(o["tag"])
            res.append(o)
    return res


RELEASES_URL = f"https://github.com/{updater.REPO}/releases/latest"
MSG_DEAD_PROXY = (T("В Windows включён прокси {addr}, но он не отвечает. Скорее всего, он остался от другой программы "
                  "(например, VPN-клиента), которую закрыли или после перезагрузки компьютера.\n\nИз-за него браузер и многие "
                  "программы не открывают сайты, даже когда VPN включён.\n\nОтключить этот прокси? Если он снова понадобится, "
                  "программа, которая его создала, включит его сама."))
MSG_NO_CORE = (T("Не хватает файла, без которого VPN не работает.\n\nТак бывает, когда антивирус удаляет его по ошибке. "
               "Что сделать:\n1. Добавь программу в исключения антивируса.\n2. Скачай программу заново и запусти её.\n\n"
               "Если не получится, напиши об этом на странице проекта на GitHub."))


# ---------- advanced ("pro") settings ----------
# Everything an ordinary user never needs. The defaults are what the program always did; the window for these settings
# opens with a double click on «Настройки». Each entry: default, kind, bounds / choices, label for the window.
PRO_FIELDS = {
    # look (the first group applies at the next start, the rest at once)
    "theme": ("light", "choice", ("auto", "light", "dark", "contrast")),
    "accent": ("blue", "choice", ("blue", "green", "orange", "violet", "pink")),  # keys of ACCENTS
    "accent_hex": ("", "color", None),
    "ui_scale": (100, "int", (70, 180)),
    "density": ("normal", "choice", ("compact", "normal", "roomy")),
    "ui_font": ("auto", "choice", ("auto", "condensed", "regular", "mono")),
    "border": (2, "int", (1, 4)),
    "win_width": (480, "int", (380, 900)),
    "shadow": (True, "bool", None),
    "anim": (True, "bool", None),
    "remember_window": (True, "bool", None),
    "on_top": (False, "bool", None),
    "alpha": (100, "int", (60, 100)),
    # connection
    "autoconnect": (False, "bool", None),
    "use_xray": (True, "bool", None),
    "merge_subs": (True, "bool", None),
    "bypass_apps": ("", "apps", None),
    "vpn_only_apps": ("", "apps", None),
    "mixed_port": (2080, "int", (1024, 65535)),
    "tun_stack": ("mixed", "choice", ("mixed", "system", "gvisor")),
    "strict_route": (True, "bool", None),
    "auto_reconnect": (True, "bool", None),
    "dns_remote": ("1.1.1.1", "host", None),
    "dns_local": ("", "host", None),  # '' = the one of the chosen country, or the system's where it has none
    "auto_url": ("https://www.gstatic.com/generate_204", "url", None),
    "auto_interval": (3, "int", (1, 60)),
    "auto_tolerance": (50, "int", (0, 1000)),
    "auto_focus": ("balanced", "choice", tuple(choice.FOCUS)),
    "auto_speed": (True, "bool", None),
    "test_top": (8, "int", (1, 50)),
    "test_secs": (4, "int", (1, 30)),
    "test_parallel": (64, "int", (1, 128)),
    "log_level": ("info", "choice", ("debug", "info", "warn", "error")),
}
PRO_DEFAULTS = {k: v[0] for k, v in PRO_FIELDS.items()}
RESTART_KEYS = ("theme", "accent", "accent_hex", "ui_scale", "density", "ui_font", "border")  # read when the window is built
PRO_LABELS = {  # what the segmented choices say (the stored value is the key)
    "theme": {"auto": T("Как в системе"), "light": T("Светлая"), "dark": T("Тёмная"), "contrast": T("Контрастная")},
    "accent": {"blue": T("Синий"), "green": T("Зелёный"), "orange": T("Оранжевый"), "violet": T("Фиолетовый"), "pink": T("Розовый")},
    "density": {"compact": T("Плотный"), "normal": T("Обычный"), "roomy": T("Свободный")},
    "ui_font": {"auto": T("Как задумано"), "condensed": T("Узкий"), "regular": T("Обычный"), "mono": T("Моноширинный")},
    "auto_focus": {"balanced": T("Поровну"), "latency": T("Отклик"), "speed": T("Скорость")},
}
FONT_CHOICES = {
    "auto": UI_FONTS,
    "condensed": (("Bahnschrift SemiCondensed", "Bahnschrift Condensed", "Arial Narrow") if IS_WIN else
                  ("Avenir Next Condensed", "Helvetica Neue") if IS_MAC else
                  ("DejaVu Sans Condensed", "Noto Sans Condensed", "Liberation Sans Narrow")),
    "regular": (("Segoe UI", "Arial") if IS_WIN else ("Helvetica Neue", "Arial") if IS_MAC else
                ("Noto Sans", "DejaVu Sans", "Liberation Sans")),
    "mono": (MONO,),
}
_HOST = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)$")


def clean_pro(raw):
    """Advanced settings made safe: (values, errors). A missing or wrong value falls back to its default and, when the
    user typed it, is named in `errors` ({key: what is wrong}) so the window can point at it."""
    out, errors = dict(PRO_DEFAULTS), {}
    if not isinstance(raw, dict):
        return out, errors
    for k, (default, kind, rule) in PRO_FIELDS.items():
        if k not in raw:
            continue
        v = raw[k]
        try:
            if kind == "bool":
                if not isinstance(v, bool):
                    raise ValueError(T("нужно «да» или «нет»"))
            elif kind == "int":
                if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str) and not v.strip().lstrip("-").isdigit()):
                    raise ValueError(T("нужно целое число"))
                v = int(v)
                if not rule[0] <= v <= rule[1]:
                    raise ValueError(T("число от {0} до {1}").format(rule[0], rule[1]))
            elif kind == "choice":
                if v not in rule:
                    raise ValueError(T("такого варианта нет"))
            elif kind == "apps":
                v = " ".join(clean_apps(v))
            elif kind == "color":
                v = str(v).strip()
                if v and not re.fullmatch(r"#?[0-9A-Fa-f]{6}", v):
                    raise ValueError(T("нужен цвет вида #1E3CFF или пусто"))
                v = ("#" + v.lstrip("#")).upper() if v else ""
            elif kind == "host":
                v = str(v).strip()
                if v == "" and k == "dns_local":
                    out[k] = v
                    continue
                if not _HOST.match(v) or any(int(p) > 255 for p in v.split(".") if v.replace(".", "").isdigit()):
                    raise ValueError(T("нужен адрес вида 1.1.1.1 или dns.google"))
            elif kind == "url":
                v = str(v).strip()
                if not re.match(r"^https?://[^\s/]+(/\S*)?$", v) or len(v) > 200:
                    raise ValueError(T("нужен адрес вида https://…"))
            out[k] = v
        except ValueError as e:
            errors[k] = str(e)
    return out, errors


def clean_apps(text):
    """Program names typed by the user ('chrome.exe, steam.exe' or one per line) as a clean list: no paths, no quotes,
    nothing a rule could choke on."""
    out = []
    for tok in re.split(r"[\s,;]+", str(text or "")):
        tok = tok.strip("\"'")
        tok = re.split(r"[\\/]", tok)[-1]  # a path pasted by mistake: the file name is what matters
        if tok and len(tok) <= 64 and re.fullmatch(r"[\w.()+\-]+", tok) and tok.lower() not in (n.lower() for n in out):
            out.append(tok)
    return out[:40]


DESIGN_SAFE = False  # set when the window could not be built with the saved design: the defaults are used then


def load_design():
    """The design settings in force, read from the settings file before any window exists. Never raises."""
    if DESIGN_SAFE:
        return dict(PRO_DEFAULTS)
    try:
        with open(SETTINGS, encoding="utf-8-sig") as f:
            return clean_pro(json.load(f).get("pro"))[0]
    except Exception:  # noqa: BLE001
        return dict(PRO_DEFAULTS)


def strip_ansi(text):
    """The core colours its messages with terminal codes; in a dialog they show up as garbage."""
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text or "")


def open_path(path):
    """Open a file or folder with whatever the system uses for it. False if that did not work."""
    try:
        if IS_WIN:
            os.startfile(path)  # noqa: S606
        else:
            subprocess.Popen(["open" if IS_MAC else "xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:  # noqa: BLE001
        return False


def open_url(url):
    try:
        import webbrowser
        return bool(webbrowser.open(url))
    except Exception:  # noqa: BLE001
        return False


# ---------- config build ----------
def local_dns_server(addr):
    """The sing-box DNS server entry named "local": a resolver at `addr`, or the system's own when there is no address."""
    return {"type": "udp", "tag": "local", "server": addr} if addr else {"type": "local", "tag": "local"}


def selector_default(tags, chosen):
    """What the "proxy" selector starts on: the server picked by hand, else (several servers) the "pick the best" group."""
    if len(tags) > 1 and (chosen == "AUTO" or chosen not in tags):
        return AUTO_TAG
    return chosen if chosen in tags else tags[0]


def build_config(outs, chosen, ru_direct, extra_direct, api=None, auto_tags=None, mixed_port=None, pro=None, xray_ports=None, region="RU"):
    """`api` = (port, secret): expose the core's local API so the window can show which server auto mode picked.
    `auto_tags`: the servers «Быстрейший из списка» may choose from (default: all); a hand-picked server is always allowed.
    `pro`: advanced settings (see PRO_FIELDS); missing or wrong values mean the defaults."""
    outs = [o for o in outs if not engines.is_xray(o) or (xray_ports or {}).get(o["tag"])]  # nothing serves the others
    if not outs:
        raise ValueError(T("нет серверов"))
    pro = clean_pro(pro)[0]
    outbounds, endpoints = engines.to_singbox(outs, xray_ports)
    tags = [o["tag"] for o in outs]
    # Every route ends in the "proxy" selector. A server is chosen, or changed while the connection is up, by telling the
    # selector (the core's local API), never by restarting the core: the tunnel stays, so not a packet can leave around it
    # while the server changes, and a server that does not answer means no traffic, not a direct one.
    # The "pick the best by itself" mode is a member of the selector too: the core's own urltest group.
    members, groups = list(tags), []
    if len(tags) > 1:
        groups.append({"type": "urltest", "tag": AUTO_TAG, "outbounds": [t for t in (auto_tags or tags) if t in tags] or tags,
                       "url": pro["auto_url"], "interval": f"{pro['auto_interval']}m", "tolerance": pro["auto_tolerance"]})
        members.append(AUTO_TAG)
    proxy_out = {"type": "selector", "tag": "proxy", "outbounds": members, "default": selector_default(tags, chosen),
                 "interrupt_exist_connections": True}
    domains = list(extra_direct)
    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    bypass, only = clean_apps(pro["bypass_apps"]), clean_apps(pro["vpn_only_apps"])
    if bypass:  # programs the user wants outside the VPN
        rules.insert(0, {"process_name": bypass, "outbound": "direct"})
    if xray_ports:  # the companion's own connections must leave around the tunnel, or they would loop back into it
        rules.insert(0, {"process_name": ["xray.exe", "xray"], "outbound": "direct"})
    if only:  # only these programs go through the VPN: the rest leaves directly
        rules.append({"process_name": only, "outbound": "proxy"})
    rule_sets = []
    mine = ru_direct and region in regions.NAMES  # this country's sites go without the VPN
    if mine:
        rules.append({"domain_suffix": regions.suffixes(region), "outbound": "direct"})
        for tag in regions.rule_sets(region):
            path = rule_path(tag)
            if path:
                rules.append({"rule_set": [tag], "outbound": "direct"})
                rule_sets.append({"tag": tag, "type": "local", "format": "binary", "path": path})
    if domains:
        rules.insert(3, {"domain_suffix": domains, "outbound": "direct"})
    dns_rules = []
    if bypass:
        dns_rules.append({"process_name": bypass, "server": "local"})
    if only:
        dns_rules.append({"process_name": only, "server": "remote"})
    if mine:
        dns_rules.append({"domain_suffix": regions.suffixes(region), "server": "local"})
        for rs in rule_sets:
            if rs["tag"].startswith("geosite-"):
                dns_rules.append({"rule_set": [rs["tag"]], "server": "local"})
    if domains:
        dns_rules.append({"domain_suffix": domains, "server": "local"})
    # proxy server hostnames must resolve via local dns (not through the tunnel)
    srv = sorted({o["server"] for o in outs if not engines.is_xray(o) and not re.match(r"^[\d.:]+$", o["server"])})
    if srv:
        dns_rules.insert(0, {"domain": srv, "server": "local"})
    cfg = {
        "log": {"level": pro["log_level"], "timestamp": True, "output": LOGFILE},
        "dns": {"servers": [{"type": "https", "tag": "remote", "server": pro["dns_remote"], "detour": "proxy"},
                            local_dns_server(pro["dns_local"] or regions.local_dns(region))],
                "rules": dns_rules, "final": "local" if only else "remote", "strategy": "ipv4_only"},
        "inbounds": [
            dict({"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True,
                  "strict_route": pro["strict_route"], "stack": pro["tun_stack"]},
                 **({} if IS_MAC else {"interface_name": TUN_NAME})),  # macOS names must be utunN: let the core pick
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixed_port or pro["mixed_port"]},
        ],
        "outbounds": outbounds + groups + [proxy_out, {"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "rule_set": rule_sets, "final": "direct" if only else "proxy", "auto_detect_interface": True,
                  "default_domain_resolver": "local"},
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    if not rule_sets:
        del cfg["route"]["rule_set"]
    if api:
        cfg["experimental"] = {"clash_api": {"external_controller": f"127.0.0.1:{api[0]}", "secret": api[1]}}
    return cfg


# ---------- GUI: palettes, accents and the settings that shape the look ----------
# Roles: INK = text, outlines, the hard shadow and the selected row; PAPER = fields and quiet buttons; BG = the ground;
# BLUE = the accent (a live connection, the main action, ticks) with ONACCENT for what is written on it.
THEMES = {
    "light": dict(INK="#12151B", PAPER="#F6F7F8", BG="#E3E5E8", MUTE="#555C67", RED="#C8102E", ONACCENT="#FFFFFF",
                  LOGBG="#12151B", LOGFG="#C9CED6", SUBON="#C9D1FF"),
    "dark": dict(INK="#E8EBF0", PAPER="#1B1F26", BG="#101318", MUTE="#97A0AD", RED="#FF6B7D", ONACCENT="#0D1015",
                 LOGBG="#0A0C10", LOGFG="#C9CED6", SUBON="#1B2144"),
    "contrast": dict(INK="#000000", PAPER="#FFFFFF", BG="#FFFFFF", MUTE="#222222", RED="#B00020", ONACCENT="#FFFFFF",
                     LOGBG="#000000", LOGFG="#F2F2F2", SUBON="#E3E8FF"),
}
ACCENTS = {"blue": ("#1E3CFF", "#7089FF"), "green": ("#087443", "#3DCB92"), "orange": ("#C2410C", "#FF8F52"),
           "violet": ("#6D28D9", "#A184FF"), "pink": ("#BE1E52", "#FF74A8")}  # (on a light theme, on the dark one)
assert set(ACCENTS) == set(PRO_FIELDS["accent"][2])
INK = "#12151B"
PAPER = "#F6F7F8"
BG = "#E3E5E8"
BLUE = "#1E3CFF"
MUTE = "#555C67"
RED = "#C8102E"
ONACCENT = "#FFFFFF"
LOGBG, LOGFG, SUBON = "#12151B", "#C9CED6", "#C9D1FF"
BORDER = 2  # the outline, in logical pixels
SHADOW = True  # the hard shadow of the main button
ANIM = True  # the blinking cursor while connecting
ROW_H = 30  # a row of the server list, in logical pixels
S = 1.0  # dpi scale, set once the root window exists
FAMILY_PREF = "auto"  # see FONT_CHOICES


def P(n):
    return max(1, int(round(n * S)))


def BW():
    """The outline's width in device pixels: at least 1, scaled like everything else."""
    return max(1, int(round(BORDER * S)))


def system_dark():
    """Does the operating system use its dark appearance? False when that cannot be told."""
    try:
        if IS_WIN:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
                return int(winreg.QueryValueEx(k, "AppsUseLightTheme")[0]) == 0
        if IS_MAC:
            out = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True, text=True, timeout=5)
            return out.stdout.strip().lower() == "dark"
        out = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"], capture_output=True, text=True, timeout=5)
        return "dark" in out.stdout.lower() or "dark" in os.environ.get("GTK_THEME", "").lower()
    except Exception:  # noqa: BLE001
        return False


def palette(d, dark=None):
    """The colours of the design settings `d`: a dict with the THEMES keys plus BLUE and the resolved theme name.
    `dark` = the system's appearance, asked for only when the theme is 'auto'."""
    theme = d.get("theme", "light")
    if theme == "auto":
        theme = "dark" if (system_dark() if dark is None else dark) else "light"
    t = dict(THEMES.get(theme, THEMES["light"]), theme=theme)
    light, bright = ACCENTS.get(d.get("accent", "blue"), ACCENTS["blue"])
    t["BLUE"] = d.get("accent_hex") or ("#0000D0" if theme == "contrast" else bright if theme == "dark" else light)
    return t


def apply_design(d, dark=None):
    """Set the module's palette and metrics from the design settings `d` (clean_pro output). Called once, before any
    widget exists: the widgets read these names when they are made."""
    global INK, PAPER, BG, BLUE, MUTE, RED, ONACCENT, LOGBG, LOGFG, SUBON, BORDER, SHADOW, ANIM, ROW_H, FAMILY_PREF
    t = palette(d, dark)
    theme = t["theme"]
    INK, PAPER, BG, MUTE, RED, ONACCENT = t["INK"], t["PAPER"], t["BG"], t["MUTE"], t["RED"], t["ONACCENT"]
    LOGBG, LOGFG, SUBON, BLUE = t["LOGBG"], t["LOGFG"], t["SUBON"], t["BLUE"]
    BORDER = int(d.get("border", 2))
    SHADOW, ANIM = bool(d.get("shadow", True)), bool(d.get("anim", True))
    ROW_H = {"compact": 24, "normal": 30, "roomy": 38}.get(d.get("density", "normal"), 30)
    FAMILY_PREF = d.get("ui_font", "auto")
    return theme


def is_admin():
    """Windows: the exe is elevated. Linux/macOS: the window never is; the core asks for rights when it starts."""
    if not IS_WIN:
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def karing_running():
    try:
        if IS_WIN:
            out = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=NOWIN).stdout.lower()
            return any(n in out for n in ("karing.exe", "karingservice.exe", "v2rayn.exe", "hiddify.exe", "nekoray.exe"))
        out = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=10).stdout.lower()
        return any(n in out for n in ("karing", "v2rayn", "hiddify", "nekoray", "throne"))
    except Exception:
        return False


# Hardware key codes of the V, C, X, A keys: they do not depend on the keyboard layout, unlike Tk's keysym.
CLIP_KEYS = ({86: "v", 67: "c", 88: "x", 65: "a"} if IS_WIN else
             {55: "v", 54: "c", 53: "x", 38: "a"} if IS_LINUX else {})  # macOS: native Command shortcuts


def enable_clipboard(w):
    """Ctrl+C/V/X/A and a right-click menu that work on ANY keyboard layout (Tk binds by keysym,
    so on the Russian layout Ctrl+V does nothing by default)."""
    def on_key(e):
        k = CLIP_KEYS.get(e.keycode)
        if k == "v":
            w.event_generate("<<Paste>>")
        elif k == "c":
            w.event_generate("<<Copy>>")
        elif k == "x":
            w.event_generate("<<Cut>>")
        elif k == "a":
            select_all()
        else:
            return None
        return "break"

    def select_all():
        if isinstance(w, tk.Text):
            w.tag_add("sel", "1.0", "end-1c")
        else:
            w.select_range(0, "end")
            w.icursor("end")

    menu = tk.Menu(w, tearoff=0)
    menu.add_command(label=T("Вставить"), command=lambda: w.event_generate("<<Paste>>"))
    menu.add_command(label=T("Копировать"), command=lambda: w.event_generate("<<Copy>>"))
    menu.add_command(label=T("Вырезать"), command=lambda: w.event_generate("<<Cut>>"))
    menu.add_separator()
    menu.add_command(label=T("Выделить всё"), command=select_all)

    def popup(e):
        w.focus_set()
        menu.tk_popup(e.x_root, e.y_root)
    if CLIP_KEYS:
        w.bind("<Control-KeyPress>", on_key)
    if IS_MAC:  # secondary click is Button-2 (or Control+click) on macOS
        w.bind("<Button-2>", popup)
        w.bind("<Control-Button-1>", popup)
    else:
        w.bind("<Button-3>", popup)


class Flat(tk.Frame):
    """Hard-edged text button: ink outline, inverts on hover and keyboard focus. `primary` = the default action (blue).
    The outline is the frame itself, the text a Label inside: a Label's own highlight ring is not painted on macOS."""
    _LABEL_OPTS = ("text", "font", "fg", "foreground", "bg", "background", "padx", "pady", "image", "anchor", "justify", "wraplength", "width")

    def __init__(self, master, text, command, font, primary=False):
        super().__init__(master, bg=INK, padx=BW(), pady=BW(), cursor="hand2", takefocus=1)
        self.rest = (BLUE, ONACCENT) if primary else (PAPER, INK)
        self.lab = tk.Label(self, text=text, font=font, bg=self.rest[0], fg=self.rest[1], padx=P(12), pady=P(4), cursor="hand2")
        self.lab.pack()
        self.command = command
        for w in (self, self.lab):
            w.bind("<Enter>", lambda e: self.paint(True))
            w.bind("<Leave>", lambda e: self.paint(False))
            w.bind("<Button-1>", lambda e: self.command())
        self.bind("<FocusIn>", lambda e: self.paint(True))
        self.bind("<FocusOut>", lambda e: self.paint(False))
        self.bind("<space>", lambda e: self.command())
        self.bind("<Return>", lambda e: self.command())

    def paint(self, lit):
        bg, fg = (INK, PAPER) if lit else self.rest
        self.lab.config(bg=bg, fg=fg)

    def configure(self, cnf=None, **kw):
        kw = dict(cnf or {}, **kw)
        lab = {k: kw.pop(k) for k in list(kw) if k in self._LABEL_OPTS}
        if lab:
            self.lab.configure(**lab)
        return super().configure(**kw) if kw else None
    config = configure

    def cget(self, key):
        return self.lab.cget(key) if key in self._LABEL_OPTS else super().cget(key)


class Check(tk.Frame):
    def __init__(self, master, text, var, font):
        super().__init__(master, bg=BG, cursor="hand2", takefocus=1, highlightthickness=BW(),
                         highlightbackground=BG, highlightcolor=BLUE)
        self.var = var
        ring = tk.Frame(self, bg=INK, padx=BW(), pady=BW())
        ring.pack(side="left")
        self.box = tk.Label(ring, width=2, font=font, bd=0)
        self.box.pack()
        self.lbl = tk.Label(self, text=text, font=font, bg=BG, fg=INK)
        self.lbl.pack(side="left", padx=P(10))
        for w in (self, ring, self.box, self.lbl):
            w.bind("<Button-1>", self.toggle)
        self.bind("<space>", self.toggle)
        var.trace_add("write", lambda *a: self.paint())
        self.paint()

    def toggle(self, e=None):
        self.var.set(not self.var.get())

    def paint(self):
        on = self.var.get()
        self.box.config(text="✓" if on else "", bg=BLUE if on else PAPER, fg=ONACCENT)


def field(parent, var, width, font):
    """A one-line text field with an even outline all round. Returns (outline frame, entry)."""
    box = tk.Frame(parent, bg=INK, padx=BW(), pady=BW())
    inner = tk.Frame(box, bg=PAPER)
    inner.pack(fill="x")
    e = tk.Entry(inner, textvariable=var, width=width, font=font, bg=PAPER, fg=INK, relief="flat", bd=0, highlightthickness=0,
                 insertbackground=INK, selectbackground=BLUE, selectforeground=ONACCENT)
    e.pack(fill="x", ipady=P(3), padx=P(6))
    return box, e


def ui_family(widget):
    """The interface font: the one the design settings ask for if this system has it, else the closest default."""
    fams = set(tkfont.families(widget))
    for name in FONT_CHOICES.get(FAMILY_PREF, UI_FONTS) + UI_FONTS:
        if name in fams:
            return name
    return UI_FONTS[-1]


class Dialog(tk.Toplevel):
    """A message box in the app's style. The system one looks like any other Windows dialog.
    A stripe on the left says what kind of message it is: blue = information or a question, red = an error.
    Enter = the default (blue) button, Esc = cancel. Blocks until closed; `result` is the index of the button."""
    def __init__(self, parent, text, buttons, kind="info", default=0, cancel=None, title=TITLE):
        super().__init__(parent)
        self.result = None
        self.withdraw()
        self.title(title)
        self.resizable(False, False)
        self.configure(bg=INK)  # the 3 px ink frame is this background showing around the body
        try:
            if IS_WIN:
                self.iconbitmap(os.path.join(BASE, "icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        set_window_icon(self)
        fam = ui_family(self)
        body = tk.Frame(self, bg=BG)
        body.pack(padx=BW() + P(1), pady=BW() + P(1))
        tk.Frame(body, bg=RED if kind == "error" else BLUE, width=P(10)).pack(side="left", fill="y")
        inner = tk.Frame(body, bg=BG)
        inner.pack(side="left", padx=P(22), pady=P(20))
        text = text if len(text) <= 1200 else text[:1197] + "…"  # a message taller than the screen could not be read or closed
        tk.Label(inner, text=text, font=(fam, FZ(11)), bg=BG, fg=INK, justify="left", anchor="w",
                 wraplength=P(400)).pack(fill="x", pady=(0, P(18)))
        row = tk.Frame(inner, bg=BG)
        row.pack(anchor="e")
        self.buttons = []
        for i, label in enumerate(buttons):
            b = Flat(row, label, lambda i=i: self.done(i), (fam, FZ(11)), primary=(i == default))
            b.pack(side="left", padx=(P(10), 0))
            self.buttons.append(b)
        self.bind("<Escape>", lambda e: self.done(cancel))
        self.bind("<Return>", lambda e: self.done(default))
        self.protocol("WM_DELETE_WINDOW", lambda: self.done(cancel))
        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        try:
            shown = bool(parent.winfo_viewable())
        except tk.TclError:
            shown = False
        if shown:  # centred over the window it belongs to
            x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 3
            self.transient(parent)
        else:  # parent hidden (tray) or not there yet: centre on the screen
            x, y = (self.winfo_screenwidth() - w) // 2, (self.winfo_screenheight() - h) // 3
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.deiconify()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.focus_force()  # Enter / Esc work without focusing a button, which would invert its colours
        self.wait_window(self)

    def done(self, i):
        self.result = i
        self.destroy()


def show_info(parent, text):
    Dialog(parent, text, ["OK"], "info", 0, 0)


def show_error(parent, text):
    Dialog(parent, text, ["OK"], "error", 0, 0)


def ask_yes_no(parent, text, yes=T("Да"), no=T("Нет")):
    return Dialog(parent, text, [yes, no], "question", 0, 1).result == 0


class Segmented(tk.Frame):
    """A row of hard-edged options of which one is selected (accent). Reads and writes a StringVar; `labels` maps an
    option to the text shown for it."""
    def __init__(self, master, options, var, font, labels=None):
        super().__init__(master, bg=INK, padx=BW(), pady=BW())  # the frame is the outline and, in the gaps, the dividers
        self.var, self.buttons = var, {}
        for i, o in enumerate(options):
            b = tk.Label(self, text=(labels or {}).get(o, o), font=font, padx=P(10), pady=P(3), cursor="hand2", bd=0)
            b.pack(side="left", padx=(0 if i == 0 else BW(), 0))
            b.bind("<Button-1>", lambda e, o=o: var.set(o))
            self.buttons[o] = b
        var.trace_add("write", lambda *a: self.paint())
        self.paint()

    def paint(self):
        for o, b in self.buttons.items():
            on = self.var.get() == o
            b.config(bg=BLUE if on else PAPER, fg=ONACCENT if on else INK)


# (key, label, widget, hint) per section of the advanced settings window; the order here is the order on screen
PRO_NARROW = ("ui_scale", "border", "win_width", "alpha", "accent_hex")  # short numbers and a colour
PRO_LAYOUT = (
    (T("Оформление"), (
        ("theme", T("Тема"), "choice", T("«Как в системе» берёт светлую или тёмную у вашей системы.")),
        ("accent", T("Цвет акцента"), "choice", T("В контрастной теме акцент всегда синий, если не задан свой цвет.")),
        ("accent_hex", T("Свой цвет акцента"), "entry", T("Вида #1E3CFF. Если заполнено, берётся он, а не цвет из списка.")),
        ("ui_scale", T("Масштаб интерфейса, %"), "entry", T("От 70 до 180. Поверх масштаба самой системы.")),
        ("density", T("Список серверов"), "choice", None),
        ("ui_font", T("Шрифт"), "choice", T("«Как задумано» — узкий шрифт системы; если его нет, берётся ближайший.")),
        ("border", T("Толщина рамок, пикселей"), "entry", T("От 1 до 4.")),
        ("win_width", T("Ширина окна, пикселей"), "entry", T("От 380 до 900. Если не помещается текст, окно станет шире само.")),
        ("shadow", T("Тень у большой кнопки"), "check", None),
        ("anim", T("Мигающий курсор при подключении"), "check", None),
        ("remember_window", T("Помнить, где стояло окно"), "check", None),
        ("on_top", T("Окно поверх остальных"), "check", None),
        ("alpha", T("Непрозрачность окна, %"), "entry", T("100 — совсем непрозрачное. На некоторых Linux не работает.")),
    )),
    (T("Программы"), (
        ("bypass_apps", T("Эти программы работают мимо VPN"), "entry", T("Имена через пробел, например: steam.exe telegram.exe. Нужно, если программа с VPN не работает или тормозит.")),
        ("vpn_only_apps", T("Через VPN только эти программы"), "entry", T("Если заполнено, через VPN идут только они, всё остальное напрямую. Имена так же, через пробел.")),
    )),
    (T("Соединение"), (
        ("mixed_port", T("Порт локального прокси"), "entry", T("Для программ, которым нужен адрес прокси: 127.0.0.1 и этот порт.")),
        ("tun_stack", T("Режим сетевого адаптера"), "choice", T("Если сайты не открываются или тормозят, попробуй system или gvisor.")),
        ("strict_route", T("Не пускать трафик в обход VPN"), "check", None),
        ("autoconnect", T("Подключаться сразу при запуске программы"), "check", T("Вместе с «Запускать при входе в систему» VPN включается сам, как только вы вошли, а окно прячется в трей.")),
        ("merge_subs", T("Спрашивать подписку как разные программы и объединять серверы"), "check", T("Провайдер отдаёт разным программам разные списки: так в списке будет больше серверов. Если провайдер считает запросы, выключи.")),
        ("use_xray", T("Запускать Xray для серверов XHTTP и похожих"), "check", T("Их ядро не умеет, поэтому рядом работает Xray. Без файла Xray или с выключенной галочкой такие серверы пропускаются.")),
        ("auto_reconnect", T("Подключаться заново, если соединение оборвалось"), "check", None),
    )),
    ("DNS", (
        ("dns_remote", T("DNS через VPN"), "entry", T("Адрес или имя DNS-сервера для обычных сайтов.")),
        ("dns_local", T("DNS для сайтов своей страны"), "entry", T("Работает мимо VPN, когда включено «Сайты страны напрямую». Пусто: DNS выбранной страны, а где его нет, DNS системы.")),
    )),
    (T("Быстрейший из списка"), (
        ("auto_focus", T("Что важнее при выборе сервера"), "choice", T("Отклик: звонки, игры, сайты, мессенджеры. Скорость: видео и загрузки. Поровну: и то и другое, хороший вариант на каждый день.")),
        ("auto_speed", T("Учитывать скорость, а не только отклик"), "check", T("Сразу после подключения программа мерит скорость у лучших по отклику серверов (несколько секунд, десятки мегабайт) и повторяет раз в полчаса.")),
        ("auto_url", T("Адрес для проверки отклика"), "entry", None),
        ("auto_interval", T("Проверять каждые, минут"), "entry", None),
        ("auto_tolerance", T("Менять сервер, если другой лучше на, мс"), "entry", T("Больше число: реже переключений.")),
    )),
    (T("Тест скорости"), (
        ("test_top", T("У скольких лучших по пингу мерить скорость"), "entry", None),
        ("test_secs", T("Секунд на каждый сервер"), "entry", None),
        ("test_parallel", T("Сколько серверов пинговать одновременно"), "entry", T("Скорость всегда меряется по одному серверу: иначе они делят канал и цифры врут.")),
    )),
    (T("Журнал"), (
        ("log_level", T("Подробность журнала ядра"), "choice", T("debug пишет всё подряд, error только ошибки.")),
    )),
)


class Preview(tk.Canvas):
    """A small picture of the main button and two controls in the colours the form currently holds, so a theme or an
    accent can be judged before the program is restarted."""
    def __init__(self, master, family, values):
        super().__init__(master, height=P(104), highlightthickness=0, bd=0)
        self.family, self.values = family, values
        self.bind("<Configure>", lambda e: self.draw())

    def draw(self):
        self.delete("all")
        try:
            v = clean_pro({k: var.get() for k, var in self.values().items()})[0]
            t = palette(v)
        except Exception:  # noqa: BLE001
            return
        bw = max(1, int(round(v["border"] * S)))
        self.configure(bg=t["BG"])
        w, o = max(self.winfo_width(), P(300)), (P(8) if v["shadow"] else 0)
        x1, y1 = w - P(16) - o, P(60)
        if o:
            self.create_rectangle(P(8) + o, P(8) + o, x1 + o, y1 + o, fill=t["INK"], outline=t["INK"])
        self.create_rectangle(P(8), P(8), x1, y1, fill=t["PAPER"], outline=t["INK"], width=max(1, int(bw * 1.5)))
        self.create_text(P(22), P(26), text=T("Подключить"), anchor="w", fill=t["INK"], font=(self.family, 15, "bold"))
        self.create_text(P(22), P(47), text=T("Быстрейший из списка"), anchor="w", fill=t["MUTE"], font=(self.family, 9))
        bx = P(8)
        for text, fill, fg in ((T("Обновить"), t["PAPER"], t["INK"]), (T("Выбрано"), t["BLUE"], t["ONACCENT"]), (T("Ошибка"), t["RED"], t["ONACCENT"])):
            tw = P(78)
            self.create_rectangle(bx, P(74), bx + tw, P(98), fill=t["INK"], outline=t["INK"])
            self.create_rectangle(bx + bw, P(74) + bw, bx + tw - bw, P(98) - bw, fill=fill, outline=fill)
            self.create_text(bx + tw // 2, P(86), text=text, fill=fg, font=(self.family, 9))
            bx += tw + P(8)


class ProWindow(tk.Toplevel):
    """The advanced settings, in a window of their own: it opens with a double click on «Настройки». Nothing here is
    needed by an ordinary user; a value that does not fit is pointed at and not saved, and a value the core cannot
    work with never stops a connection (prepare_config falls back to the defaults)."""
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title(TITLE + T(" · расширенные настройки"))
        self.configure(bg=BG)
        try:
            if IS_WIN:
                self.iconbitmap(os.path.join(BASE, "icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        set_window_icon(self)
        f_b, f_s, f_h, fam = app.f_b, app.f_s, app.f_h, app.fam
        self.f_b = f_b
        self.vars, self.boxes, self.labels = {}, {}, {}
        cur = app.pro()

        # the form scrolls (small screens), the buttons below it do not
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        self.sb = ttk.Scrollbar(outer, orient="vertical", style="Flat.Vertical.TScrollbar", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(self.canvas, bg=BG)
        win = self.canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(win, width=e.width))
        pad = tk.Frame(body, bg=BG)
        pad.pack(fill="both", expand=True, padx=P(22), pady=P(18))

        tk.Label(pad, text=T("Расширенные настройки"), font=f_h, bg=BG, fg=INK).pack(anchor="w")
        self.preview = None
        tk.Label(pad, text=T("Для опытных пользователей. Обычно здесь ничего менять не нужно. Если значение не подойдёт, "
                           "программа вернёт обычное и всё равно подключится."), font=f_s, bg=BG, fg=MUTE, wraplength=P(500),
                 justify="left", anchor="w").pack(anchor="w", pady=(P(4), 0))
        for title, rows in PRO_LAYOUT:
            tk.Label(pad, text=title, font=f_h, bg=BG, fg=INK).pack(anchor="w", pady=(P(18), P(6)))
            if title == T("Оформление"):
                self.preview = Preview(pad, fam, lambda: self.vars)
                self.preview.pack(fill="x", pady=(0, P(10)))
            for key, label, kind, hint in rows:
                self.add_row(pad, key, label, kind, hint, cur[key], fam)
        if self.preview:
            for var in self.vars.values():
                var.trace_add("write", lambda *a: self.preview.draw())

        # fixed footer
        self.msg = tk.Label(self, text="", font=f_s, bg=BG, fg=MUTE, anchor="w", justify="left", wraplength=P(500))
        self.msg.pack(fill="x", padx=P(22), pady=(P(8), 0))
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=P(22), pady=P(14))
        tools = tk.Frame(foot, bg=BG)
        tools.pack(fill="x")
        Flat(tools, T("По умолчанию"), self.reset, f_s).pack(side="left")
        Flat(tools, T("Папка данных"), lambda: self.tool(DATA), f_s).pack(side="left", padx=(P(8), 0))
        Flat(tools, T("Журнал"), lambda: self.tool(LOGFILE), f_s).pack(side="left", padx=(P(8), 0))
        acts = tk.Frame(foot, bg=BG)
        acts.pack(fill="x", pady=(P(8), 0))
        Flat(acts, T("Закрыть"), self.close, f_s).pack(side="right")
        Flat(acts, T("Применить"), self.apply, f_s, primary=True).pack(side="right", padx=(0, P(8)))
        self.restart_btn = Flat(acts, T("Перезапустить"), self.restart, f_s)  # shown once something needs a restart

        self.bind("<Escape>", lambda e: self.close())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.update_idletasks()
        w = min(max(P(580), pad.winfo_reqwidth() + P(44) + P(16)), max(P(480), self.winfo_screenwidth() - P(40)))
        need = body.winfo_reqheight() + self.msg.winfo_reqheight() + foot.winfo_reqheight() + P(30)
        h = min(need, max(P(420), self.winfo_screenheight() - P(160)))
        if need > h:  # does not fit the screen: scroll
            self.sb.pack(side="right", fill="y")
            for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.bind(ev, self.on_wheel)
        x = app.winfo_rootx() + app.winfo_width() + P(12)
        if x + w > self.winfo_screenwidth():
            x = max(0, app.winfo_rootx() + P(40))
        y = max(0, min(app.winfo_rooty(), self.winfo_screenheight() - h - P(80)))
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(P(480), P(360))
        self.focus_force()

    def on_wheel(self, e):
        step = -1 if (getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0) else 1
        self.canvas.yview_scroll(step * 2, "units")

    def add_row(self, parent, key, label, kind, hint, value, fam):
        f_b, f_s = self.app.f_b, self.app.f_s
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(0, P(6)))
        if kind == "check":
            var = tk.BooleanVar(value=bool(value))
            Check(row, label, var, f_b).pack(anchor="w")
        else:
            wide = key in ("auto_url", "theme", "accent", "ui_font", "bypass_apps", "vpn_only_apps")  # these need the whole width: label above; the rest sit beside their label
            line = tk.Frame(row, bg=BG)
            line.pack(fill="x")
            lab = tk.Label(line, text=label, font=f_b, bg=BG, fg=INK, anchor="w", justify="left", wraplength=P(330 if not wide else 500))
            lab.pack(fill="x") if wide else lab.pack(side="left")
            self.labels[key] = lab
            var = tk.StringVar(value=str(value))
            if kind == "choice":
                seg = Segmented(line, PRO_FIELDS[key][2], var, f_b, PRO_LABELS.get(key))
                seg.pack(side="right") if not wide else seg.pack(anchor="w", pady=(P(4), 0))
            else:
                box, e = field(line, var, 50 if key in ("auto_url", "bypass_apps", "vpn_only_apps") else 10 if key in PRO_NARROW else 14, f_b)
                box.pack(fill="x", pady=(P(3), 0)) if wide else box.pack(side="right")
                e.bind("<Return>", lambda ev: self.apply())
                enable_clipboard(e)
                self.boxes[key] = box
                var.trace_add("write", lambda *a, k=key: self.boxes[k].config(bg=INK))
        if hint:
            tk.Label(row, text=hint, font=f_s, bg=BG, fg=MUTE, anchor="w", justify="left", wraplength=P(500)).pack(fill="x", pady=(P(2), 0))
        self.vars[key] = var

    def values(self):
        return {k: v.get() for k, v in self.vars.items()}

    def apply(self):
        raw = self.values()
        clean, errors = clean_pro(raw)
        for k, box in self.boxes.items():
            box.config(bg=RED if k in errors else INK)
        if errors:
            k = next(iter(errors))
            label = self.labels[k].cget("text") if k in self.labels else k
            self.msg.config(text=T("Не сохранено. {0}: {1}.").format(label, errors[k]), fg=RED)
            return False
        self.app.cfg["pro"] = {k: v for k, v in clean.items() if v != PRO_DEFAULTS[k]}  # only what differs from the defaults
        self.app.save(sources=False)
        for k, var in self.vars.items():
            var.set(clean[k] if isinstance(var, tk.BooleanVar) else str(clean[k]))
        self.app.apply_live()
        self.app.sort_rows()  # the order of the list follows what the auto mode is told to care about
        self.app.apply_smart()
        note = T("Сохранено.")
        if self.app.state != "off":
            note += T(" Настройки соединения заработают при следующем подключении.")
            self.app.say(T("Расширенные настройки сохранены. Настройки соединения заработают при следующем подключении."))
        if any(clean[k] != self.app.design[k] for k in RESTART_KEYS):
            note += T(" Тема, цвета, масштаб, шрифт и рамки применятся после перезапуска программы.")
            self.restart_btn.pack(side="right", padx=(0, P(8)))
        else:
            self.restart_btn.pack_forget()
        self.msg.config(text=note, fg=MUTE)
        return True

    def restart(self):
        if self.apply():
            self.app.restart()

    def reset(self):
        for k, var in self.vars.items():
            var.set(PRO_DEFAULTS[k] if isinstance(var, tk.BooleanVar) else str(PRO_DEFAULTS[k]))
        self.msg.config(text=T("Поля вернулись к обычным значениям. Нажми «Применить», чтобы сохранить."), fg=MUTE)

    def tool(self, path):
        if os.path.exists(path) and open_path(path):
            return
        self.msg.config(text=T("Этого файла ещё нет: он появится после первого подключения.") if path == LOGFILE
                        else T("Не получилось открыть."), fg=RED)

    def close(self):
        self.app.pro_win = None
        self.destroy()


class SetupDialog(tk.Toplevel):
    """Language and country, in the program's style: shown at the very first start, and from the «Страна» button. The sites of
    the chosen country go without the VPN. `result` = (language, country code or 'NONE'), None if closed without choosing."""
    def __init__(self, parent, region, first=False, suggest=""):
        super().__init__(parent)
        self.withdraw()
        self.result = None
        self.first = first
        self.start_lang = i18n.LANG
        self.lang = tk.StringVar(value=i18n.LANG)
        self.query = tk.StringVar()
        self.picked = region if (regions.valid(region) and region) else (suggest if regions.valid(suggest) and suggest else regions.NONE)
        self.configure(bg=INK)
        self.resizable(False, False)
        try:
            if IS_WIN:
                self.iconbitmap(os.path.join(BASE, "icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        set_window_icon(self)
        self.fam = ui_family(self)
        self.body = tk.Frame(self, bg=BG)
        self.body.pack(padx=BW() + P(1), pady=BW() + P(1))
        self.lang.trace_add("write", lambda *a: self.relanguage())
        self.build()
        self.bind("<Escape>", lambda e: self.close(False))
        self.protocol("WM_DELETE_WINDOW", lambda: self.close(first))
        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        try:
            shown = bool(parent.winfo_viewable())
        except tk.TclError:
            shown = False
        if shown:
            x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
            y = parent.winfo_rooty() + max(P(10), (parent.winfo_height() - h) // 3)
            self.transient(parent)
        else:
            x, y = (self.winfo_screenwidth() - w) // 2, (self.winfo_screenheight() - h) // 3
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.deiconify()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.focus_force()
        self.wait_window(self)

    def build(self):
        for w in self.body.winfo_children():
            w.destroy()
        self.title(TITLE)
        f_b, f_s = (self.fam, FZ(11)), (self.fam, FZ(10))
        pad = tk.Frame(self.body, bg=BG)
        pad.pack(padx=P(22), pady=P(18))
        tk.Label(pad, text=T("Добро пожаловать") if self.first else T("Язык и страна"), font=(self.fam, FZ(14), "bold"), bg=BG, fg=INK,
                 anchor="w").pack(fill="x")
        lrow = tk.Frame(pad, bg=BG)
        lrow.pack(fill="x", pady=(P(12), P(8)))
        tk.Label(lrow, text=T("Язык"), font=f_b, bg=BG, fg=INK).pack(side="left")
        Segmented(lrow, tuple(i18n.LANGS), self.lang, f_b, i18n.LANGS).pack(side="right")
        tk.Label(pad, text=T("Сайты выбранной страны (банки, госуслуги, местные сервисы) открываются напрямую, без VPN, всё остальное идёт "
                             "через VPN. Страну можно поменять потом."), font=f_s, bg=BG, fg=MUTE, justify="left", anchor="w",
                 wraplength=P(420)).pack(fill="x", pady=(0, P(8)))
        tk.Label(pad, text=T("Страна"), font=f_b, bg=BG, fg=INK, anchor="w").pack(fill="x")
        box, entry = field(pad, self.query, 30, f_b)
        box.pack(fill="x", pady=(P(4), P(6)))
        entry.bind("<KeyRelease>", lambda e: self.refill())
        enable_clipboard(entry)
        frame = tk.Frame(pad, bg=INK, padx=BW(), pady=BW())
        frame.pack(fill="x")
        inner = tk.Frame(frame, bg=PAPER)
        inner.pack(fill="x")
        self.list = tk.Listbox(inner, height=9, font=f_b, bg=PAPER, fg=INK, selectbackground=INK, selectforeground=PAPER, relief="flat", bd=0,
                               highlightthickness=0, activestyle="none", exportselection=False)
        sb = ttk.Scrollbar(inner, orient="vertical", style="Flat.Vertical.TScrollbar", command=self.list.yview)
        self.list.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.list.pack(side="left", fill="x", expand=True)
        self.list.bind("<<ListboxSelect>>", lambda e: self.on_pick())
        self.list.bind("<Double-1>", lambda e: self.close(True))
        self.list.bind("<Return>", lambda e: self.close(True))
        self.bind("<Return>", lambda e: self.close(True))
        row = tk.Frame(pad, bg=BG)
        row.pack(fill="x", pady=(P(14), 0))
        Flat(row, T("Готово"), lambda: self.close(True), f_s, primary=True).pack(side="right")
        if not self.first:
            Flat(row, T("Отмена"), lambda: self.close(False), f_s).pack(side="right", padx=(0, P(8)))
        self.refill()

    def refill(self):
        """The list for the words typed so far; the chosen country stays chosen if it is still there."""
        none_label = T("Нигде: весь трафик через VPN")
        rows = [(regions.NONE, none_label)] + regions.search(self.query.get())
        if self.query.get().strip():
            rows = [r for r in rows if r[0] != regions.NONE or self.query.get().strip().lower() in none_label.lower()]
        self.rows = rows
        self.list.delete(0, "end")
        for _, n in rows:
            self.list.insert("end", n)
        for i, (c, _) in enumerate(rows):
            if c == self.picked:
                self.list.selection_set(i)
                self.list.see(i)
                break

    def on_pick(self):
        sel = self.list.curselection()
        if sel:
            self.picked = self.rows[sel[0]][0]

    def relanguage(self):
        i18n.set_language(self.lang.get())
        self.build()

    def close(self, ok):
        if ok:
            self.on_pick()
            self.result = (self.lang.get(), self.picked)
        else:
            i18n.set_language(self.start_lang)  # nothing was chosen: the language stays what it was
        self.destroy()


def set_window_icon(win):
    """Windows: give the window icons at the exact sizes this display scaling uses: 16 px for the title bar and 24 px
    for the taskbar at 100 % (30 / 36 / 48 at 125 / 150 / 200 %). Tk's iconbitmap hands Windows only a 16 and a 32 px
    icon and the shell stretches those to the taskbar size, which blurred the edges."""
    if not IS_WIN:
        return
    try:
        win.update_idletasks()
        user = ctypes.windll.user32
        user.GetParent.restype = ctypes.c_void_p
        user.GetParent.argtypes = [ctypes.c_void_p]
        hwnd = user.GetParent(win.winfo_id()) or win.winfo_id()
        try:
            dpi = user.GetDpiForSystem()
        except Exception:  # noqa: BLE001
            dpi = 96
        user.LoadImageW.restype = ctypes.c_void_p
        user.LoadImageW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        user.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p]
        path = os.path.join(BASE, "icon.ico")
        for which, base in ((0, 16), (1, 24)):  # ICON_SMALL (title bar), ICON_BIG (taskbar)
            size = round(base * dpi / 96)
            handle = user.LoadImageW(None, path, 1, size, size, 0x10)  # IMAGE_ICON, LR_LOADFROMFILE
            if handle:
                user.SendMessageW(hwnd, 0x80, which, handle)  # WM_SETICON
    except Exception:  # noqa: BLE001
        pass


class FlagImages:
    """Tk images of the flat flags (see flags.py), made on first use, one per country, and kept alive here."""
    def __init__(self, master):
        self.master = master  # images belong to this window's Tk, not to whichever root was created first
        self.cache = {}

    def get(self, code):
        code = code if code in flags.FLAGS else "??"
        img = self.cache.get(code)
        if img is None:
            w, h = P(24), P(16)
            img = tk.PhotoImage(master=self.master, width=w + P(9), height=h)  # transparent right margin = gap before the text
            img.put(flags.to_tk_data(flags.render(code, w, h, max(1, P(1)), accent=BLUE, ink=INK)))
            self.cache[code] = img
        return img

    def for_tag(self, tag):
        return self.get(flags.code_for(tag))


class Power(tk.Canvas):
    """The one loud element: a slab with a hard shadow that presses in, fills blue when connected."""
    def __init__(self, master, command, fam):
        self.H = P(132)
        super().__init__(master, height=self.H, bg=BG, highlightthickness=0, cursor="hand2", takefocus=1)
        self.command = command
        self.fam = fam
        self.state, self.server, self.clock = "off", "", ""
        self.flag = None  # Tk image of the current server's flag
        self.blink, self.pressed, self.focused = True, False, False
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<ButtonPress-1>", self.down)
        self.bind("<ButtonRelease-1>", self.up)
        self.bind("<FocusIn>", lambda e: self.set_focus(True))
        self.bind("<FocusOut>", lambda e: self.set_focus(False))
        self.bind("<space>", lambda e: self.command())
        self.bind("<Return>", lambda e: self.command())

    def set_focus(self, v):
        self.focused = v
        self.draw()

    def set(self, state, server, clock, blink=True, flag=None):
        if (state, server, clock, blink, flag) != (self.state, self.server, self.clock, self.blink, self.flag):
            self.state, self.server, self.clock, self.blink, self.flag = state, server, clock, blink, flag
            self.draw()

    def down(self, e):
        self.pressed = True
        self.draw()

    def up(self, e):
        self.pressed = False
        self.draw()
        if 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.H:
            self.command()

    def draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.H
        o = P(9) if SHADOW else P(3)  # without a shadow the slab still presses in a little
        d = o if self.pressed else 0
        x1, y1 = w - o + d, h - o + d
        if SHADOW:
            self.create_rectangle(o, o, w, h, fill=INK, outline=INK)
        on = self.state == "on"
        fill = BLUE if on else PAPER
        fg = ONACCENT if on else INK
        sub = SUBON if on else MUTE
        self.create_rectangle(d + 2, d + 2, x1, y1, fill=fill, outline=INK, width=max(1, int(round(BORDER * 1.5 * S))))
        title = {"off": T("Подключить"), "connecting": T("Подключаю"), "on": T("Отключить")}[self.state]
        if self.state == "connecting":
            title += " █" if self.blink else ""
        self.create_text(d + P(24), d + P(40), text=title, anchor="w", fill=fg, font=(self.fam, FZ(24), "bold"))
        if self.clock:
            self.create_text(x1 - P(22), d + P(40), text=self.clock, anchor="e", fill=fg, font=(MONO, FZ(16), "bold"))
        name = self.server if len(self.server) <= 40 else self.server[:39] + "…"
        tx = d + P(24)
        if self.flag is not None:
            self.create_image(tx, y1 - P(30), image=self.flag, anchor="w")
            tx += self.flag.width()  # includes the transparent gap
        self.create_text(tx, y1 - P(30), text=name, anchor="w", fill=sub, font=(self.fam, FZ(11)))
        if self.focused:
            self.create_rectangle(d + P(10), d + P(10), x1 - P(8), y1 - P(8), outline=fg, dash=(3, 3))


PROTO = {"shadowsocks": "SS", "hysteria2": "HY2", "hysteria": "HY1", "vless": "VLESS", "vmess": "VMESS", "trojan": "TROJAN",
         "tuic": "TUIC", "anytls": "ANYTLS", "socks": "SOCKS"}

# ---------- speed test ----------
TEST_BASE_PORT = 21080
HOME_PORT = TEST_BASE_PORT - 1
# Countries where blocking happens: a server that exits there gives no way round it. If the user is in one of them,
# «Быстрейший из списка» passes over servers that exit in the same country; elsewhere such a server is as good as any.
NO_BYPASS = ("RU",)
# Checked direct from Russia (2026-10-30): Cloudflare 403s the default Python User-Agent and caps `bytes` at 50 MB;
# thinkbroadband answers 403 to everything; speed.hetzner.de no longer resolves. OVH is slow (7-10 Mbit/s), so it is last.
# Russian hosts are last-resort fallbacks: the test runs through servers abroad, where they can be slow or filtered.
SPEED_URLS = ("https://speed.cloudflare.com/__down?bytes=50000000",
              "http://cachefly.cachefly.net/50mb.test",
              "https://proof.ovh.net/files/100Mb.dat",
              "https://speedtest.selectel.ru/100MB",
              "https://mirror.truenetwork.ru/ubuntu/ls-lR.gz")
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36")
PING_URL = "https://www.gstatic.com/generate_204"
# Cloudflare answers with the country it sees the request come from: through a server that is its real exit country.
EXIT_URLS = ("https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace")
TOP_FOR_SPEED = 8


TUN_NAME = "FimaTUN"
DOUBLE_CLICK_MS = 250  # how long a single click on «Настройки» waits for a possible second one


def build_test_config(outs, nic=None, skip=(), xray_ports=None):
    """One local mixed inbound per server, each pinned to its server. No TUN, no admin needed.
    `nic` = physical adapter name: bind outbound sockets to it so the test bypasses a running VPN.
    `skip` = row numbers the core refused: left out, the others keep their ports."""
    live = [i for i in range(len(outs)) if i not in skip and (not engines.is_xray(outs[i]) or (xray_ports or {}).get(outs[i]["tag"]))]
    outbounds, endpoints = engines.to_singbox([outs[i] for i in live], xray_ports)
    inbounds = [{"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1", "listen_port": TEST_BASE_PORT + i} for i in live]
    rules = [{"inbound": [f"in{i}"], "outbound": outs[i]["tag"]} for i in live]
    cfg = {"log": {"level": "warn", "output": TESTLOG},
           "dns": {"servers": [local_dns_server(LOCAL_DNS)], "strategy": "ipv4_only"},
           "inbounds": inbounds, "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
           "route": {"rules": rules, "final": "direct", "default_domain_resolver": "local"}}
    if endpoints:
        cfg["endpoints"] = endpoints
    if nic:
        cfg["route"]["default_interface"] = nic
    return cfg


def core_check(cfg_path):
    """(ok, message) of `sing-box check` for a config file."""
    try:
        chk = subprocess.run([CORE, "check", "-c", cfg_path], capture_output=True, text=True, creationflags=NOWIN, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:  # core missing (antivirus), blocked, hung
        return False, T("ядро не запускается: {0}").format(e)
    return chk.returncode == 0, strip_ansi(chk.stderr or chk.stdout).strip()


def drop_downloaded_rules():
    """Delete the downloaded RU lists: rule_path() then falls back to the copy bundled with the program."""
    try:
        for name in os.listdir(RULES_DIR):
            if name.endswith(".srs"):
                os.remove(os.path.join(RULES_DIR, name))
    except OSError:
        pass


def system_proxy():
    """Windows: (switched on?, 'host:port' text) of the proxy in 'Internet Settings' that browsers and many programs
    obey. Elsewhere (False, "")."""
    if not IS_WIN:
        return False, ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            on = int(winreg.QueryValueEx(k, "ProxyEnable")[0]) == 1
            return on, (str(winreg.QueryValueEx(k, "ProxyServer")[0]) if on else "")
    except (OSError, ValueError):
        return False, ""


def proxy_endpoints(server):
    """'127.0.0.1:3067' or 'http=a:1;https=b:2' -> [('127.0.0.1', 3067)]"""
    out = []
    for part in str(server).split(";"):
        part = re.sub(r"^[A-Za-z]+://", "", part.split("=", 1)[-1].strip())
        host, _, port = part.rpartition(":")
        if host and port.isdigit():
            out.append((host.strip("[]"), int(port)))
    return out


def local_proxy_state():
    """(address, alive) of the system proxy if it sits on this computer, else (None, False). A proxy that nobody
    listens on is what a closed or crashed VPN client leaves behind: browsers then show no internet at all."""
    on, server = system_proxy()
    if not on:
        return None, False
    for host, port in proxy_endpoints(server):
        if host in ("127.0.0.1", "localhost", "::1"):
            try:
                socket.create_connection((host, port), 0.7).close()
                return f"{host}:{port}", True
            except OSError:
                return f"{host}:{port}", False
    return None, False


def disable_system_proxy():
    """Switch the Windows proxy off and tell running programs. True if it worked."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
        return True
    except Exception:  # noqa: BLE001
        return False


def pick_port(preferred):
    """`preferred` if it is free on loopback, else any free one (another program may sit on 2080)."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", preferred))
        return preferred
    except OSError:
        return free_port()
    finally:
        s.close()


def merge_cfg(defaults, loaded):
    """Saved settings laid over the defaults; a value of the wrong type (a hand-edited or damaged file) is ignored
    instead of crashing the window at start."""
    cfg = dict(defaults)
    if not isinstance(loaded, dict):
        return cfg
    for k, v in loaded.items():
        d = defaults.get(k)
        if k not in defaults:
            cfg[k] = v
        elif d is None:
            ok = v is None or isinstance(v, bool)
        elif isinstance(d, bool):
            ok = isinstance(v, bool)
        elif isinstance(d, (int, float)):
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        else:
            ok = isinstance(v, type(d))
        if k in defaults and ok:
            cfg[k] = v
    return cfg


def clean_subs(raw):
    """The cached subscriptions: only well-formed entries with usable servers survive."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for url, e in raw.items():
        if isinstance(url, str) and isinstance(e, dict) and isinstance(e.get("outs"), list):
            e = dict(e)
            e["outs"] = [o for o in e["outs"] if valid_outbound(o)]
            if not isinstance(e.get("info"), dict):
                e["info"] = {}
            if isinstance(e.get("time"), bool) or not isinstance(e.get("time"), (int, float)):
                e["time"] = 0
            out[url] = e
    return out


def trim_logs():
    """The core logs every connection: over days that is hundreds of megabytes. Keep the files small."""
    try:
        if os.path.getsize(LOGFILE) > 16 * 1024 * 1024:
            open(LOGFILE, "w").close()  # the core appends: it goes on from the start
            return True
    except OSError:
        pass
    return False


def salvage_outs(outs, work_path=None):
    """The core refused the whole config: ask it about each server on its own. Returns (good, bad), so one server
    with data the core does not accept costs only itself. Slow (one core start per server): only for that case."""
    work_path = work_path or CHECKCFG
    good, bad = [], []
    for o in outs:
        write_json(work_path, build_config([o], o["tag"], False, [], xray_ports={o["tag"]: 1} if engines.is_xray(o) else None))
        (good if core_check(work_path)[0] else bad).append(o)
    return good, bad


def clean_domains(text):
    """Domains typed into «Свои домены»: separators of any kind, pasted links and wildcards are tolerated, what is
    not a domain is dropped (one stray character used to make the core refuse the whole config)."""
    out = []
    for tok in re.split(r"[\s,;]+", text or ""):
        tok = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", tok.strip().lower())
        tok = re.split(r"[/?#:]", tok)[0].lstrip("*.").strip(".")
        try:
            tok = tok.encode("idna").decode("ascii")  # домены на кириллице: как их видит сеть
        except UnicodeError:
            continue
        if tok and re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", tok) and tok not in out:
            out.append(tok)
    return out


def build_home_config(nic=None):
    """A core with one local port and a direct exit pinned to the physical adapter: whatever answers through it is this
    computer's own connection, VPN or not."""
    cfg = {"log": {"level": "warn", "output": HOMELOG},
           "dns": {"servers": [local_dns_server(LOCAL_DNS)], "strategy": "ipv4_only"},
           "inbounds": [{"type": "mixed", "tag": "home-in", "listen": "127.0.0.1", "listen_port": HOME_PORT}],
           "outbounds": [{"type": "direct", "tag": "direct"}],
           "route": {"final": "direct", "default_domain_resolver": "local"}}
    if nic:
        cfg["route"]["default_interface"] = nic
    return cfg


HOME_PROC = None  # the home probe's core while it runs, so quitting the app can stop it


def detect_home(nic=None):
    """Two-letter country this computer really connects from (around any VPN that is running), or None."""
    global HOME_PROC
    p = None
    try:
        write_json(HOMECFG, build_home_config(nic))
        p = subprocess.Popen([CORE, "run", "-c", HOMECFG], cwd=DATA, creationflags=NOWIN,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        own(p)
        HOME_PROC = p
        deadline = time.time() + 8
        while True:
            if p.poll() is not None:
                return None
            try:
                socket.create_connection(("127.0.0.1", HOME_PORT), 0.3).close()
                break
            except OSError:
                if time.time() > deadline:
                    return None
                time.sleep(0.2)
        return probe_exit(HOME_PORT, urls=tuple(reversed(EXIT_URLS)))  # from Russia the bare IP answers, the domain does not
    except Exception:  # noqa: BLE001
        return None
    finally:
        HOME_PROC = None
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except Exception:  # noqa: BLE001
                p.kill()


TUNLIKE = re.compile(r"^(tun|utun|wg|tailscale|ppp|ipsec|zt|sing|" + re.escape(TUN_NAME) + ")", re.I)


def posix_nic():
    """Real adapter behind the IPv4 default route on Linux/macOS, skipping tunnel-like devices (ours or another VPN)."""
    try:
        if IS_MAC:
            out = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "default" and not TUNLIKE.match(parts[3]):
                    return parts[3]
            return None
        out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            m = re.search(r"\bdev (\S+)", line)
            if m and not TUNLIKE.match(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return None


def physical_nic():
    """Name of the real network adapter (lowest-metric IPv4 default route that is not our TUN), or None."""
    if not IS_WIN:
        return posix_nic()
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
          f"$r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -ne '{TUN_NAME}' }});"
          "$p = @((Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }).InterfaceIndex);"
          "$c = @($r | Where-Object { $p -contains $_.InterfaceIndex }); if (-not $c) { $c = $r };"
          "$c | Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex "
          "-AddressFamily IPv4).InterfaceMetric } | Select-Object -First 1 -ExpandProperty InterfaceAlias")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=20,
                             creationflags=NOWIN).stdout.decode("utf-8", "replace").strip()
        return out.splitlines()[0].strip() if out else None
    except Exception:
        return None


def parse_stale(output, data_dir, own_pids):
    """PIDs from 'pid|commandline' lines whose command line points into our data folder."""
    pids = []
    for line in output.splitlines():
        pid, _, cmd = line.partition("|")
        pid = pid.strip()
        if pid.isdigit() and int(pid) not in own_pids and data_dir.lower() in cmd.lower():
            pids.append(int(pid))
    return pids


def kill_stale_cores(own_pids=()):
    """Stop sing-box processes started from our config folder by an earlier run of this app (the window was killed
    or crashed). A leftover core keeps the TUN adapter and DNS capture alive while the window says 'off', so every
    other program, including our own speed test, silently goes through it."""
    if not IS_WIN:
        # Linux/macOS: the root supervisor script stops the core when the window dies; a companion Xray (ours, user-level) is
        # left behind and is stopped here
        try:
            out = subprocess.run(["ps", "-A", "-o", "pid=,command="], capture_output=True, text=True, timeout=10).stdout
        except Exception:  # noqa: BLE001
            return 0
        lines = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if "xray" in cmd and "run" in cmd:
                lines.append(f"{pid}|{cmd.strip()}")
        pids = parse_stale(chr(10).join(lines), DATA, set(own_pids))
        for pid in pids:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        return len(pids)
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe' OR Name='xray.exe'\" | "
          "ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.CommandLine }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=20,
                             creationflags=NOWIN).stdout.decode("utf-8", "replace")
    except Exception:
        return 0
    pids = parse_stale(out, DATA, set(own_pids))
    for pid in pids:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, creationflags=NOWIN)
    return len(pids)


def supervisor_script(core, cfg_path, stopfile, gui_pid):
    """Shell script that runs the core and stops it when the window process is gone, the core exits on its own,
    or `stopfile` appears. Its exit status is the core's, so a crash is visible to the window."""
    q = shlex.quote
    return (f"{q(core)} run -c {q(cfg_path)} & C=$!; "
            f"while kill -0 {gui_pid} 2>/dev/null && kill -0 $C 2>/dev/null && [ ! -e {q(stopfile)} ]; "
            f"do sleep 1; done; kill $C 2>/dev/null; wait $C; exit $?")


def xray_check(cfg_path):
    """(ok, message) of `xray run -test` for a config file."""
    try:
        r = subprocess.run([XRAY, "run", "-test", "-format", "json", "-c", cfg_path], capture_output=True, text=True, creationflags=NOWIN, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return False, T("Xray не запускается: {0}").format(e)
    return r.returncode == 0, strip_ansi(r.stdout + r.stderr).strip()


def launch_xray(outs, base_port, cfg_path, log_path, nic=None):
    """Start the companion Xray for the "xray" servers among `outs`. Returns (process or None, {tag: local port},
    what the user should be told, '' if nothing). A server Xray refuses costs only itself; without a working Xray
    those servers are simply not offered."""
    xs = [o for o in outs if engines.is_xray(o)]
    if not xs:
        return None, {}, ""
    if not os.path.isfile(XRAY):
        return None, {}, T("Серверы XHTTP и похожие пропущены: рядом с программой нет файла Xray (скорее всего, его удалил антивирус).")
    try:
        open(log_path, "w").close()
    except OSError:
        pass
    note = ""
    ok, _ = (False, "")
    ports = {}
    good = xs
    for attempt in range(2):
        nxt, ports = base_port, {}
        for o in good:
            nxt = pick_port(nxt)
            ports[o["tag"]] = nxt
            nxt += 1
        write_json(cfg_path, engines.xray_config(good, ports, log_path, nic))
        ok, msg = xray_check(cfg_path)
        if ok or attempt == 1:
            break
        keep = []  # the whole config was refused: ask about each server on its own
        for o in good:
            write_json(cfg_path, engines.xray_config([o], {o["tag"]: base_port}, None, nic))
            if xray_check(cfg_path)[0]:
                keep.append(o)
        if len(keep) < len(good):
            note = T("Пропущено серверов, которые Xray не принял: {0}.").format(len(good) - len(keep))
        good = keep
        if not good:
            return None, {}, note or T("Серверы XHTTP и похожие пропущены: Xray их не принял.")
    if not ok:
        return None, {}, T("Серверы XHTTP и похожие пропущены: Xray не принял настройки.")
    try:
        proc = subprocess.Popen([XRAY, "run", "-format", "json", "-c", cfg_path], cwd=DATA, creationflags=NOWIN,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        return None, {}, T("Серверы XHTTP и похожие пропущены: Xray не запустился ({0}).").format(e)
    own(proc)
    end = time.time() + 8
    pending = set(ports.values())
    while pending and time.time() < end:
        if proc.poll() is not None:
            return None, {}, T("Серверы XHTTP и похожие пропущены: Xray сразу закрылся (его мог остановить антивирус).")
        for pt in list(pending):
            try:
                socket.create_connection(("127.0.0.1", pt), 0.3).close()
                pending.discard(pt)
            except OSError:
                pass
        if pending:
            time.sleep(0.2)
    if pending:
        stop_proc(proc)
        return None, {}, T("Серверы XHTTP и похожие пропущены: Xray не ответил.")
    return proc, ports, note


def stop_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:  # noqa: BLE001
            proc.kill()


def start_core(cfg_path):
    """Start the VPN core with TUN rights. Windows: this process is already elevated. Linux/macOS: only the core
    runs as root (pkexec / the macOS admin prompt), inside a small supervisor that stops it as soon as this window
    dies, the core crashes, or STOPFILE appears - so disconnecting never needs a second password."""
    if IS_WIN:
        p = subprocess.Popen([CORE, "run", "-c", cfg_path], cwd=DATA, creationflags=NOWIN,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        own(p)
        return p
    try:
        os.remove(STOPFILE)
    except OSError:
        pass
    q = shlex.quote
    inner = supervisor_script(CORE, cfg_path, STOPFILE, os.getpid())
    if IS_MAC:
        shell = "/bin/sh -c " + q(inner)
        script = 'do shell script "' + shell.replace("\\", "\\\\").replace('"', '\\"') + '" with administrator privileges'
        cmd = ["osascript", "-e", script]
    else:
        cmd = ["pkexec", "/bin/sh", "-c", inner]
    return subprocess.Popen(cmd, cwd=DATA, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def stop_core(proc):
    """Stop what start_core started and wait for it."""
    if not proc or proc.poll() is not None:
        return
    if not IS_WIN:
        try:
            open(STOPFILE, "w").close()  # the root supervisor notices within a second and stops the core
        except OSError:
            pass
        try:
            proc.wait(8)
            return
        except Exception:
            pass
    proc.terminate()
    try:
        proc.wait(5)
    except Exception:
        proc.kill()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def core_api(api, method, path, body=None, timeout=3):
    """One call to the core's local API (`api` = (port, secret), loopback only): (HTTP status, answer as a dict).
    Status 0 when the core does not answer at all."""
    port, secret = api
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except Exception:  # noqa: BLE001
        return 0, {}
    try:
        got = json.loads(raw) if raw else {}
    except ValueError:
        got = {}
    return status, got if isinstance(got, dict) else {}


def current_server(api, raw=False):
    """Tag of the server the 'proxy' selector is on right now, asked from the core's local API. When it is on the "pick the
    best" group, the server that group picked (`raw=True`: the group's own tag). None when the core does not answer."""
    status, got = core_api(api, "GET", "/proxies/proxy")
    now = got.get("now") or None if status == 200 else None
    if now == AUTO_TAG and not raw:
        status, got = core_api(api, "GET", "/proxies/" + urllib.parse.quote(AUTO_TAG, safe=""))
        now = got.get("now") or None if status == 200 else None
    return now


def close_via(api, tag):
    """Close the connections that go through server `tag` (the applications open new ones, which take the new server).
    How many were closed. The selector's own option does not reach the connections of a proxy request, so this does."""
    status, got = core_api(api, "GET", "/connections", timeout=4)
    if status != 200:
        return 0
    n = 0
    for c in got.get("connections") or []:
        if isinstance(c, dict) and tag in (c.get("chains") or []) and c.get("id"):
            if core_api(api, "DELETE", "/connections/" + urllib.parse.quote(str(c["id"]), safe=""), timeout=3)[0] in (200, 204):
                n += 1
    return n


def switch_server(api, tag, interrupt=True):
    """Move the running core to another server (or to AUTO_TAG) without restarting it: the tunnel stays up, so nothing
    leaves around it. With `interrupt`, connections open on the server being left are closed, so the whole connection
    is on the new server at once. (True, "") or (False, why)."""
    old = current_server(api) if interrupt else None
    status, got = core_api(api, "PUT", "/proxies/proxy", {"name": tag}, timeout=5)
    if status not in (200, 204):
        return False, T("ядро не отвечает") if status == 0 else str(got.get("message") or status)
    if old and current_server(api) != old:
        close_via(api, old)
    return True, ""


def server_delay(api, tag, url, timeout_ms=4000):
    """The core's own check of a server: how long it takes to reach `url` through it, in ms, None if it does not answer.
    Done by the running core, with its own sockets, so the tunnel is not involved and nothing is switched."""
    path = f"/proxies/{urllib.parse.quote(tag, safe='')}/delay?url={urllib.parse.quote(url, safe='')}&timeout={int(timeout_ms)}"
    status, got = core_api(api, "GET", path, timeout=timeout_ms / 1000 + 3)
    d = got.get("delay")
    return d if status == 200 and isinstance(d, (int, float)) and not isinstance(d, bool) and d >= 0 else None  # 0 ms is a real answer (loopback)


def resolve_servers(outs):
    """Replace server hostnames by IPs (keeping SNI), so the test needs no DNS at all: with a VPN up,
    DNS from another interface can be blocked by its strict_route."""
    res = []
    for o in outs:
        o = dict(o)
        host = o.get("server", "")
        if host and not re.match(r"^[\d.:]+$", host):
            try:
                ip = socket.getaddrinfo(host, o.get("server_port"), socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            except OSError:
                res.append(o)
                continue
            if isinstance(o.get("tls"), dict) and not o["tls"].get("server_name"):
                o["tls"] = dict(o["tls"], server_name=host)
            if engines.is_xray(o):
                o["xray"] = engines.xray_with_address(o, ip)
            o["server"] = ip
        res.append(o)
    return res


def _opener(port):
    px = f"http://127.0.0.1:{port}"
    op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": px, "https": px}))
    op.addheaders = [("User-Agent", UA_BROWSER), ("Accept", "*/*")]  # the default Python UA gets 403 from Cloudflare
    return op


def probe_ping(port):
    """Response time through the server in ms, None if unreachable.

    The first request opens the tunnel (TCP + TLS/REALITY/WebSocket + TLS to the site = several round trips)
    and is only a warm-up. The number shown is the best of the next two requests on the SAME connection,
    i.e. about one round trip to the server plus its hop to the site. Timing a cold connection instead made
    every server look 3-6 times slower than it is."""
    u = urlsplit(PING_URL)
    try:
        if u.scheme == "https":
            c = http.client.HTTPSConnection("127.0.0.1", port, timeout=6)
            c.set_tunnel(u.hostname, u.port or 443)
            target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        else:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
            target = PING_URL  # absolute URI: plain HTTP through a proxy
    except Exception:
        return None
    best = None
    try:
        for i in range(3):
            t = time.perf_counter()
            try:
                c.request("GET", target, headers={"Host": u.netloc, "Connection": "keep-alive",
                                                  "User-Agent": UA_BROWSER})
                c.getresponse().read()
            except Exception:
                if i == 0:
                    return None  # the tunnel never came up
                c.close()  # connection dropped: try once more from scratch, but do not count the rebuild
                continue
            ms = (time.perf_counter() - t) * 1000
            if i > 0:
                best = ms if best is None else min(best, ms)
    finally:
        c.close()
    return best


def probe_exit(port, urls=None):
    """Two-letter country code where the server really exits to the internet, as Cloudflare sees it, else None.
    A server's name says where the provider claims it is; behind a CDN it can be anywhere."""
    for url in (urls or EXIT_URLS):
        try:
            with _opener(port).open(url, timeout=6) as r:
                m = re.search(r"^loc=([A-Za-z]{2})\s*$", r.read(4096).decode("utf-8", "replace"), re.M)
        except Exception:
            continue
        if m and m.group(1).upper() != "XX":  # XX = unknown
            return m.group(1).upper()
    return None


def okey(o):
    """Stable identity of a server across subscription updates (names change, the address does not)."""
    return f"{o.get('server')}:{o.get('server_port')}"


def probe_speed(port, secs=4.0, urls=None):
    """Download throughput through the server: (Mbit/s, url that answered), or (None, None).
    Measured from the first bytes for up to `secs` seconds; `urls` is tried in order."""
    for url in (urls or SPEED_URLS):
        try:
            r = _opener(port).open(url, timeout=5)
            try:
                r.read(1024)  # first bytes: skip connection setup in the measurement
                t0 = time.perf_counter()
                total = 0
                while time.perf_counter() - t0 < secs:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                dt = time.perf_counter() - t0
            finally:
                r.close()
            if total >= 100_000:
                return total * 8 / max(dt, 0.01) / 1e6, url
        except Exception:
            continue
    return None, None


def fmt_ping(ms):
    """None = not tested yet, negative = tested and unreachable."""
    return "" if ms is None else (T("нет") if ms < 0 else T("{0:.0f} мс").format(ms))


def fmt_speed(v):
    """None = not tested yet, negative = tested but no download source answered."""
    return "" if v is None else ("—" if v < 0 else (T("{0:.0f} Мбит/с").format(v) if v >= 10 else T("{0:.1f} Мбит/с").format(v)))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        global S
        self.design = load_design()  # the look is fixed before the first widget is made
        base = float(self.tk.call("tk", "scaling"))
        factor = self.design["ui_scale"] / 100
        S = max(1.0, base / 1.3333) * factor
        if factor != 1.0:
            self.tk.call("tk", "scaling", base * factor)  # fonts are in points: they follow
        apply_design(self.design)
        def on_error(*a):
            log_crash(*a)
            if time.time() - getattr(self, "_last_err", 0.0) < 30:  # an error repeating every half second must not pile up dialogs
                return
            self._last_err = time.time()
            try:
                show_error(self, T("Что-то пошло не так, но программа продолжает работать.\n\nЕсли это повторяется, пришли "
                                 "файл crash.log из папки:\n") + DATA + T("\n\nТехническая причина: ") + str(a[1])[:200])
            except Exception:  # noqa: BLE001
                pass
        self.report_callback_exception = on_error
        self.title(TITLE)
        try:
            if IS_WIN:
                self.iconbitmap(os.path.join(BASE, "icon.ico"))
            else:
                self._icon = tk.PhotoImage(file=os.path.join(BASE, "icon.png"))  # keep a reference
                self.iconphoto(True, self._icon)
        except Exception:
            pass
        set_window_icon(self)
        self.configure(bg=BG)
        avail = self.avail_height()
        width = P(self.design["win_width"])
        self.geometry(f"{width}x{min(P(840), avail)}")
        self.minsize(min(P(440), width), min(P(560), avail))  # never taller than the screen can show, whatever its size and scaling
        fam = ui_family(self)
        self.fam = fam
        self.f_h, self.f_b, self.f_s = (fam, FZ(12), "bold"), (fam, FZ(11)), (fam, FZ(10))
        self.proc = None
        self.pro_win = None  # the advanced settings window, while it is open
        self.lang_at_start = i18n.LANG
        self.mixed_active = None  # port of the local proxy of the running connection
        self._login_busy = False
        self.xray_proc = None  # the companion Xray of the running connection, if any servers need it
        self.test_xray = None  # ... and the one of a running test
        self.test_proc = None
        self.test_skip = set()  # rows of the server list the core refused in the last test
        self.restarts = []  # when the connection was brought back after the core stopped on its own
        self._last_err = 0.0
        self.testing = False
        self.test_stop = threading.Event()
        self.results = {}
        self.alive = {}  # tag -> True/False: did the server answer in the last test (kept even if ping is hidden)
        self.outs = []
        self.subs = {}  # url -> last good fetch {"outs", "info", "time", "ua"}; cached on disk
        self.sub_fail = {}  # url -> time of the last failed fetch
        self.inline = []  # outbounds from share links pasted directly
        self.loading = False
        self.reload_pending = False
        self.rules_busy = False
        self.api = None  # (port, secret) of the running core's local API
        self.current = ""  # server the core is using right now
        self.polling = False
        self.core_tags = set()  # the servers the running core was started with: only these can be switched to without a reconnect
        self.core_sel = ""  # what the core's selector was last told: a server, or AUTO_TAG
        self.smart_tag = None  # in «Быстрейший из списка»: the server the app itself picked by ping and speed (None: the core's group decides)
        self.switching = False  # a change of server is under way (off the UI thread)
        self.switch_again = False  # ... and the user chose again meanwhile
        self.switch_timer = None  # waits for the user to stop moving through the list before switching
        self.test_quick = False  # the running test is the background one of the auto mode, not the user's
        self.test_thread = None
        self.speed_time = {}  # tag -> when its speed was last measured
        self.skip_auto = {}  # tag -> until when the auto mode keeps away from it (it stopped answering)
        self.bad_checks = 0  # answers in a row that the server of the smart pick did not give
        self.t_t = 0.0  # when the connection last became ready
        self.t_conn = 0.0  # when the last connect started
        self.uiq = queue.Queue()  # callables from worker threads, run by pump() on the Tk thread
        self.flagimgs = FlagImages(self)
        self.quitting = False
        self.installing = False  # an update install has been handed to the helper
        self.tray, self.tray_ok = None, False
        if not os.environ.get("FIMA_NO_TRAY"):  # tests and screenshots must not put icons on the real desktop
            self.tray = tray.Tray(os.path.join(BASE, "icon.png"), self._ui, self.show_window, self.toggle_from_tray,
                                  self.quit_app)
            self.tray_ok = self.tray.start()
        self._pick = None  # row the app selected itself (see on_select)
        self._pump_id = self._tick_id = None
        self.state = "off"
        self.active = ""
        self.t0 = 0.0
        self.blink = True
        self.n = 0
        self._pos = 0
        self.pending = None  # a verified update that is downloaded and waiting to be installed
        self.upd_busy = False
        self.cfg = {"sources": "", "chosen": "AUTO", "ru_direct": True, "extra": "", "rules_ok": 0, "rules_try": 0,
                    "auto_update": None,  # None = not asked yet
                    "show_flags": True, "show_ping": True, "show_speed": True,
                    "skip_home": True,  # auto mode passes over servers that exit in the user's own blocking country
                    "pro": {},  # advanced settings the user changed (window opens with a double click on «Настройки»)
                    "autostart": False,  # started at login by the system (see autostart_set)
                    "pins": [],  # servers pinned to the top of the list (their address:port)
                    "region": "",  # the country whose sites go without the VPN ("NONE" = none do); '' = not chosen yet
                    "lang": i18n.LANG, "setup_done": False,
                    "tray_on_close": True, "tray_hint_shown": False}
        raw_cfg = None
        try:
            raw_cfg = json.load(open(SETTINGS, encoding="utf-8-sig"))
            self.cfg = merge_cfg(self.cfg, raw_cfg)
        except Exception:
            pass
        if isinstance(raw_cfg, dict) and raw_cfg and "setup_done" not in raw_cfg:
            # an installation from before there was a choice of language and country: Russian, Russia, nothing to ask
            self.cfg.update(region="RU", lang="ru", setup_done=True)
        if not regions.valid(self.cfg.get("region")):
            self.cfg["region"] = ""
        global LOCAL_DNS
        LOCAL_DNS = self.pro()["dns_local"] or regions.local_dns(self.region())
        try:
            self.subs = clean_subs(json.load(open(SUBCACHE, encoding="utf-8")))
        except Exception:
            pass
        self.home_cc = self.cfg.get("home_cc") if isinstance(self.cfg.get("home_cc"), str) else None  # where this computer is
        self.live_tag = ""  # the server the connection is on right now (its row is blue)
        self.exit_cc = {}  # server -> real exit country, learned by the speed test and kept between runs
        try:
            self.exit_cc = {k: v for k, v in json.load(open(EXITFILE, encoding="utf-8")).items() if isinstance(v, str)}
        except Exception:
            pass

        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("T.Treeview", background=PAPER, fieldbackground=PAPER, foreground=INK, borderwidth=0,
                     rowheight=P(ROW_H), font=self.f_b)
        st.map("T.Treeview", background=[("selected", INK)], foreground=[("selected", PAPER)])
        st.layout("T.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        # rows are flag + name: drop the expander arrow's empty space on the left
        st.layout("T.Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""}), ("Treeitem.text", {"side": "left", "sticky": ""})]})])
        st.configure("T.Treeview.Item", padding=(P(8), 0, P(8), 0))  # breathing room: with no flags the name touched the edge
        st.layout("Flat.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "ns"})])
        st.configure("Flat.Vertical.TScrollbar", background=INK, troughcolor=PAPER, borderwidth=0, width=P(10))

        side = P(22)
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True, padx=side, pady=(P(18), P(16)))
        # The footer is first in the packing order: when the window is too short something else is cut, never this row.
        # Everything above it lives on a canvas that scrolls when the screen is too small to show it whole.
        self.foot = tk.Frame(shell, bg=BG)
        self.foot.pack(side="bottom", fill="x", pady=(P(14), 0))
        self.canvas = tk.Canvas(shell, bg=BG, highlightthickness=0, bd=0, yscrollincrement=P(24))
        self.vbar = ttk.Scrollbar(shell, orient="vertical", style="Flat.Vertical.TScrollbar", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        root = self.body = tk.Frame(self.canvas, bg=BG)
        self.body_id = self.canvas.create_window(0, 0, window=root, anchor="nw")
        self._syncing = self._sync_again = self._bar_on = False
        root.bind("<Configure>", lambda e: self.sync_scroll())
        self.canvas.bind("<Configure>", lambda e: self.sync_scroll())
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(ev, self.on_body_wheel, add="+")

        if IS_WIN and not is_admin():
            tk.Label(root, text=T("Нужны права администратора"), font=self.f_s, bg=RED, fg=ONACCENT,
                     padx=P(8), pady=P(4)).pack(fill="x", pady=(0, P(12)))

        self.power = Power(root, self.toggle, fam)
        self.power.pack(fill="x")
        self.status = tk.Label(root, text="", font=self.f_s, bg=BG, fg=MUTE, anchor="w", justify="left",
                               wraplength=P(430))
        self.status.pack(fill="x", pady=(P(6), 0))

        # servers
        row = self.section(root, T("Серверы"))
        self.count = tk.Label(row, text="", font=self.f_s, bg=BG, fg=MUTE)
        self.count.pack(side="right", padx=(P(10), 0))
        self.test_btn = Flat(row, T("Тест скорости"), self.run_test, self.f_s)
        self.test_btn.pack(side="right")
        frame = tk.Frame(root, bg=INK, padx=BW(), pady=BW())
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, style="T.Treeview", columns=("ping", "speed", "proto"), show="tree",
                                 selectmode="browse", height=6)
        self.tree.column("#0", anchor="w", stretch=True, width=P(170))  # flag + server name
        meter = tkfont.Font(self, font=self.f_b)
        self.col_w = {"ping": meter.measure(T("0000 мс")) + P(20), "speed": meter.measure(T("000 Мбит/с")) + P(20),
                      "proto": max(meter.measure(n) for n in list(PROTO.values()) + ["XHTTP", "MKCP", "TROJAN+"]) + P(20)}
        self.tree.column("ping", anchor="e", width=self.col_w["ping"], stretch=False)
        self.tree.column("speed", anchor="e", width=self.col_w["speed"], stretch=False)
        self.tree.column("proto", anchor="e", width=self.col_w["proto"], stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", style="Flat.Vertical.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.tag_configure("live", foreground=BLUE, font=(fam, FZ(11), "bold"))
        self.tree.tag_configure("home", foreground=MUTE)  # servers «Быстрейший из списка» passes over
        self.tree.bind("<Configure>", self.fit_tree_columns, add="+")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Button-2>" if IS_MAC else "<Button-3>", self.row_menu)
        if IS_MAC:
            self.tree.bind("<Control-Button-1>", self.row_menu)
        self.empty = tk.Label(frame, text=T("Серверов пока нет.\n\nВставь ссылку подписки или ключ в поле «Подписки» ниже "
                                          "и нажми «Обновить»."), font=self.f_s, bg=PAPER, fg=MUTE, justify="center", wraplength=P(300))
        self.tree.bind("<Double-1>", lambda e: self.toggle() if self.state == "off" else None)

        # routing
        route_row = self.section(root, T("Маршрут"))
        self.region_btn = Flat(route_row, self.region_button_text(), self.open_setup, self.f_s)
        self.region_btn.pack(side="right")
        self.ru = tk.BooleanVar(value=self.cfg["ru_direct"])
        self.ru_check = Check(root, self.direct_label(), self.ru, self.f_b)
        self.ru_check.pack(anchor="w")
        tk.Label(root, text=T("Свои домены напрямую, через пробел"), font=self.f_s, bg=BG, fg=MUTE,
                 anchor="w").pack(fill="x", pady=(P(10), P(4)))
        eb = tk.Frame(root, bg=INK, padx=BW(), pady=BW())
        eb.pack(fill="x")
        inner = tk.Frame(eb, bg=PAPER)
        inner.pack(fill="x")
        self.extra = tk.Entry(inner, font=self.f_b, bg=PAPER, fg=INK, relief="flat", bd=0, highlightthickness=0,
                              insertbackground=INK, selectbackground=BLUE, selectforeground=ONACCENT)
        self.extra.pack(fill="x", ipady=P(5), padx=P(6))
        self.extra.insert(0, self.cfg["extra"])

        # subscriptions
        row = self.section(root, T("Подписки"))
        Flat(row, T("Обновить"), self.load, self.f_s).pack(side="right")
        Flat(row, T("Вставить"), self.paste_clip, self.f_s).pack(side="right", padx=(0, P(8)))
        self.sub_note = tk.Label(row, text="", font=self.f_s, bg=BG, fg=MUTE)
        self.sub_note.pack(side="left", padx=(P(10), 0))
        sbx = self.sbx = tk.Frame(root, bg=INK, padx=BW(), pady=BW())  # last block of the content; the panels open right below it
        sbx.pack(fill="x")
        self.src = tk.Text(sbx, height=3, wrap="char", font=(MONO, FZ(9)), bg=PAPER, fg=INK, relief="flat", bd=0,
                           highlightthickness=0, insertbackground=INK, selectbackground=BLUE,
                           selectforeground=ONACCENT, padx=P(6), pady=P(5))
        self.src.pack(fill="x")
        self.src.insert("1.0", self.cfg["sources"])
        self.usage = tk.Label(root, text="", font=self.f_s, bg=BG, fg=MUTE, anchor="w", justify="left", wraplength=P(430))  # shown above the box when a provider reports traffic or an expiry date
        self.src_hint = tk.Label(self.src, text=T("Ссылка подписки (https://…) или ключ (vless://, vmess://, trojan://, ss://, hysteria2://…). "
                                                "Можно вставить несколько, по одной в строке."), font=(self.fam, FZ(9)), bg=PAPER, fg=MUTE,
                                 justify="left", anchor="w", wraplength=P(380), cursor="xterm")
        self.src_hint.bind("<Button-1>", lambda e: self.src.focus_set())
        for ev in ("<KeyRelease>", "<FocusIn>", "<FocusOut>", "<ButtonRelease-1>"):
            self.src.bind(ev, lambda e: self.sync_hints(), add="+")

        # log (folded)
        self.log_open = False
        self.log_box = tk.Frame(root, bg=INK, padx=BW(), pady=BW())
        self.log = tk.Text(self.log_box, height=8, state="disabled", bg=LOGBG, fg=LOGFG, font=(MONO, FZ(9)),
                           relief="flat", bd=0, highlightthickness=0, selectbackground=BLUE, padx=P(6), pady=P(5))
        self.log.pack(fill="both", expand=True)

        # settings (folded): what the list shows and the test measures, program updates
        self.set_open = False
        self.set_box = tk.Frame(root, bg=BG)
        self.v_flags = tk.BooleanVar(value=bool(self.cfg.get("show_flags", True)))
        self.v_ping = tk.BooleanVar(value=bool(self.cfg.get("show_ping", True)))
        self.v_speed = tk.BooleanVar(value=bool(self.cfg.get("show_speed", True)))
        for text, var in ((T("Флаги стран"), self.v_flags), (T("Пинг: показывать и измерять"), self.v_ping),
                          (T("Скорость: показывать и измерять"), self.v_speed)):
            Check(self.set_box, text, var, self.f_b).pack(anchor="w", pady=(0, P(2)))
            var.trace_add("write", self.on_view_toggle)
        self.v_skip = tk.BooleanVar(value=bool(self.cfg.get("skip_home", True)))
        Check(self.set_box, T("Автовыбор: не брать серверы своей страны, если там блокируют"), self.v_skip,
              self.f_b).pack(anchor="w", pady=(0, P(2)))
        self.v_skip.trace_add("write", self.on_skip_toggle)
        self.v_tray =tk.BooleanVar(value=bool(self.cfg.get("tray_on_close", True)))
        if self.tray_ok:
            Check(self.set_box, T("Закрытие окна сворачивает в трей"), self.v_tray, self.f_b).pack(anchor="w", pady=(0, P(2)))
            self.v_tray.trace_add("write", lambda *a: (self.cfg.update(tray_on_close=self.v_tray.get()),
                                                       self.save(sources=False)))
        self.v_login = tk.BooleanVar(value=bool(self.cfg.get("autostart", False)))
        if autostart_command() is not None:  # only the packaged program has something to start
            Check(self.set_box, T("Запускать при входе в систему"), self.v_login, self.f_b).pack(anchor="w", pady=(0, P(2)))
            self.v_login.trace_add("write", self.on_login_toggle)
        urow = tk.Frame(self.set_box, bg=BG)
        urow.pack(fill="x", pady=(P(8), 0))
        self.upd_var = tk.BooleanVar(value=bool(self.cfg.get("auto_update")))
        Check(urow, T("Обновлять программу автоматически"), self.upd_var, self.f_s).pack(side="left")
        self.upd_btn = Flat(urow, T("Проверить"), self.on_upd_click, self.f_s)
        self.upd_btn.pack(side="right")
        self.upd_var.trace_add("write", self.on_upd_toggle)
        tk.Label(self.set_box, text=T("Для опытных: двойной щелчок по «Настройки» открывает расширенные настройки."),
                 font=self.f_s, bg=BG, fg=MUTE, anchor="w", justify="left", wraplength=P(430)).pack(fill="x", pady=(P(8), 0))

        # footer: deliberately quiet. Small grey links; the version on the right.
        self.log_head = self.quiet_link(self.foot, T("Лог"), self.toggle_log)
        self.log_head.pack(side="left")
        self.set_head = self.quiet_link(self.foot, T("Настройки"), self.toggle_settings, double=self.open_pro)
        self.set_head.pack(side="left", padx=(P(16), 0))
        tk.Label(self.foot, text=f"v{updater.VERSION}", font=self.f_s, bg=BG, fg=MUTE).pack(side="right")

        for w in (self.src, self.extra, self.log):
            enable_clipboard(w)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.apply_view()
        self.show_cached()
        self.clean_done = threading.Event()

        def clean():
            try:
                n = kill_stale_cores({p.pid for p in (self.proc, self.test_proc) if p})
                if n:
                    self._ui(lambda: self.say(T("Закрыл остатки прошлого запуска VPN.")))
            finally:
                self.clean_done.set()
        threading.Thread(target=clean, daemon=True).start()
        if self.cfg.get("autostart") and autostart_command() is not None:  # keep the login entry pointing at this very file
            threading.Thread(target=autostart_set, args=(True,), daemon=True).start()
        threading.Thread(target=self.home_worker, daemon=True).start()
        self._pump_id = self.after(50, self.pump)
        self.start_instance_server()
        self.after(300, self.refresh_due)
        self.after(900, self.first_run)
        self.sync_hints()
        self.restore_window()
        self.apply_live()
        self.after(120, lambda: self.fit_height(P(840)))
        self._tick_id = self.after(500, self.tick)
        self.after(1500, self.update_startup)

    # ----- program updates -----
    def frozen(self):
        return bool(getattr(sys, "frozen", False))

    def update_startup(self):
        """First start: ask whether to update automatically. Then check, if the answer is yes."""
        if not self.frozen():
            return  # running from source: there is no program file to replace
        if self.cfg.get("auto_update") is None:
            yes = ask_yes_no(self, T("Обновлять программу автоматически?\n\n"
                       "Когда на GitHub выйдет новая версия, программа скачает её, проверит контрольную сумму и "
                       "установит при следующем запуске. Ничего о тебе не отправляется.\n\n"
                       "Это можно включить и выключить внизу окна."))
            self.upd_var.set(bool(yes))  # the trace saves the choice
            self.cfg["auto_update"] = bool(yes)
            self.save(sources=False)
        if self.cfg.get("auto_update"):
            self.update_check()

    def on_upd_toggle(self, *a):
        self.cfg["auto_update"] = bool(self.upd_var.get())
        self.save(sources=False)
        if self.cfg["auto_update"]:
            self.update_check()

    def on_upd_click(self):
        if self.pending:
            return self.install_now()
        self.update_check(manual=True)

    def update_check(self, manual=False):
        """Look for a newer release and download it in the background. Auto mode installs it at the next start."""
        if self.upd_busy:
            return
        if not self.frozen():
            if manual:
                self.say(T("Обновление работает в собранной программе, а не при запуске из исходников."))
            return
        self.upd_busy = True
        if manual:
            self.say(T("Проверяю обновления…"))

        def work():
            upd = got = err = None
            try:
                upd = updater.find_update()
                if upd:
                    got = updater.stage(upd, UPDATE_DIR)
            except Exception as e:  # noqa: BLE001
                err = str(e)
            self._ui(lambda: self.update_done(upd, got, err, manual))
        threading.Thread(target=work, daemon=True).start()

    def update_done(self, upd, got, err, manual):
        self.upd_busy = False
        if err:
            return self.say(T("Не удалось проверить обновления. Проверь интернет и попробуй позже."), err=True) if manual else None
        if not upd:
            return self.say(T("Установлена последняя версия ({0}).").format(updater.VERSION)) if manual else None
        self.pending = got
        self.upd_btn.config(text=T("Установить {0}").format(upd['version']))
        if manual:
            if ask_yes_no(self, T("Версия {0} скачана и проверена.\nУстановить сейчас? Программа перезапустится.").format(upd['version'])):
                return self.install_now()
        self.say(T("Версия {0} скачана. ").format(upd['version']) + (T("Установится при следующем запуске.")
                                                         if self.cfg.get("auto_update") else T("Нажми «Установить».")))

    def install_now(self):
        if self.installing:
            return  # a second click while the first install is on its way
        if self.state != "off" and not ask_yes_no(self, T("VPN отключится на время обновления. Продолжить?")):
            return
        self.installing = True
        self.save()
        self.test_stop.set()
        self.stop()
        if updater.apply_staged(self.pending, relaunch=True):
            self.quitting = True
            self.destroy()  # the loop ends and the process with it; the helper swaps the files and starts the new copy
            return
        self.installing = False
        self.say(T("Не удалось установить обновление. Скачай новую версию с GitHub вручную."), err=True)

    # ----- small helpers -----
    def section(self, parent, title):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(P(18), P(6)))
        tk.Label(row, text=title, font=self.f_h, bg=BG, fg=INK).pack(side="left")
        self._rows = getattr(self, "_rows", []) + [row]
        return row

    def needed_width(self):
        """The narrowest the window may be for its rows (a title, a note and two buttons side by side; the server list with
        all its columns; the footer) not to overlap, whatever font the system or the settings gave it."""
        try:
            self.update_idletasks()
            rows = max([r.winfo_reqwidth() for r in getattr(self, "_rows", [])] + [self.foot.winfo_reqwidth()] + [0]) + P(24)
            tree = sum(self.col_w.values()) + P(190) + P(10) + 4 * BW() + P(8)  # numbers, then room for a server name
            return max(rows, tree) + 2 * P(22) + P(4)
        except (tk.TclError, AttributeError):
            return 0

    def quiet_link(self, parent, text, command, double=None):
        """A small grey text link: dark and underlined only while hovered or while its panel is open.
        With `double`, a double click does that instead; the single click then waits a moment to see whether a second
        one follows, so the panel does not flicker open and shut."""
        base, lit = (self.fam, FZ(10)), (self.fam, FZ(10), "underline")
        lbl = tk.Label(parent, text=text, font=base, bg=BG, fg=MUTE, cursor="hand2")
        lbl.base, lbl.lit, lbl.open = base, lit, False

        def paint(hover):
            on = hover or lbl.open
            lbl.config(fg=INK if on else MUTE, font=lit if on else base)
        lbl.paint = paint
        lbl.bind("<Enter>", lambda e: paint(True))
        lbl.bind("<Leave>", lambda e: paint(False))
        if double is None:
            lbl.bind("<Button-1>", lambda e: command())
            return lbl
        st = {"timer": None, "fired": False}

        def single(e=None):
            st["fired"] = False

            def fire():
                st["timer"], st["fired"] = None, True
                command()
            st["timer"] = lbl.after(DOUBLE_CLICK_MS, fire)

        def twice(e=None):
            if st["timer"] is not None:  # the single click has not acted yet: cancel it
                lbl.after_cancel(st["timer"])
                st["timer"] = None
            elif st["fired"]:  # it already did: take that back
                command()
            st["fired"] = False
            double()
        lbl.bind("<Button-1>", single)
        lbl.bind("<Double-Button-1>", twice)
        lbl.single, lbl.twice = single, twice  # for tests: synthetic events do not make Tk count a double click
        return lbl

    def open_pro(self):
        """The advanced settings window (one at a time)."""
        w = getattr(self, "pro_win", None)
        try:
            if w is not None and w.winfo_exists():
                w.deiconify()
                w.lift()
                w.focus_force()
                return w
        except tk.TclError:
            pass
        self.pro_win = ProWindow(self)
        return self.pro_win

    def toggle_log(self, force=None):
        self.log_open = (not self.log_open) if force is None else force
        self.log_head.open = self.log_open
        self.log_head.paint(False)
        if self.log_open:
            self.log_box.pack(fill="x", pady=(P(12), 0), after=self.set_box if self.set_open else self.sbx)  # panels open above the footer, which never moves
        else:
            self.log_box.pack_forget()
        self.fit_height()

    def work_area(self):
        """(top, bottom) of the usable screen in pixels: without the taskbar, the menu bar or the dock."""
        top, bottom = 0, self.winfo_screenheight()
        if IS_WIN:
            try:
                from ctypes import wintypes
                r = wintypes.RECT()
                if ctypes.windll.user32.SystemParametersInfoW(0x30, 0, ctypes.byref(r), 0):  # SPI_GETWORKAREA
                    top, bottom = max(top, r.top), min(bottom, r.bottom)
            except Exception:  # noqa: BLE001
                pass
        elif IS_MAC:
            top, bottom = P(24), bottom - P(70)
        else:
            bottom -= P(48)
        return top, bottom

    def avail_height(self):
        """The tallest the window may be (its inner height): the usable screen minus the title bar and the frame."""
        top, bottom = self.work_area()
        return max(P(300), bottom - top - P(48 if IS_WIN else 36))

    def keep_on_screen(self):
        """Pull the window back so that all of it, the title bar down to the bottom edge, is on the usable screen: where
        Windows first puts a window and the growth of the panels can both push its lower part off the screen, and
        with it the buttons that minimise it and the footer."""
        try:
            self.update_idletasks()
            top, bottom = self.work_area()
            x, y = self.winfo_x(), self.winfo_y()
            outer = self.winfo_height() + max(0, self.winfo_rooty() - y) + P(8)
            ny = max(top, min(y, bottom - outer))
            if ny != y:
                self.geometry(f"+{x}+{ny}")
        except tk.TclError:
            pass

    def sync_scroll(self):
        """The scrolling body as wide as its canvas (and at least as tall), the scroll bar only while the content does
        not fit."""
        if self._syncing:  # showing or hiding the bar resizes the canvas: look again once that has settled
            self._sync_again = True
            return
        self._syncing = True
        try:
            c = self.canvas
            need = self.body.winfo_reqheight()
            have = c.winfo_height()
            c.itemconfigure(self.body_id, width=max(1, c.winfo_width()), height=max(need, have))
            c.configure(scrollregion=(0, 0, max(1, c.winfo_width()), max(need, have)))
            if need > have + 1 and have > 1:
                if not self._bar_on:  # (own flag: winfo_ismapped() lags behind pack until the event loop runs)
                    self.vbar.pack(side="right", fill="y")
                    self._bar_on = True
            elif self._bar_on:
                self.vbar.pack_forget()
                self._bar_on = False
                c.yview_moveto(0)
        except tk.TclError:
            pass
        finally:
            self._syncing = False
        if self._sync_again:
            self._sync_again = False
            self.after_idle(self.sync_scroll)

    def on_body_wheel(self, e):
        """The mouse wheel scrolls the body, except over the widgets that scroll themselves."""
        try:
            w = e.widget
            if w.winfo_toplevel() is not self or isinstance(w, (tk.Text, ttk.Treeview)) or not self._bar_on:
                return
        except (AttributeError, tk.TclError, KeyError):
            return
        up = getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0
        self.canvas.yview_scroll(-1 if up else 1, "units")

    def fit_height(self, floor=None):
        """Resize to what the content needs, but never taller than the screen shows: first the server list gives way,
        then the body scrolls. Keeps the width (geometry("") would also reset it to the widest child's natural request:
        the 80-character text fields make that wider than the window)."""
        self.update_idletasks()
        avail = self.avail_height()
        self.minsize(P(440), min(P(560), avail))  # the screen may have changed since the start (another monitor, resolution)
        rows = 6
        while True:  # the window asks for the body's height plus the footer; the server list gives way until that fits
            self.tree.configure(height=rows)
            self.update_idletasks()
            self.canvas.configure(height=self.body.winfo_reqheight())
            self.update_idletasks()
            if self.winfo_reqheight() <= avail or rows <= 2:
                break
            rows -= 1
        w = max(self.winfo_width() if self.winfo_width() > 100 else P(self.design["win_width"]), self.needed_width())
        w = min(w, max(P(440), self.winfo_screenwidth() - P(40)))
        h = min(max(self.winfo_reqheight(), min(floor or P(760), avail)), avail)
        self.minsize(min(P(440), w), self.minsize()[1])
        self.geometry(f"{w}x{h}")
        self.update_idletasks()
        self.keep_on_screen()
        self.sync_scroll()

    def toggle_settings(self, force=None):
        self.set_open = (not self.set_open) if force is None else force
        self.set_head.open = self.set_open
        self.set_head.paint(False)
        if self.set_open:
            self.set_box.pack(fill="x", pady=(P(12), 0), after=self.sbx)
        else:
            self.set_box.pack_forget()
        self.fit_height()

    def on_view_toggle(self, *a):
        self.cfg.update(show_flags=self.v_flags.get(), show_ping=self.v_ping.get(), show_speed=self.v_speed.get())
        self.save(sources=False)
        self.apply_view()

    def apply_view(self):
        """Flags, the ping column and the speed column are independent. Hidden = not shown AND not measured."""
        cols = [c for c, on in (("ping", self.v_ping.get()), ("speed", self.v_speed.get()), ("proto", True)) if on]
        self.tree.configure(displaycolumns=cols)
        for iid in self.tree.get_children():
            img = self.flagimgs.get("AUTO") if iid == "auto" else self.flagimgs.get(self.flag_code(self.outs[int(iid)]))
            self.tree.item(iid, image=img if self.v_flags.get() else "")
        if not self.testing:
            self.test_btn.config(text=self.test_label())
        self.after_idle(self.fit_tree_columns)
        self.refresh_power()

    def fit_tree_columns(self, e=None):
        """The name column takes whatever width the visible columns leave. ttk re-stretches only when the widget is
        resized, not when columns are hidden, which left the selection bar ending halfway across the list."""
        total = self.tree.winfo_width()
        if total < 50:
            return
        other = sum(int(self.tree.column(c, "width")) for c in self.tree.cget("displaycolumns")
                    if c in ("ping", "speed", "proto"))
        want = max(P(120), total - other - P(4))
        if abs(int(self.tree.column("#0", "width")) - want) > 2:
            self.tree.column("#0", width=want)

    def test_label(self):
        if self.v_speed.get():
            return T("Тест скорости")
        if self.v_ping.get():
            return T("Тест пинга")
        return T("Определить страны") if self.v_flags.get() else T("Тест")

    def say(self, text, err=False):
        self.status.config(text=text, fg=RED if err else MUTE)

    def chosen(self):
        sel = self.tree.selection()
        if not sel or sel[0] == "auto":
            return "AUTO"
        return self.outs[int(sel[0])]["tag"]

    def sel_name(self):
        sel = self.tree.selection()
        if not sel:
            return ""
        return AUTO_LABEL if sel[0] == "auto" else self.outs[int(sel[0])]["tag"]

    def flag_code(self, o):
        """Flag of a server: the country it really exits to once the test has found it, else what its name says."""
        cc = self.exit_cc.get(okey(o))
        if cc:
            return cc if cc in flags.FLAGS else "??"  # a real country without a drawing: neutral tile, never a wrong flag
        return flags.code_for(o["tag"])

    def skip_cc(self):
        """The country «Быстрейший из списка» keeps away from: the one the user is in, if blocking happens there
        (and the user has not switched this off in the settings)."""
        if not self.cfg.get("skip_home", True):
            return None
        return self.home_cc if regions.blocks(self.home_cc) else None

    def on_skip_toggle(self, *a):
        self.cfg["skip_home"] = self.v_skip.get()
        self.save(sources=False)
        self.paint_rows()
        if self.state != "off" and self.chosen() == "AUTO":
            self.say(T("Автовыбор учтёт это при следующем подключении."))

    def is_home_exit(self, o):
        """Does this server exit in the user's own blocking country? Such a server bypasses nothing."""
        cc = self.skip_cc()
        return bool(cc) and self.flag_code(o) == cc

    def auto_pool(self):
        """Tags «Быстрейший из списка» may use. Never empty: if every server is such a one, all of them stay."""
        keep = [o["tag"] for o in self.outs if not self.is_home_exit(o)]
        return keep or [o["tag"] for o in self.outs]

    def row_tags(self, iid):
        if iid == "auto":
            return ()
        o = self.outs[int(iid)]
        if self.live_tag and o["tag"] == self.live_tag:
            return ("live",)
        return ("home",) if self.is_home_exit(o) else ()

    def paint_rows(self):
        for iid in self.tree.get_children():
            self.tree.item(iid, tags=self.row_tags(iid))

    def home_worker(self):
        """At start: ask where this computer really is (not where a running VPN is), in the background."""
        try:
            self.clean_done.wait(10)  # a leftover core of ours would answer with its own exit
            nic = physical_nic()
            if IS_LINUX and self.state == "off":
                nic = None
            if not nic and self.state != "off":
                return  # a VPN is up and the real adapter is unknown: any answer would be the tunnel's
            cc = detect_home(nic)
            if cc:
                self._ui(lambda: self.set_home(cc))
        except Exception:  # noqa: BLE001
            pass

    def set_home(self, cc):
        changed = cc != self.home_cc
        self.home_cc = cc
        self.cfg["home_cc"] = cc
        self.save(sources=False)
        if changed:
            self.paint_rows()

    def flag_for_tag(self, tag):
        o = next((o for o in self.outs if o["tag"] == tag), None)
        return self.flagimgs.get(self.flag_code(o) if o else flags.code_for(tag))

    def set_exit(self, i, cc):
        """The test learned where server i really exits: redraw its row and, if connected to it, the main button."""
        if not cc or i >= len(self.outs):
            return
        o = self.outs[i]
        self.exit_cc[okey(o)] = cc
        if self.tree.exists(str(i)):
            self.tree.item(str(i), image=self.flagimgs.get(self.flag_code(o)) if self.v_flags.get() else "",
                           tags=self.row_tags(str(i)))
        if self.state != "off":
            self.refresh_power()

    def refresh_power(self):
        clock = ""
        if self.state == "on":
            s = int(time.time() - self.t0)
            clock = f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
        label = self.active if self.state != "off" else self.sel_name()  # what the user picked
        if self.state == "on" and self.current:  # the server the core is really on (auto mode switches by itself)
            shown = flags.strip_flag(self.current)
            name = T("Авто: {0}").format(shown) if self.chosen() == "AUTO" else shown
            flag = self.flag_for_tag(self.current)
        elif label == AUTO_LABEL:
            name, flag = label, self.flagimgs.get("AUTO")
        elif label:
            name, flag = flags.strip_flag(label), self.flag_for_tag(label)
        else:
            name, flag = "", None
        self.power.set(self.state, name, clock, self.blink, flag if self.v_flags.get() else None)

    def save(self, sources=True):
        """Persist settings. Background jobs pass sources=False so a half-edited sources box is not committed."""
        if sources:
            self.cfg["sources"] = self.src.get("1.0", "end").strip()
        self.cfg.update(ru_direct=self.ru.get(), extra=self.extra.get())
        try:
            write_json(SETTINGS, self.cfg)
        except OSError:
            pass

    # ----- subscriptions -----
    def paste_clip(self):
        try:
            txt = self.clipboard_get()
        except tk.TclError:
            return show_info(self, T("Буфер обмена пуст."))
        cur = self.src.get("1.0", "end").strip()
        self.src.delete("1.0", "end")
        self.src.insert("1.0", (cur + "\n" if cur else "") + txt.strip())
        self.sync_hints()
        self.load()

    def show_cached(self):
        """Show the servers saved from the last good fetch right away, before touching the network."""
        urls, inline = split_sources(self.cfg["sources"])
        self.subs = {u: s for u, s in self.subs.items() if u in urls and s.get("outs")}
        self.inline = parse_inline(inline)[0]
        if self.subs or self.inline:
            self.apply_outs()

    def load(self, silent=False, only=None):
        """Fetch subscriptions in the background: all of them (button, paste) or just `only` (timer)."""
        manual = only is None
        if self.testing:
            if manual:
                self.say(T("Идёт тест скорости. Дождись конца или остановь его."), err=True)
            return
        if self.loading:
            self.reload_pending = self.reload_pending or manual
            return
        if manual:
            raw = self.src.get("1.0", "end").strip()
            tidy = "\n".join(source_lines(raw))  # "open in the app" links unwrapped, quotes and stray words gone
            if tidy and tidy != raw:
                self.src.delete("1.0", "end")
                self.src.insert("1.0", tidy)
            self.cfg["sources"] = tidy or raw
            self.count.config(text=T("Загрузка…"))
        urls, inline = split_sources(self.cfg["sources"])
        targets = urls if manual else [u for u in only if u in urls]
        prefer = {u: self.subs.get(u, {}).get("ua") for u in targets}
        # a provider that blocks the direct way is often reachable through the VPN that is already up
        via = f"http://127.0.0.1:{self.mixed_active}" if self.state == "on" and self.mixed_active else None
        merge = bool(self.pro()["merge_subs"])
        self.loading = True
        self.sub_note.config(text=T("обновляю…"))

        def work():
            got = {u: fetch_source(u, prefer[u], via, merge) for u in targets}
            inline_outs, inline_skipped = parse_inline(inline)
            self._ui(lambda: self.loaded(got, inline_outs, urls, manual, silent, inline_skipped))
        threading.Thread(target=work, daemon=True).start()

    def loaded(self, got, inline_outs, urls, manual, silent, inline_skipped=None):
        self.loading = False
        now = time.time()
        errors, changed = [], manual
        left_out = Counter(inline_skipped or {})
        for u, (outs, info, ua, errs) in got.items():
            left_out.update((info or {}).get("skipped") or {})
            if outs:
                changed = changed or self.subs.get(u, {}).get("outs") != outs
                self.subs[u] = {"outs": outs, "info": info, "time": now, "ua": ua}
                self.sub_fail.pop(u, None)
            else:
                self.sub_fail[u] = now
                errors += errs
        if manual:
            self.subs = {u: s for u, s in self.subs.items() if u in urls}
            self.inline = inline_outs
        try:
            write_json(SUBCACHE, self.subs)
        except OSError:
            pass
        if changed:
            self.apply_outs(errors, manual, silent)
        else:
            self.note_subs()
        if manual and left_out and self.outs:  # servers the core cannot run: say which and why, once
            now_text = self.status.cget("text")
            self.say((now_text + " " if now_text else "") + skipped_note(left_out), err=bool(errors))
        if self.reload_pending:
            self.reload_pending = False
            self.load()

    def apply_outs(self, errors=(), manual=False, silent=True):
        """Rebuild the server list from cached subscriptions + inline links, keeping selection and scroll."""
        urls, _ = split_sources(self.cfg["sources"])
        outs = merge_outs([self.subs[u]["outs"] for u in urls if u in self.subs] + [self.inline])
        first = not self.tree.get_children()
        keep = self.cfg["chosen"]
        top = self.tree.yview()[0]
        self.outs = outs
        self.tree.delete(*self.tree.get_children())
        self.note_subs()
        if not outs:
            self.count.config(text=T("Пусто"))
            self.sync_hints()
            self.say(T("Серверов нет. Проверь ссылку или ключ."), err=True)
            if manual and not silent:
                show_error(self, T("Не удалось получить серверы.\n\nЧто сделать: проверь, что ссылка подписки скопирована целиком "
                                     "(она начинается с https://) и что есть интернет, потом нажми «Обновить».\n\n") +
                                     ("\n".join(errors) if errors else T("Серверов в ответе нет.")))
            return
        if manual:
            self.say(T("Не все подписки обновились, показаны сохранённые серверы.") if errors else "", err=bool(errors))
        if len(outs) > 1:
            self.tree.insert("", "end", iid="auto", text=AUTO_LABEL, image=self.flagimgs.get("AUTO") if self.v_flags.get() else "",
                             values=("", "", "AUTO"))
        for i, o in enumerate(outs):
            ping, speed = self.results.get(o["tag"], (None, None))
            self.tree.insert("", "end", iid=str(i), text=self.row_text(o),
                             image=self.flagimgs.get(self.flag_code(o)) if self.v_flags.get() else "",
                             values=(fmt_ping(ping), fmt_speed(speed), engines.proto_label(o) or PROTO.get(o["type"], o["type"].upper())))
        if self.results or self.cfg["pins"]:
            self.sort_rows()
        pick = next((str(i) for i, o in enumerate(outs) if o["tag"] == keep), None)
        pick = pick or ("auto" if len(outs) > 1 else "0")
        self.select(pick)
        if first or manual:
            self.tree.see(pick)
        else:
            self.tree.yview_moveto(top)
        self.count.config(text=str(len(outs)))
        self.paint_rows()  # the list was rebuilt: keep the live row marked, mute the skipped ones
        self.sync_hints()
        self.save(sources=manual)

    def sync_hints(self):
        """The hint in an empty server list, and the one in an empty subscription box (gone as soon as there is text or
        the cursor is in the box)."""
        try:
            if self.tree.get_children():
                self.empty.place_forget()
            else:
                self.empty.place(relx=0.5, rely=0.5, anchor="center")
                self.empty.lift()
            if self.src.get("1.0", "end").strip() or self.focus_get() is self.src:
                self.src_hint.place_forget()
            else:
                self.src_hint.place(x=P(8), y=P(5))
        except tk.TclError:
            pass

    def show_usage(self):
        """What each provider says about traffic left and the end date, above the subscription box (red when little is left)."""
        lines, warn = [], False
        for u, sub in self.subs.items():
            line, bad = usage_line(sub.get("info"), urlsplit(u).hostname)
            if line:
                lines.append(line)
                warn = warn or bad
        try:
            if lines:
                self.usage.config(text="\n".join(lines[:4]), fg=RED if warn else MUTE)
                self.usage.pack(fill="x", pady=(0, P(6)), before=self.sbx)
            else:
                self.usage.pack_forget()
        except tk.TclError:
            pass

    def note_subs(self):
        """'обновлено в 14:05' = when the least fresh subscription was last fetched successfully."""
        self.show_usage()
        times = [s.get("time", 0) for s in self.subs.values()]
        if not times:
            return self.sub_note.config(text="")
        t = time.localtime(min(times))
        today = time.strftime("%d.%m") == time.strftime("%d.%m", t)
        self.sub_note.config(text=time.strftime(T("обновлено в %H:%M") if today else T("обновлено %d.%m"), t))

    def refresh_due(self):
        """Re-fetch subscriptions whose provider interval (profile-update-interval) has passed."""
        if self.loading or self.testing:
            return
        urls, _ = split_sources(self.cfg["sources"])
        now = time.time()
        due = []
        for u in urls:
            s = self.subs.get(u)
            if s is None:
                retry = 5 * 60  # never loaded yet
            else:
                hours = min(max(s.get("info", {}).get("interval_h") or REFRESH_DEFAULT_H, 1), 24 * 7)
                if now - s.get("time", 0) < hours * 3600:
                    continue
                retry = 15 * 60
            if now - self.sub_fail.get(u, 0) >= retry:
                due.append(u)
        if due:
            self.load(silent=True, only=due)

    # ----- RU lists -----
    def update_rules_due(self):
        """Weekly refresh of the RU lists, downloaded through the tunnel while connected."""
        now = time.time()
        if (self.rules_busy or self.state != "on" or not self.ru.get() or self.region() == regions.NONE or now - self.t0 < 20
                or now - self.cfg.get("rules_ok", 0) < RULES_EVERY
                or now - self.cfg.get("rules_try", 0) < RULES_RETRY):
            return
        self.rules_busy = True
        self.cfg["rules_try"] = now
        region = self.region()

        def work():
            try:
                n = update_rule_sets(MIXED_PORT, region)
            except Exception:
                n = 0
            self._ui(lambda: self.rules_done(n))
        threading.Thread(target=work, daemon=True).start()

    def rules_done(self, n):
        self.rules_busy = False
        if n == len(regions.rule_sets(self.region())):
            self.cfg["rules_ok"] = time.time()
            self.say(T("Списки сайтов страны обновлены. Они заработают при следующем подключении."))
        self.save(sources=False)

    # ----- speed test -----
    def run_test(self, quick=False):
        """The user's test (the button), or with `quick` the background one of «Быстрейший из списка»: ping of every server and a
        short speed run of the best few, which is what the choice by ping and speed goes by."""
        if self.testing:
            if quick:
                return
            self.test_stop.set()
            return self.test_btn.config(text=T("Останавливаю…"))
        if not self.outs:
            return self.say(T("Сначала добавь подписку и нажми «Обновить»."), err=True)
        plan = (False, True, True) if quick else (self.v_flags.get(), self.v_ping.get(), self.v_speed.get())
        if not any(plan):
            return self.say(T("В настройках выключено всё: флаги, пинг и скорость. Включи то, что нужно измерить."), err=True)
        self.testing = True
        self.test_quick = quick
        self.test_stop.clear()
        self.test_btn.config(text=T("Остановить"))
        self.say(T("Подбираю лучший сервер: проверяю отклик и скорость…") if quick else "")
        self.test_thread = threading.Thread(target=self._test_worker, args=(list(self.outs), plan, quick), daemon=True)
        self.test_thread.start()

    def _ui(self, fn):
        """Hand fn to the Tk thread. Worker threads must never call Tk themselves."""
        self.uiq.put(fn)

    def pump(self):
        try:
            while True:
                self.uiq.get_nowait()()
        except queue.Empty:
            pass
        finally:
            if not self.quitting:  # after destroy() there is no window left to schedule on
                self._pump_id = self.after(50, self.pump)

    def on_select(self, e=None):
        """Remember the server the user picked. Selections the app makes itself (self._pick) do not count,
        so a temporarily shorter list never overwrites the saved choice."""
        sel = self.tree.selection()
        if sel and sel[0] != self._pick:
            self._pick = sel[0]
            self.cfg["chosen"] = self.chosen()
            self.want_switch()
        self.refresh_power()

    # ----- changing the server of a running connection -----
    # The core is never restarted for this: the "proxy" selector is told, so the tunnel stays up, nothing leaves around it
    # and the connection is on the new server at once. A server that does not answer means no traffic, not a direct one.
    def want_switch(self):
        """The user picked another row while the connection is up (or coming up): move the core, a moment after the last
        click so that going through the list with the arrow keys does not switch at every row."""
        if self.state == "off":
            return
        if self.switch_timer:
            self.after_cancel(self.switch_timer)
        self.switch_timer = self.after(350, self.apply_choice)

    def switch_target(self):
        """What the selector should be on for what the list says: the server, or in «Быстрейший из списка» the server the
        app picked by ping and speed, else the core's own group."""
        want = self.chosen()
        if want == "AUTO":
            return self.smart_tag if self.smart_tag in self.core_tags else AUTO_TAG
        return want

    def apply_choice(self):
        self.switch_timer = None
        if self.state != "on" or not self.api:  # still connecting: got_current() comes back here once the core is up
            return
        if self.chosen() != "AUTO":
            self.smart_tag = None
        target = self.switch_target()
        if target != AUTO_TAG and target not in self.core_tags:
            where = flags.strip_flag(self.current) if self.current else ""
            return self.say(T("Этого сервера не было в списке при подключении. Отключись и подключись снова, тогда им можно будет "
                            "пользоваться. Пока всё идёт через «{0}».").format(where), err=True)
        if target == self.core_sel:
            return
        if self.switching:
            self.switch_again = True
            return
        self.switching = True
        api, url = self.api, self.pro()["auto_url"]
        self.say(T("Переключаюсь на «{0}»…").format(AUTO_LABEL if target == AUTO_TAG else flags.strip_flag(target)))

        def work():
            ok, why = switch_server(api, target)
            now = current_server(api) if ok else None
            ms = server_delay(api, now, url, 5000) if now else None  # the core's own check: is it answering?
            self._ui(lambda: self.switched(api, target, ok, why, now, ms))
        threading.Thread(target=work, daemon=True).start()

    def switched(self, api, target, ok, why, now, ms):
        self.switching = False
        if api != self.api or self.state == "off":  # the connection ended meanwhile
            return
        if ok:
            self.core_sel = target
            if now:
                self.current = now
                self.mark_live(now)
            self.refresh_power()
            name = flags.strip_flag(now or target)
            if now and ms is None:
                self.say(T("Сервер «{0}» не отвечает. Через него трафик не идёт, мимо VPN ничего не уходит. Выбери другой сервер.").format(name), err=True)
            elif ms is not None and self.chosen() == "AUTO":
                sp = self.results.get(now or target, (None, None))[1]
                self.say(T("Автовыбор: «{0}», отклик {1:.0f} мс").format(name, ms) + (", " + fmt_speed(sp) if choice.usable(sp) else "") + ".")
            elif ms is not None:
                self.say(T("Теперь «{0}», отклик {1:.0f} мс.").format(name, ms))
            else:
                self.say(T("Теперь «{0}».").format(name))
        else:
            self.say(T("Не получилось переключить сервер ({0}). Соединение осталось на прежнем.").format(why), err=True)
        if self.switch_again:
            self.switch_again = False
            self.apply_choice()

    # ----- «Быстрейший из списка»: ping and speed together -----
    # The lowest ping can sit on a thin pipe: fine for a message, bad for a video. The core's own group goes by ping alone, so
    # the app measures speed too (a few seconds, the best few servers, now and then), weighs both (choice.py) and puts the
    # connection on the result. Until there are numbers, and whenever speed is switched off, the core's group does the choice.
    def use_speed(self):
        """Does the auto mode weigh speed? Only when the advanced settings allow it and ping and speed are switched on."""
        return bool(self.pro()["auto_speed"]) and bool(self.v_speed.get()) and bool(self.v_ping.get())

    def auto_candidates(self):
        """{tag: (ping, speed)} of the servers the auto mode may be on, from the measurements (those that stopped answering
        a moment ago, and those the core does not have, are left out)."""
        now = time.time()
        res = {}
        for tag in set(self.auto_pool()) & self.core_tags:
            if self.skip_auto.get(tag, 0) > now or self.alive.get(tag) is False:
                continue
            p, s = self.results.get(tag, (None, None))
            if choice.usable(p):
                res[tag] = (p, s if choice.usable(s) else None)
        return res

    def smart_pick(self):
        """The server the auto mode should be on, or None when the numbers say nothing (the core's group goes on)."""
        if not self.use_speed():
            return None
        res = self.auto_candidates()
        if not any(choice.usable(s) for _, s in res.values()):
            return None
        stay = self.smart_tag or (self.current if self.current in res else None)
        return choice.best(res, self.pro()["auto_focus"], current=stay)

    def apply_smart(self):
        """Connected in the auto mode: put the connection on the server the numbers favour (only for a clear gain)."""
        if self.state != "on" or not self.api or self.chosen() != "AUTO" or len(self.core_tags) < 2:
            return
        tag = self.smart_pick()
        if tag is None or tag == self.smart_tag:
            return
        self.smart_tag = tag
        self.apply_choice()

    def review_auto(self):
        """Connected in the auto mode: if the speeds are not fresh, measure them (the background test), then pick."""
        if self.state != "on" or not self.api or self.chosen() != "AUTO" or len(self.core_tags) < 2 or self.testing:
            return
        if self.use_speed() and not self.loading:
            pool = [t for t in self.auto_pool() if t in self.core_tags]
            fresh = sum(1 for t in pool if time.time() - self.speed_time.get(t, 0) < REVIEW_EVERY)
            if fresh < min(3, len(pool)):
                return self.run_test(quick=True)
        self.apply_smart()

    def health_check(self):
        """On the server the app picked: is it still answering? Asked of the core, not the tunnel, every few seconds."""
        if (self.state != "on" or not self.api or self.smart_tag is None or self.chosen() != "AUTO" or self.switching
                or self.testing):
            return
        api, tag, url = self.api, self.smart_tag, self.pro()["auto_url"]

        def work():
            ms = server_delay(api, tag, url, 4000)
            self._ui(lambda: self.health_done(api, tag, ms))
        threading.Thread(target=work, daemon=True).start()

    def health_done(self, api, tag, ms):
        if api != self.api or tag != self.smart_tag or self.state != "on":
            return
        if ms is not None:
            self.bad_checks = 0
            return
        self.bad_checks += 1
        if self.bad_checks < 2:  # one lost answer is not yet a dead server
            return
        self.bad_checks = 0
        self.skip_auto[tag] = time.time() + 600
        self.say(T("Сервер «{0}» перестал отвечать, перехожу на другой.").format(flags.strip_flag(tag)), err=True)
        self.smart_tag = None
        self.smart_tag = self.smart_pick()  # the next best; None: the core's own group takes over
        self.apply_choice()

    def select(self, iid):
        self._pick = iid
        self.tree.selection_set(iid)

    def is_alive(self, i):
        tag = self.outs[i]["tag"]
        a = self.alive.get(tag)
        if a is not None:
            return a
        p = self.results.get(tag, (None, None))[0]
        return p is not None and p >= 0

    def _probe(self, i, plan):
        """One server of the test. Only what is switched on is measured: the response time (ping), the real exit
        country (flags), and, if the ping is off, a bare alive check so a speed test knows whom to try.
        Returns (ping ms or None, country or None, alive True/False/None)."""
        flags_on, ping_on, _ = plan
        if i in self.test_skip:
            return None, None, False  # the core refused this server's data
        port = TEST_BASE_PORT + i
        ms = probe_ping(port) if ping_on else None
        alive = (ms is not None) if ping_on else None
        cc = None
        if (flags_on or not ping_on or self.skip_cc()) and alive is not False and not self.test_stop.is_set():
            cc = probe_exit(port)
            if alive is None:  # the country request doubles as the alive check; a plain request is the fallback
                alive = cc is not None or probe_ping(port) is not None
        return ms, cc, alive

    def probed(self, i, ms, cc, alive, plan, done, total):
        """UI side of one finished server: show what was measured, nothing else."""
        _, ping_on, speed_on = plan
        if i < len(self.outs) and alive is not None:
            self.alive[self.outs[i]["tag"]] = alive
        if ping_on:
            self._cell(i, ping=(-1 if ms is None else ms))
        elif alive is False and speed_on:
            self._cell(i, speed=-1)  # shown as a dash: nothing to measure on a server that does not answer
        self.set_exit(i, cc)
        self.count.config(text=f"{T('Пинг') if ping_on else T('Проверка')} {done}/{total}")

    def _probe_all(self, outs, plan, quick=False):
        """The measuring itself (the core is already running): servers in parallel, then the speed of the best ones.
        `quick` (the background one): fewer servers, a few seconds each, and only those the auto mode may use."""
        _, ping_on, speed_on = plan
        n = len(outs)
        alive_i, pings, done = {}, {}, 0
        pro = self.pro()
        with ThreadPoolExecutor(pro["test_parallel"]) as ex:
            futs = {ex.submit(lambda i=i: (None, None, None) if self.test_stop.is_set() else self._probe(i, plan)): i
                    for i in range(n)}
            for f in as_completed(futs):
                i = futs[f]
                ms, cc, alive = f.result()
                done += 1
                if alive is None and ms is None and self.test_stop.is_set():
                    continue  # skipped after Stop, leave the row untested
                alive_i[i], pings[i] = bool(alive), ms
                self._ui(lambda i=i, ms=ms, cc=cc, alive=alive, d=done: self.probed(i, ms, cc, alive, plan, d, n))
        if not speed_on or self.test_stop.is_set():
            return
        pool = set(self.auto_pool()) if quick else None
        usable_i = [i for i, ok in alive_i.items() if ok and (pool is None or outs[i]["tag"] in pool)]
        if ping_on:  # the fastest by response time are the likeliest to be fast
            top = sorted(usable_i, key=lambda i: pings[i])[:min(pro["test_top"], QUICK_TOP) if quick else pro["test_top"]]
        else:  # no ranking without ping: every server that answered
            top = sorted(usable_i)
        secs = min(pro["test_secs"], QUICK_SECS) if quick else pro["test_secs"]
        urls = list(SPEED_URLS)  # one source for the whole run so servers are compared on equal terms
        self.speed_host = ""
        for k, i in enumerate(top, 1):
            if self.test_stop.is_set():
                break
            self._ui(lambda k=k, t=len(top): self.count.config(text=T("Скорость {0}/{1}").format(k, t)))
            sp, used = probe_speed(TEST_BASE_PORT + i, secs=secs, urls=urls)
            if used:
                urls.remove(used)
                urls.insert(0, used)
                self.speed_host = urlsplit(used).hostname or ""
            if sp is None and self.test_stop.is_set():
                break
            self._ui(lambda i=i, sp=(-1 if sp is None else sp): self._cell(i, speed=sp))

    def _cell(self, i, ping=None, speed=None):
        tag = self.outs[i]["tag"] if i < len(self.outs) else None
        if tag is None:
            return
        p, s = self.results.get(tag, (None, None))
        self.results[tag] = (ping if ping is not None else p, speed if speed is not None else s)
        if choice.usable(speed):
            self.speed_time[tag] = time.time()
        p, s = self.results[tag]
        if self.tree.exists(str(i)):
            self.tree.set(str(i), "ping", fmt_ping(p))
            self.tree.set(str(i), "speed", fmt_speed(s))

    def _test_worker(self, outs, plan=(True, True, True), quick=False):
        err = None
        try:
            # Always measure around any tunnel (ours, a leftover core, Karing...), not through it: sockets are bound
            # to the real adapter. Without a VPN this changes nothing, so no need to guess whether one is up.
            nic = physical_nic()
            if IS_LINUX and self.state == "off":
                nic = None  # binding sockets to a device may need CAP_NET_RAW on old kernels; only do it when needed
            if not nic and self.state != "off":
                raise RuntimeError(T("не нашёл подключение к интернету"))
            outs = resolve_servers(outs)
            xports = {}
            if engines.has_xray(outs) and self.pro()["use_xray"]:
                self.test_xray, xports, xnote = launch_xray(outs, XRAY_TEST_PORT, XRAYTESTCFG, XRAYTESTLOG, nic)
                if xnote:
                    self._ui(lambda: self.say(xnote, err=True))
            self.test_skip = {i for i, o in enumerate(outs) if engines.is_xray(o) and o["tag"] not in xports}  # nothing serves them
            write_json(TESTCFG, build_test_config(outs, nic, self.test_skip, xports))
            open(TESTLOG, "w").close()
            ok, msg = core_check(TESTCFG)
            if not ok:  # one server the core does not accept must not spoil the test of all the others
                good, bad = salvage_outs([o for i, o in enumerate(outs) if i not in self.test_skip], CHECKCFG)
                self.test_skip |= {i for i, o in enumerate(outs) if any(o is b for b in bad)}
                if good and self.test_skip:
                    write_json(TESTCFG, build_test_config(outs, nic, self.test_skip, xports))
                    ok, msg = core_check(TESTCFG)
            if not ok:
                raise RuntimeError(T("не получилось подготовить проверку серверов"))
            self.test_proc = subprocess.Popen([CORE, "run", "-c", TESTCFG], cwd=DATA, creationflags=NOWIN,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            own(self.test_proc)
            last = TEST_BASE_PORT + max(i for i in range(len(outs)) if i not in self.test_skip)
            deadline = time.time() + 10
            while True:
                if self.test_proc.poll() is not None:
                    raise RuntimeError(T("проверка не запустилась (возможно, мешает антивирус)"))
                try:
                    socket.create_connection(("127.0.0.1", last), 0.3).close()
                    break
                except OSError:
                    if time.time() > deadline:
                        raise RuntimeError(T("проверка не ответила (возможно, мешает антивирус)"))
                    time.sleep(0.2)

            self._probe_all(outs, plan, quick)
        except Exception as e:
            err = str(e)
        finally:
            p = self.test_proc
            self.test_proc = None
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except Exception:
                    p.kill()
            stop_proc(self.test_xray)
            self.test_xray = None
            self._ui(lambda: self.test_done(err))

    def test_done(self, err):
        quick, self.test_quick = self.test_quick, False
        self.testing = False
        self.test_btn.config(text=self.test_label())
        self.count.config(text=str(len(self.outs)))
        if err:
            if quick:
                return self.say(T("Не получилось проверить серверы для автовыбора, он остался на прежнем. Попробую позже."), err=True)
            return self.say(T("Проверка не получилась: ") + err + T(". Проверь интернет и попробуй ещё раз."), err=True)
        show_flags, show_ping, show_speed = self.v_flags.get(), self.v_ping.get(), self.v_speed.get()

        def res(i):
            return self.results.get(self.outs[i]["tag"], (None, None))

        alive_all = [i for i in range(len(self.outs)) if self.is_alive(i)]
        # «самый быстрый» is advice on what to connect to: a server in the user's own blocking country is no answer
        alive = [i for i in alive_all if not self.is_home_exit(self.outs[i])] or alive_all
        passed = len(alive_all) - len(alive)
        if not alive:
            asked = any(self.alive.get(o["tag"]) is not None or res(i)[0] is not None for i, o in enumerate(self.outs))
            return self.say(T("Ни один сервер не ответил. Проверь интернет или обнови подписку.") if asked
                            else T("Проверка остановлена до первых результатов."), err=True)
        with_speed = [i for i in alive if show_speed and res(i)[1] is not None and res(i)[1] >= 0]
        with_ping = [i for i in alive if show_ping and res(i)[0] is not None and res(i)[0] >= 0]

        # The test only reorders rows and reports. It never changes what the user picked: with «Быстрейший из списка»
        # selected, connecting must still switch servers by itself, not pin the connection to one of them.
        self.sort_rows()
        if not quick:  # a test in the background must not move the list under the user's hand
            self.tree.yview_moveto(0)
        try:
            write_json(EXITFILE, self.exit_cc)
        except OSError:
            pass
        src = note = hint = ""
        if with_speed:
            best = self.best_row(alive)  # ping and speed together: the lowest ping with a thin pipe is not the best choice
            if best is None:
                best = max(with_speed, key=lambda i: res(i)[1])
            p, sp = res(best)
            what = fmt_speed(sp) + (f", {fmt_ping(p)}" if show_ping and p is not None and p >= 0 else "")
            skipped = sum(1 for i in alive if res(i)[1] is not None and res(i)[1] < 0)
            if skipped:
                what += T("; у {0} серверов скорость не замерилась").format(skipped)
            head = T("Лучший выбор: {0} ({1}).").format(flags.strip_flag(self.outs[best]['tag']), what)
            quick_ping = min(with_ping, key=lambda i: res(i)[0]) if with_ping else None
            if quick_ping is not None and quick_ping != best and choice.usable(res(quick_ping)[1]):
                head += T(" Отклик ниже у «{0}» ({1}), но скорость там {2}.").format(
                    flags.strip_flag(self.outs[quick_ping]["tag"]), fmt_ping(res(quick_ping)[0]), fmt_speed(res(quick_ping)[1]))
            src = T(" Скорость измерена загрузкой с {0}.").format(self.speed_host) if getattr(self, "speed_host", "") else ""
        elif with_ping:
            best = min(with_ping, key=lambda i: res(i)[0])
            head = T("Самый быстрый по отклику: {0} ({1}).").format(flags.strip_flag(self.outs[best]['tag']), fmt_ping(res(best)[0]))
        else:
            best = None
            head = T("Ответили {0} из {1} серверов.").format(len(alive_all), len(self.outs))
        if show_flags:
            wrong = sum(1 for o in self.outs
                        if self.exit_cc.get(okey(o)) and flags.code_for(o["tag"]) not in ("??", self.exit_cc[okey(o)]))
            if wrong:
                note = T(" У {0} серверов страна в названии не совпала с реальным выходом: флаг показан по выходу.").format(wrong)
        if best is not None and self.tree.selection() and self.tree.selection()[0] == "auto":
            hint = (T("«Быстрейший из списка» выбирает по отклику и скорости вместе и сам переключается, если сервер стал хуже. "
                    "Чтобы подключаться только к одному серверу, выбери его в списке."))
        if passed:
            hint += T(" Серые серверы (выход в {0}) «Быстрейший из списка» не берёт: через них блокировки не обойти.").format(regions.name(self.home_cc) or self.home_cc)
        if quick:
            self.say("")  # the background test says only what it did with the connection (apply_smart)
        else:
            self.say(f"{head}{src}{note} {hint}".strip())
        self.apply_smart()  # connected in the auto mode: go to what the numbers say

    def best_row(self, rows):
        """Index of the best server among `rows` by ping and speed together (what is shown counts), None if nothing to go by."""
        show_ping, show_speed = self.v_ping.get(), self.v_speed.get()
        cands = {}
        for i in rows:
            p, sp = self.results.get(self.outs[i]["tag"], (None, None))
            if show_ping and not choice.usable(p):
                continue
            cands[str(i)] = (p if show_ping else 0.0, sp if show_speed else None)
        top = choice.best(cands, self.pro()["auto_focus"])
        return int(top) if top is not None else None

    def is_pinned(self, i):
        return okey(self.outs[i]) in self.cfg["pins"]

    def row_text(self, o):
        return ("★ " if okey(o) in self.cfg["pins"] else "") + flags.strip_flag(o["tag"])

    def toggle_pin(self, i):
        """Pin a server to the top of the list, or take it off again; kept by address, so it survives a refresh."""
        key = okey(self.outs[i])
        pins = [k for k in self.cfg["pins"] if k != key]
        if key not in self.cfg["pins"]:
            pins.insert(0, key)
        self.cfg["pins"] = pins[:200]
        if self.tree.exists(str(i)):
            self.tree.item(str(i), text=self.row_text(self.outs[i]))
        self.sort_rows()
        self.save(sources=False)

    def row_menu(self, e):
        """Right click on a server: pin it, copy its name."""
        iid = self.tree.identify_row(e.y)
        if not iid or iid == "auto" or not iid.isdigit() or int(iid) >= len(self.outs):
            return
        i = int(iid)
        o = self.outs[i]
        m = tk.Menu(self, tearoff=0, bg=PAPER, fg=INK, activebackground=INK, activeforeground=PAPER, bd=0, font=self.f_s)
        m.add_command(label=T("Открепить") if self.is_pinned(i) else T("Закрепить сверху"), command=lambda: self.toggle_pin(i))
        m.add_command(label=T("Скопировать название"), command=lambda: (self.clipboard_clear(), self.clipboard_append(flags.strip_flag(o["tag"]))))
        m.tk_popup(e.x_root, e.y_root)

    def on_login_toggle(self, *a):
        want = self.v_login.get()
        if self._login_busy:
            return
        if autostart_set(want):
            self.cfg["autostart"] = want
            self.save(sources=False)
            self.say(T("Программа будет запускаться при входе в систему.") if want else T("Автозапуск выключен."))
        else:
            self._login_busy = True  # put the tick back without running this handler again
            self.v_login.set(not want)
            self._login_busy = False
            self.say(T("Не получилось изменить автозапуск. Нужны права администратора и собранная программа."), err=True)

    def autostart_run(self):
        """Started at login (--autostart): out of the way in the tray, and connected if the settings say so."""
        if self.tray_ok:
            self.hide_to_tray()
        if self.pro()["autoconnect"] and self.outs and self.state == "off":
            self.toggle()

    def sort_rows(self):
        """Pinned first, then by the score of ping and speed together (choice.py); only what is switched on counts. Servers
        that did not answer and untested ones go last; "auto" stays on top."""
        focus, show_ping, show_speed = self.pro()["auto_focus"], self.v_ping.get(), self.v_speed.get()
        assumed = choice.assumed_speed({t: (p, sp if show_speed else None) for t, (p, sp) in self.results.items()})

        def key(i):
            p, sp = self.results.get(self.outs[i]["tag"], (None, None))
            fast = show_speed and choice.usable(sp)
            usep = show_ping and choice.usable(p)
            # the order of the list is the order of advice: ping and speed together, as «Быстрейший из списка» weighs them
            score = choice.score(p if usep else 0.0, sp if fast else None, focus, assumed if show_speed else None) if (usep or fast) else 0.0
            return (not self.is_pinned(i), not self.is_alive(i), not (usep or fast), -score, p if usep else 0)
        start = 1 if self.tree.exists("auto") else 0
        for pos, i in enumerate(sorted(range(len(self.outs)), key=key)):
            self.tree.move(str(i), "", pos + start)

    # ----- connection -----
    def toggle(self):
        if self.proc and self.proc.poll() is None:
            return self.stop()
        if not is_admin():
            self.say(T("Нужны права администратора. Закрой программу и открой её снова от имени администратора."), err=True)
            return show_error(self, T("Для работы VPN нужны права администратора.\n\nЗакрой программу и открой её снова: нажми "
                                    "на значок правой кнопкой и выбери «Запуск от имени администратора»."))
        if not self.outs:
            return self.say(T("Сначала добавь подписку и нажми «Обновить»."), err=True)
        if self.testing and not self.test_quick:
            return self.say(T("Идёт тест скорости. Дождись конца или остановь его."), err=True)
        if self.testing:  # the background test of the auto mode of the connection that has just been closed: it ends at once
            self.test_stop.set()
            if self.test_thread:
                self.test_thread.join(8)
            self.testing = self.test_quick = False
        self.clean_done.wait(8)  # leftover cores from a previous run are being closed
        self.save()
        if karing_running() and not ask_yes_no(self, T("Запущен другой VPN-клиент (Karing / v2rayN / Hiddify / NekoRay).\n"
                     "Два VPN сразу конфликтуют. Отключи его и нажми «Да», либо «Нет» для отмены.")):
            return
        proxy_note = ""
        addr, alive = local_proxy_state()
        if addr and not alive:
            if ask_yes_no(self, MSG_DEAD_PROXY.format(addr=addr), T("Отключить прокси"), T("Оставить")):
                proxy_note = T("Прокси Windows отключён: он не отвечал.") if disable_system_proxy() else ""
                if not proxy_note:
                    self.say(T("Не получилось отключить прокси. Отключи его в настройках Windows: «Сеть и Интернет» → «Прокси»."), err=True)
            else:
                proxy_note = T("Прокси Windows {0} не отвечает, сайты в браузере могут не открываться.").format(addr)
        elif addr:
            proxy_note = T("В Windows включён прокси {0} (другая программа): браузер идёт через него, а не через этот VPN.").format(addr)
        if not os.path.isfile(CORE):
            self.say(T("Не хватает файла для работы VPN. Скорее всего, его удалил антивирус."), err=True)
            if Dialog(self, MSG_NO_CORE, [T("Скачать заново"), T("Закрыть")], "error", 0, 1).result == 0:
                open_url(RELEASES_URL)
            return
        self.api = (free_port(), secrets.token_hex(16))  # new secret per connection, loopback only
        self.current = ""
        open(LOGFILE, "w").close()
        self._pos = 0
        ok, msg, note = self.prepare_config()
        if not ok:
            self.toggle_log(True)
            self.say(T("Не получилось подготовить подключение. Обнови подписку или выбери другой сервер."), err=True)
            return show_error(self, T("Не получилось подготовить подключение.\n\nЧто сделать:\n• нажми «Обновить» в разделе «Подписки» "
                                    "и подключись снова;\n• или выбери в списке другой сервер.\n\nЕсли не помогает, открой «Лог» внизу "
                                    "окна и пришли его текст в поддержку.\n\nТехническая причина: ") + msg[-300:])
        try:
            self.proc = start_core(RUNCFG)
        except OSError as e:  # blocked by an antivirus, no rights, file locked
            self.stop_xray()
            self.say(T("VPN не запустился. Проверь антивирус и права."), err=True)
            return show_error(self, T("VPN не смог запуститься.\n\nОбычно виноват антивирус или нехватка прав. Что сделать: добавь программу в исключения антивируса, закрой её и открой снова от имени администратора.\n\nТехническая причина: {0}").format(e))
        self.active = self.sel_name()
        self.state = "connecting"
        self.t_conn = time.time()
        self.say(" ".join(t for t in (note, proxy_note, "" if IS_WIN else T("Подтверди права администратора в окне системы.")) if t))
        self.refresh_power()

    def prepare_config(self):
        """Write the config to connect with. If the core refuses it, repair what can be repaired instead of giving up:
        a damaged downloaded rule list is dropped (the bundled copy takes over), a server whose data the core does not
        accept is left out. Returns (ok, core message, note for the user)."""
        outs, chosen, pool, extra = self.outs, self.chosen(), self.auto_pool(), clean_domains(self.extra.get())
        pro = self.pro()
        mixed = pick_port(pro["mixed_port"])
        notes = [] if mixed == pro["mixed_port"] else [T("Порт {0} занят, локальный прокси на порту {1}.").format(pro['mixed_port'], mixed)]
        self.stop_xray()
        xports = {}
        if engines.has_xray(outs):
            if pro["use_xray"]:
                xs = resolve_servers([o for o in outs if engines.is_xray(o)])  # Xray needs no DNS of its own, whatever the tunnel does
                by_tag = {o["tag"]: o for o in xs}
                outs = [by_tag.get(o["tag"], o) for o in outs]
                self.xray_proc, xports, problem = launch_xray(outs, XRAY_PORT, XRAYCFG, XRAYLOG)
                if problem:
                    notes.append(problem)
            else:
                notes.append(T("Серверы XHTTP и похожие пропущены: Xray выключен в расширенных настройках."))
            outs = [o for o in outs if not engines.is_xray(o) or o["tag"] in xports]
            names = {o["tag"] for o in outs}
            pool = [t for t in pool if t in names] or list(names)
            if chosen != "AUTO" and chosen not in names:
                chosen = "AUTO"
            if not outs:
                return False, T("нет серверов, которые можно запустить"), " ".join(notes)

        def write():
            write_json(RUNCFG, build_config(outs, chosen, self.ru.get(), extra, self.api, pool, mixed, pro, xports, self.region()))
        write()
        ok, msg = core_check(RUNCFG)
        for step in ("rules", "servers", "pro"):  # what may be to blame, most likely first
            if ok:
                break
            if step == "rules":
                if "rule-set" not in msg.lower():
                    continue
                drop_downloaded_rules()
                self.cfg["rules_ok"] = 0  # fetch a fresh copy at the next chance
                notes.append(T("Список сайтов страны был повреждён, взял встроенный."))
            elif step == "servers":
                self.say(T("Проверяю серверы по одному…"))
                self.update_idletasks()
                good, bad = salvage_outs(outs)
                if not (good and bad):
                    continue
                names = {o["tag"] for o in good}
                outs = good
                chosen = chosen if chosen in names else "AUTO"
                pool = [t for t in pool if t in names] or [o["tag"] for o in good]
                notes.append(T("Пропущено серверов с неверными данными: {0}.").format(len(bad)))
            else:  # the user's advanced settings: last suspect, but a connection beats a setting
                if pro == PRO_DEFAULTS:
                    continue
                pro = dict(PRO_DEFAULTS)
                mixed = pick_port(pro["mixed_port"])
                notes.append(T("Расширенные настройки не подошли, использованы обычные."))
            write()
            ok, msg = core_check(RUNCFG)
        self.mixed_active = mixed
        self.core_tags = {o["tag"] for o in outs}  # what this core can be switched between while it runs
        self.core_sel = selector_default([o["tag"] for o in outs], chosen)
        if not ok:
            self.stop_xray()
        return ok, msg, " ".join(notes)

    def stop_xray(self):
        stop_proc(getattr(self, "xray_proc", None))
        self.xray_proc = None

    def region(self):
        """The country whose sites go without the VPN ('NONE' when none, or not chosen yet)."""
        r = self.cfg.get("region")
        return r if r in regions.NAMES else regions.NONE

    def open_setup(self, first=False):
        """Language and country. A new country takes effect at once (its lists are fetched in the background); a new language
        needs the program to start again."""
        suggest = self.home_cc or regions.system_country()
        res = SetupDialog(self, self.cfg.get("region") or "", first, suggest).result
        if not res:
            return
        lang, region = res
        old_region = self.cfg.get("region")
        self.cfg.update(region=region, lang=lang, setup_done=True)
        global LOCAL_DNS
        LOCAL_DNS = self.pro()["dns_local"] or regions.local_dns(self.region())
        self.ru_check.lbl.config(text=self.direct_label())
        self.region_btn.config(text=self.region_button_text())
        if region != old_region:
            self.cfg["rules_ok"] = 0  # the lists of the new country are fetched at the first chance
            if region != regions.NONE:
                threading.Thread(target=lambda: update_rule_sets(None, region), daemon=True).start()
            if self.state == "on":
                self.say(T("Страна изменена. Новые правила заработают при следующем подключении."))
        self.save(sources=False)
        if lang != self.lang_at_start:
            self.restart()

    def first_run(self):
        """A new installation asks for the language and the country once."""
        if not self.cfg.get("setup_done") and not self.quitting:
            self.open_setup(first=True)

    def region_button_text(self):
        r = self.region()
        return T("Страна: {0}").format(regions.name(r) if r != regions.NONE else T("не выбрана"))

    def direct_label(self):
        """The text of the checkbox: 'Russian sites' for Russia, 'sites of <country>' for every other."""
        r = self.region()
        if r == "RU":
            return T("Российские сайты напрямую, без VPN")
        if r == regions.NONE:
            return T("Сайты своей страны напрямую, без VPN (выбери страну)")
        return T("Сайты страны «{0}» напрямую, без VPN").format(regions.name(r))

    def pro(self):
        """The advanced settings in force (defaults where the user changed nothing or typed something unusable)."""
        return clean_pro(self.cfg.get("pro"))[0]

    def apply_live(self):
        """The design settings that need no restart: opacity, always on top, the button's shadow, blinking, width."""
        global SHADOW, ANIM
        pro = self.pro()
        SHADOW, ANIM = bool(pro["shadow"]), bool(pro["anim"])
        for attr, value in (("-alpha", pro["alpha"] / 100), ("-topmost", bool(pro["on_top"]))):
            try:
                self.attributes(attr, value)
            except tk.TclError:  # not every window manager has it
                pass
        try:
            self.power.draw()
            w = P(pro["win_width"])
            self.minsize(min(P(440), w), self.minsize()[1])
            if abs(self.winfo_width() - w) > 2:
                self.geometry(f"{w}x{self.winfo_height()}")
                self.keep_on_screen()
        except (tk.TclError, AttributeError):
            pass

    def remember_window(self):
        """Keep where the window stands and how wide it is, if the settings ask for it."""
        try:
            if self.pro()["remember_window"] and self.winfo_viewable():
                self.cfg["win"] = {"x": self.winfo_x(), "y": self.winfo_y(), "w": self.winfo_width()}
        except (tk.TclError, AttributeError):
            pass

    def restore_window(self):
        """Put the window back where it was, if that place is still on a screen."""
        try:
            w = self.cfg.get("win")
            if not (self.pro()["remember_window"] and isinstance(w, dict)):
                return
            x, y, width = int(w["x"]), int(w["y"]), int(w["w"])
            top, bottom = self.work_area()
            if not (-P(200) < x < self.winfo_screenwidth() - P(120) and top - P(20) <= y < bottom - P(120) and P(380) <= width <= P(1200)):
                return
            self.geometry(f"{width}x{self.winfo_height()}+{x}+{y}")
        except (KeyError, TypeError, ValueError, tk.TclError):
            pass

    def restart(self):
        """Start this program again (the look is read at start). The VPN is off for the moment."""
        if self.state != "off" and not ask_yes_no(self, T("Чтобы применить изменения, программа перезапустится. VPN на это "
                                                  "время выключится, потом его можно включить снова.\n\nПерезапустить?"),
                                                  T("Перезапустить"), T("Не сейчас")):
            return
        cmd = [sys.executable] if self.frozen() else [sys.executable, os.path.abspath(__file__)]
        env = dict(updater.fresh_env(), FIMA_WAIT_PID=str(os.getpid()))
        extra = {"creationflags": 0x00000008 | 0x00000200 | NOWIN} if IS_WIN else {"start_new_session": True}
        try:
            subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True, **extra)
        except OSError:
            return self.say(T("Не получилось перезапустить. Закрой программу и открой её снова."), err=True)
        self.quit_app()

    def may_restart(self):
        """At most 3 automatic reconnects in 10 minutes: a core that keeps dying must not loop forever."""
        now = time.time()
        self.restarts = [t for t in self.restarts if now - t < 600]
        if len(self.restarts) >= 3:
            return False
        self.restarts.append(now)
        return True

    def reconnect(self):
        if self.state != "off" or self.quitting or self.installing:
            return
        if karing_running():
            return self.say(T("Соединение прервалось. Сейчас работает другой VPN-клиент: выключи его и нажми «Подключить»."), err=True)
        self.toggle()

    def fail(self):
        was_on = self.state == "on" and time.time() - self.t0 > 15  # it had worked: not a bad config
        rc = self.proc.poll() if self.proc else None
        err = ""
        try:
            err = self.proc.stderr.read().decode("utf-8", "replace") if self.proc and self.proc.stderr else ""
        except Exception:
            pass
        self.stop()
        if not IS_WIN and (rc in (126, 127) or "cancel" in err.lower()):
            return self.say(T("Не получилось подтвердить права администратора: окно с паролем закрыто. "
                            "Нажми «Подключить» и введи пароль."), err=True)
        if IS_WIN and was_on and self.pro()["auto_reconnect"] and self.may_restart():  # on Linux/macOS a new connection needs the password again
            self.say(T("Соединение прервалось, подключаюсь заново…"), err=True)
            self.after(1500, self.reconnect)
            return
        self.say(T("Соединение прервалось. Нажми «Подключить» ещё раз. Если так повторяется, выбери другой сервер "
                 "или обнови подписку."), err=True)
        self.toggle_log(True)

    def stop(self):
        stop_core(self.proc)
        self.stop_xray()
        self.proc = None
        self.state = "off"
        self.active = ""
        self.current = ""
        self.api = None
        self.core_tags, self.core_sel, self.smart_tag = set(), "", None
        self.switching = self.switch_again = False
        self.skip_auto, self.bad_checks = {}, 0
        if self.switch_timer:
            self.after_cancel(self.switch_timer)
            self.switch_timer = None
        if self.testing and self.test_quick:  # the background test of the auto mode is of no use without a connection
            self.test_stop.set()
        self.mark_live("")
        self.refresh_power()

    def mark_live(self, tag):
        """Blue bold row = the server the connection is using right now."""
        self.live_tag = tag or ""
        self.paint_rows()

    def poll_current(self):
        """Ask the core which server auto mode is on (off the UI thread; at most one request in flight)."""
        if self.polling or self.state not in ("connecting", "on") or not self.api:
            return
        self.polling = True
        api = self.api

        def work():
            now = current_server(api)
            self._ui(lambda: self.got_current(now, api))
        threading.Thread(target=work, daemon=True).start()

    def got_current(self, now, api):
        self.polling = False
        if api != self.api or self.state not in ("connecting", "on") or not now:  # stale answer or core gone
            return
        if self.state == "connecting":  # the core answers its API: it is really up
            self.state = "on"
            self.t0 = time.time()
            self.say("")
            self.refresh_power()
            if self.switch_target() != self.core_sel:  # something else was picked while it was connecting
                self.want_switch()
            self.after(3000, self.review_auto)  # (auto mode only) measure what the choice by ping and speed goes by
        if now != self.current:
            self.current = now
            self.mark_live(now)
            self.refresh_power()

    def tick(self):
        try:
            self._tick()
        except Exception:  # noqa: BLE001
            log_crash(*sys.exc_info())  # logged; the loop that watches the core goes on
        finally:
            if not self.quitting:
                self._tick_id = self.after(500, self.tick)

    def _tick(self):
        self.n += 1
        self.blink = (not self.blink) if ANIM else True
        if self.state in ("on", "connecting"):
            self.refresh_power()
        if self.n % 2 == 0:
            self.tail()
        if self.tray_ok and self.n % 2 == 0:
            self.tray.update(self.state == "on", self.tray_title())
        if self.n % 4 == 0 or self.state == "connecting":  # which server is auto mode on now (and: is the core up yet)
            self.poll_current()
        if self.state == "connecting" and self.proc and self.proc.poll() is None:
            # Fallback if the local API never answers: treat a core that stays alive as connected.
            if time.time() - self.t_conn > (20 if IS_WIN else 150):
                self.state = "on"
                self.t0 = time.time()
                self.say("")
                self.refresh_power()
        if self.n % 30 == 0:  # every 15 seconds: is the server the auto mode picked still answering?
            self.health_check()
        if self.n % 3600 == 0:  # every half hour: are the numbers the auto mode goes by still fresh?
            self.review_auto()
        if self.n % 120 == 0:  # every minute
            if trim_logs():
                self._pos = 0
            self.refresh_due()
            self.update_rules_due()
        if self.n % 43200 == 0 and self.cfg.get("auto_update"):  # every 6 hours
            self.update_check()
        if self.proc and self.proc.poll() is not None and self.state != "off":
            self.fail()
        elif self.xray_proc is not None and self.xray_proc.poll() is not None and self.state in ("on", "connecting"):
            self.revive_xray()

    def revive_xray(self):
        """The companion Xray stopped while the connection is up (a crash, an antivirus): start it again on the same ports,
        the core's SOCKS servers pick up where they were. At most 3 times in 10 minutes."""
        now = time.time()
        self.xray_restarts = [t for t in getattr(self, "xray_restarts", []) if now - t < 600]
        if len(self.xray_restarts) >= 3:
            self.xray_proc = None
            return self.say(T("Xray остановился несколько раз подряд: серверы XHTTP и похожие сейчас не работают. Подключись заново."), err=True)
        self.xray_restarts.append(now)
        try:
            self.xray_proc = subprocess.Popen([XRAY, "run", "-format", "json", "-c", XRAYCFG], cwd=DATA, creationflags=NOWIN,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            own(self.xray_proc)
        except OSError:
            self.xray_proc = None

    def tail(self):
        try:
            with open(LOGFILE, "rb") as f:
                f.seek(self._pos)
                data = f.read()
                self._pos = f.tell()
            if data:
                self.log.config(state="normal")
                self.log.insert("end", data.decode("utf-8", "replace"))
                self.log.see("end")
                self.log.config(state="disabled")
        except Exception:
            pass

    def tray_title(self):
        if self.state == "on":
            name = flags.strip_flag(self.current) if self.current else ""
            return (T("VPN: подключено") + (f", {name}" if name else ""))[:100]
        return T("VPN: подключаю…") if self.state == "connecting" else T("VPN: выключено")

    def show_window(self):
        """Bring the window back from the tray (or from behind other windows)."""
        self.deiconify()
        self.lift()
        self.focus_force()
        try:
            self.attributes("-topmost", True)  # Windows only lets a window forward if it asks like this
            self.after(300, lambda: self.attributes("-topmost", bool(self.pro()["on_top"])))
        except tk.TclError:
            pass

    def toggle_from_tray(self):
        self.show_window()  # a prompt (admin rights, another VPN running) needs a visible window
        self.toggle()

    def hide_to_tray(self):
        self.remember_window()
        self.withdraw()
        if not self.cfg.get("tray_hint_shown") and self.tray:
            self.tray.notify(T("Программа работает в трее. Чтобы выйти совсем, выбери «Выход» в меню значка."))
            self.cfg["tray_hint_shown"] = True
            self.save(sources=False)

    def on_close(self):
        """The window's X button: hide to the tray if there is one and the setting allows, otherwise quit."""
        if self.tray_ok and self.cfg.get("tray_on_close", True) and not self.quitting:
            return self.hide_to_tray()
        self.quit_app()

    def quit_app(self):
        self.quitting = True
        self.remember_window()
        self.save()
        self.test_stop.set()
        for p in (self.test_proc, self.test_xray, HOME_PROC):
            if p and p.poll() is None:
                p.kill()
        self.stop()
        if self.cfg.get("auto_update") and self.frozen():
            info = updater.staged(UPDATE_DIR)  # a downloaded update installs while the program is closed
            if info:
                updater.apply_staged(info, relaunch=False)
        self.destroy()

    def start_instance_server(self):
        """Listen on a loopback port: a second launch connects here and this window comes forward."""
        self._srv = None
        try:
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            with open(INSTANCE_FILE, "w", encoding="utf-8") as f:
                f.write(str(srv.getsockname()[1]))
        except OSError:
            return
        self._srv = srv

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return  # closed on exit
                try:
                    conn.settimeout(2)
                    if conn.recv(16).startswith(b"show"):
                        self._ui(lambda: self.show_window())
                        conn.sendall(b"ok\n")
                except OSError:
                    pass
                finally:
                    conn.close()
        threading.Thread(target=serve, daemon=True).start()

    def destroy(self):
        if getattr(self, "_srv", None):
            try:
                port = self._srv.getsockname()[1]
                self._srv.close()
                with open(INSTANCE_FILE, encoding="utf-8") as f:
                    mine = f.read().strip() == str(port)
                if mine:  # only our own entry; removed after the file is closed (Windows cannot delete an open file)
                    os.remove(INSTANCE_FILE)
            except OSError:
                pass
            self._srv = None
        if self.tray:
            self.tray.stop()
        for aid in (self._pump_id, self._tick_id):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        super().destroy()


def already_running():
    """True if another copy of the app holds the single-instance lock (a named mutex on Windows, flock elsewhere)."""
    global _LOCK
    if IS_WIN:
        _LOCK = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\FimaVPN-single-instance")
        return ctypes.windll.kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS
    import fcntl
    _LOCK = open(os.path.join(DATA, "app.lock"), "w")
    try:
        fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return False
    except OSError:
        return True


_LOCK = None


def signal_running_instance():
    """Ask the copy that is already running to show its window: a second launch should bring it forward, not nag."""
    try:
        with open(INSTANCE_FILE, encoding="utf-8") as f:
            port = int(f.read().strip())
        with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
            c.settimeout(2)
            c.sendall(b"show\n")
            return c.recv(8).startswith(b"ok")
    except Exception:  # noqa: BLE001
        return False


AUTOSTART_NAME = "FimaVPN"


def autostart_command():
    """The program as the system should start it at login, or None when this is not the packaged program (a source run has
    nothing stable to start)."""
    if not getattr(sys, "frozen", False):
        return None
    return [sys.executable, "--autostart"]


def _autostart_files():
    home = os.path.expanduser("~")
    return (os.path.join(home, "Library", "LaunchAgents", "io.fimavpn.plist") if IS_MAC
            else os.path.join(home, ".config", "autostart", "fimavpn.desktop"))


def autostart_set(on, cmd=None):
    """Start the program at login (or stop doing so). Windows: a scheduled task at logon with the highest rights, because
    the program needs the administrator's rights and a plain startup entry would ask for them at every login. Linux: an
    autostart entry. macOS: a LaunchAgent. Returns True if it worked."""
    cmd = cmd or autostart_command()
    try:
        if IS_WIN:
            if on:
                if not cmd:
                    return False
                tr = " ".join('"' + c + '"' if " " in c else c for c in cmd)
                r = subprocess.run(["schtasks", "/create", "/tn", AUTOSTART_NAME, "/tr", tr, "/sc", "onlogon", "/rl", "highest", "/f"],
                                   capture_output=True, creationflags=NOWIN, timeout=30)
            else:
                r = subprocess.run(["schtasks", "/delete", "/tn", AUTOSTART_NAME, "/f"], capture_output=True, creationflags=NOWIN, timeout=30)
                return r.returncode == 0 or not autostart_enabled()  # already gone is as good
            return r.returncode == 0
        path = _autostart_files()
        if not on:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            return True
        if not cmd:
            return False
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if IS_MAC:
            args = "".join(f"<string>{c}</string>" for c in cmd)
            body = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                    f'<key>Label</key><string>io.fimavpn</string><key>ProgramArguments</key><array>{args}</array>'
                    '<key>RunAtLoad</key><true/></dict></plist>\n')
        else:
            body = ("[Desktop Entry]\nType=Application\nName=VPN\nExec=" + " ".join(shlex.quote(c) for c in cmd) +
                    "\nTerminal=false\nX-GNOME-Autostart-enabled=true\n")
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def autostart_enabled():
    try:
        if IS_WIN:
            return subprocess.run(["schtasks", "/query", "/tn", AUTOSTART_NAME], capture_output=True, creationflags=NOWIN, timeout=20).returncode == 0
        return os.path.isfile(_autostart_files())
    except (OSError, subprocess.SubprocessError):
        return False


def wait_for_exit(pid, seconds=15):
    """Block until process `pid` is gone (the copy that restarted us), at most `seconds`."""
    end = time.time() + seconds
    if IS_WIN:
        try:
            k = ctypes.windll.kernel32
            k.OpenProcess.restype = ctypes.c_void_p
            h = k.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            if h:
                k.WaitForSingleObject(ctypes.c_void_p(h), int(seconds * 1000))
                k.CloseHandle(ctypes.c_void_p(h))
        except Exception:  # noqa: BLE001
            time.sleep(1.5)
        return
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.2)


def swap_selftest(new_exe):
    """`--swap-selftest <file>` in a packaged build: copy <file> over this program the way an update does and let the
    helper start it. CI checks that the started copy runs (a packaged program that cannot restart itself is the
    kind of bug unit tests cannot see)."""
    info = {"version": "0", "name": "x", "path": os.path.abspath(new_exe), "sha256": updater.sha256_file(new_exe), "tries": 0}
    return 0 if updater.apply_staged(info, relaunch=True) else 1


def net_selftest():
    """`--net-selftest` in a packaged build, CI: the program must be able to open https sites the way a subscription
    download does. A packaged Python without certificates fails here (as it did on a Mac) while every unit test passes."""
    import ssl
    ok = True
    ctx = updater.ssl_context()
    print("trusted certificate authorities:", ctx.cert_store_stats().get("x509_ca"), "| python", sys.version.split()[0])
    try:  # what a program without our fix would do: only informs
        urllib.request.urlopen("https://api.github.com/zen", timeout=15, context=ssl.create_default_context()).read()
        print("plain python https: ok")
    except Exception as e:  # noqa: BLE001
        print("plain python https: FAILS (", str(e)[:100], ") - the reason a fix is needed on this system")
    def answered(fn):  # any reply, even "403 rate limit" (CI runners share addresses), proves the https connection worked
        try:
            fn()
        except urllib.error.HTTPError:
            pass

    checks = (
        ("fetch() like a subscription", lambda: answered(lambda: fetch("https://api.github.com/zen", "v2rayN/7.0"))),
        ("http.client like the ping probe", lambda: http.client.HTTPSConnection("www.gstatic.com", timeout=15).request("GET", "/generate_204")),
        ("DNS-over-HTTPS fallback", lambda: answered(lambda: updater.get_resolved("https://api.github.com/zen", {"User-Agent": "v2rayN/7.0"}, 15))),
    )
    for name, fn in checks:
        try:
            fn()
            print(name + ": ok")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(name + ": FAILED:", updater.explain(e), "|", e)
    return 0 if ok else 1


def apply_pending_update():
    """At start: if automatic updates are on and a verified newer version is waiting, install it and restart."""
    try:
        if not getattr(sys, "frozen", False):
            return False
        with open(SETTINGS, encoding="utf-8-sig") as f:
            if not json.load(f).get("auto_update"):
                return False
        info = updater.staged(UPDATE_DIR)
        return bool(info) and updater.apply_staged(info, relaunch=True)
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    sys.excepthook = log_crash
    threading.excepthook = lambda a: log_crash(a.exc_type, a.exc_value, a.exc_traceback)
    if "--swap-selftest" in sys.argv:  # packaged build, CI: replace this very file the way an update does
        sys.exit(swap_selftest(sys.argv[sys.argv.index("--swap-selftest") + 1]))
    if os.environ.get("FIMA_SWAP_MARKER") and getattr(sys, "frozen", False):  # ...and this is the copy that got started
        with open(os.environ["FIMA_SWAP_MARKER"], "w") as _f:
            _f.write(f"started {sys.executable}")
        sys.exit(0)
    if "--net-selftest" in sys.argv:  # packaged build, CI: can it open https sites at all?
        sys.exit(net_selftest())
    _wait = os.environ.pop("FIMA_WAIT_PID", "")
    if _wait.isdigit():  # we were started by a copy that is closing: wait until it is gone (single-instance lock)
        wait_for_exit(int(_wait))
    if not any(a in sys.argv for a in ("--selftest", "--tray-selftest")) and already_running():
        if not signal_running_instance():  # it did not answer: say so, in the app's style
            _r = tk.Tk()
            _r.withdraw()
            Dialog(_r, T("Приложение уже запущено, но не отвечает.\n\nЗакрой его в диспетчере задач и запусти снова."),
                   ["OK"], "error", 0, 0)
        sys.exit(0)
    if "--selftest" in sys.argv:
        outs = parse_text(sys.stdin.read())
        json.dump(build_config(outs, "AUTO", True, ["example.com"]), open(RUNCFG, "w"), indent=1)
        print(len(outs), "outbounds")
        if len(i18n.catalog("en")) < 250:  # a packaged program that lost its English texts would show Russian to everyone
            print("the English texts are missing from this build")
            sys.exit(1)
        sys.exit(0)
    if "--tray-selftest" in sys.argv:
        print(tray.selftest())
        sys.exit(0)
    if getattr(sys, "frozen", False):
        updater.cleanup(UPDATE_DIR)  # what a finished update left behind
    if apply_pending_update():
        sys.exit(0)  # the helper swaps the files after we exit and starts the new version
    try:
        app = App()
    except Exception:  # noqa: BLE001
        log_crash(*sys.exc_info())
        try:  # most likely a design setting the system cannot do: the default look, nothing else touched
            DESIGN_SAFE = True
            app = App()
            if "--autostart" in sys.argv:
                app.after(400, app.autostart_run)
            app.mainloop()
            sys.exit(0)
        except Exception:  # noqa: BLE001
            log_crash(*sys.exc_info())
        for _p in (SETTINGS, SUBCACHE, EXITFILE):  # most likely a damaged data file: keep it as .bad and start clean
            try:
                os.replace(_p, _p + ".bad")
            except OSError:
                pass
        app = App()
    if "--autostart" in sys.argv:
        app.after(400, app.autostart_run)
    app.mainloop()
