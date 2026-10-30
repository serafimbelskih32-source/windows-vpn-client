"""FimaVPN - Windows VPN client on top of sing-box (TUN, system-wide).

Paste a subscription URL or share links (vless/vmess/trojan/ss/hysteria2/tuic),
pick a server, press Connect. Needs admin rights (TUN adapter); the exe asks for it.
"""
import base64
import ctypes
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import font as tkfont
import urllib.request
from tkinter import messagebox, ttk
from urllib.parse import parse_qs, unquote, urlparse, urlsplit
import http.client

APP = "FimaVPN"  # settings folder name only
TITLE = "VPN"
DATA = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP)
SETTINGS = os.path.join(DATA, "settings.json")
RUNCFG = os.path.join(DATA, "run.json")
LOGFILE = os.path.join(DATA, "sing-box.log")
TESTCFG = os.path.join(DATA, "test.json")
TESTLOG = os.path.join(DATA, "test.log")
SUBCACHE = os.path.join(DATA, "subs.json")
RULES_DIR = os.path.join(DATA, "rules")
os.makedirs(DATA, exist_ok=True)

BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
CORE_DIR = os.path.join(BASE, "core")
CORE = os.path.join(CORE_DIR, "sing-box.exe")
NOWIN = 0x08000000  # CREATE_NO_WINDOW
MIXED_PORT = 2080

RU_SUFFIXES = ["ru", "su", "xn--p1ai", "yandex.net", "yastatic.net", "vk.com", "userapi.com",
               "vkuser.net", "mail.ru", "ok.ru", "sberbank.ru", "tinkoff.ru", "gosuslugi.ru"]

# RU lists for "Russian sites direct". Copies bundled in core/ are the fallback; fresher ones are
# downloaded weekly through the tunnel into RULES_DIR and win while they are valid.
RULE_SETS = {
    "geosite-ru": ("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
                   "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs"),
    "geoip-ru": ("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
                 "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs"),
}
RULES_EVERY = 7 * 24 * 3600
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
    """Tie a child process to our lifetime (see make_job)."""
    global _JOB
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


def update_rule_sets(port):
    """Download fresh RU lists through the local proxy, i.e. through the VPN. Returns how many updated."""
    os.makedirs(RULES_DIR, exist_ok=True)
    done = 0
    for tag, urls in RULE_SETS.items():
        for url in urls:
            try:
                with _opener(port).open(url, timeout=30) as r:
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


# ---------- link parsing ----------
def b64d(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def _tls(q, host, default_sec="none"):
    sec = q.get("security", [default_sec])[0]
    if sec not in ("tls", "reality"):
        return None
    t = {"enabled": True, "server_name": q.get("sni", q.get("peer", [host]))[0] or host}
    if q.get("allowInsecure", ["0"])[0] in ("1", "true") or q.get("insecure", ["0"])[0] in ("1", "true"):
        t["insecure"] = True
    if q.get("alpn", [""])[0]:
        t["alpn"] = q["alpn"][0].split(",")
    fp = q.get("fp", [""])[0]
    if fp or sec == "reality":
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    if sec == "reality":
        t["reality"] = {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}
    return t


def _transport(q):
    typ = q.get("type", ["tcp"])[0]
    if typ == "ws":
        t = {"type": "ws", "path": unquote(q.get("path", ["/"])[0])}
        if q.get("host", [""])[0]:
            t["headers"] = {"Host": q["host"][0]}
        return t
    if typ == "grpc":
        return {"type": "grpc", "service_name": unquote(q.get("serviceName", [""])[0])}
    if typ in ("http", "h2"):
        return {"type": "http", "path": unquote(q.get("path", ["/"])[0]),
                "host": [q["host"][0]] if q.get("host", [""])[0] else []}
    if typ == "httpupgrade":
        return {"type": "httpupgrade", "path": unquote(q.get("path", ["/"])[0]), "host": q.get("host", [""])[0]}
    return None


def parse_link(link: str):
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    name = unquote(link.split("#", 1)[1]) if "#" in link else ""
    try:
        if scheme == "vmess":
            j = json.loads(b64d(link[8:].split("#")[0]))
            o = {"type": "vmess", "tag": j.get("ps") or name, "server": j["add"], "server_port": int(j["port"]),
                 "uuid": j["id"], "security": j.get("scy", "auto"), "alter_id": int(j.get("aid", 0) or 0)}
            q = {"security": ["tls" if j.get("tls") == "tls" else "none"], "sni": [j.get("sni") or j.get("host") or j["add"]],
                 "type": [j.get("net", "tcp")], "path": [j.get("path", "/")], "host": [j.get("host", "")],
                 "serviceName": [j.get("path", "")], "fp": [j.get("fp", "")], "alpn": [j.get("alpn", "")]}
            t = _tls(q, j["add"])
            if t:
                o["tls"] = t
            tr = _transport(q)
            if tr:
                o["transport"] = tr
            return o
        if scheme == "ss":
            body = link[5:].split("#")[0]
            plugin = None
            if "?" in body:
                body, qs = body.split("?", 1)
                plugin = parse_qs(qs).get("plugin", [None])[0]
            if "@" not in body:
                body = b64d(body)
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = b64d(userinfo)
            method, pw = userinfo.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            o = {"type": "shadowsocks", "tag": name, "server": host.strip("[]"), "server_port": int(port),
                 "method": unquote(method), "password": unquote(pw)}
            if plugin:
                p = unquote(plugin).split(";")
                o["plugin"] = p[0]
                o["plugin_opts"] = ";".join(p[1:])
            return o
        u = urlparse(link)
        q = parse_qs(u.query)
        host, port = u.hostname, u.port or 443
        if scheme == "vless":
            o = {"type": "vless", "tag": name, "server": host, "server_port": port, "uuid": unquote(u.username or ""),
                 "packet_encoding": "xudp"}
            if q.get("flow", [""])[0]:
                o["flow"] = q["flow"][0]
            t = _tls(q, host)
            if t:
                o["tls"] = t
            tr = _transport(q)
            if tr:
                o["transport"] = tr
            return o
        if scheme == "trojan":
            o = {"type": "trojan", "tag": name, "server": host, "server_port": port, "password": unquote(u.username or "")}
            o["tls"] = _tls(q, host, "tls") or {"enabled": True, "server_name": host}
            tr = _transport(q)
            if tr:
                o["transport"] = tr
            return o
        if scheme in ("hysteria2", "hy2"):
            o = {"type": "hysteria2", "tag": name, "server": host, "server_port": port,
                 "password": unquote(u.username or ""),
                 "tls": {"enabled": True, "server_name": q.get("sni", [host])[0],
                         "insecure": q.get("insecure", ["0"])[0] in ("1", "true")}}
            if q.get("obfs", [""])[0]:
                o["obfs"] = {"type": q["obfs"][0], "password": q.get("obfs-password", [""])[0]}
            return o
        if scheme == "tuic":
            o = {"type": "tuic", "tag": name, "server": host, "server_port": port, "uuid": unquote(u.username or ""),
                 "password": unquote(u.password or ""), "congestion_control": q.get("congestion_control", ["bbr"])[0],
                 "tls": {"enabled": True, "server_name": q.get("sni", [host])[0],
                         "insecure": q.get("allow_insecure", ["0"])[0] in ("1", "true"),
                         "alpn": q.get("alpn", ["h3"])[0].split(",")}}
            return o
    except Exception:
        return None
    return None


def parse_text(text: str):
    """Return list of sing-box outbounds from a blob: links, base64 of links, or a sing-box json."""
    text = text.strip()
    if text.startswith("{"):
        try:
            j = json.loads(text)
            skip = {"direct", "block", "dns", "selector", "urltest"}
            return [o for o in j.get("outbounds", []) if o.get("type") not in skip]
        except Exception:
            return []
    if "://" not in text.split("\n")[0]:
        try:
            text = b64d("".join(text.split()))
        except Exception:
            pass
    outs = []
    for line in re.split(r"[\r\n]+", text):
        o = parse_link(line)
        if o:
            outs.append(o)
    seen = {}
    for i, o in enumerate(outs):
        t = o.get("tag") or f"{o['type']}-{o.get('server', '?')}:{o.get('server_port', '')}"
        if t in ("proxy", "direct", "AUTO"):
            t += " (node)"
        if t in seen:
            seen[t] += 1
            t = f"{t} ({seen[t]})"
        else:
            seen[t] = 1
        o["tag"] = t
    return outs


UAS = ("v2rayN/7.0", "sing-box/1.13")
REFRESH_DEFAULT_H = 12  # when the provider does not send profile-update-interval


def fetch(url: str, ua: str):
    """Returns (body, headers with lower-case names)."""
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace"), {k.lower(): v for k, v in r.headers.items()}


def split_sources(src: str):
    """Subscription URLs and inline share links from the sources box."""
    urls, inline = [], []
    for line in src.splitlines():
        line = line.strip()
        if line:
            (urls if line.lower().startswith(("http://", "https://")) else inline).append(line)
    return urls, inline


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


def fetch_source(url, prefer=None):
    """Fetch one subscription, trying the UA that worked last time first. Returns (outs, info, ua, errors)."""
    errors = []
    for ua in sorted(UAS, key=lambda u: u != prefer):
        try:
            body, headers = fetch(url, ua)
        except Exception as e:
            errors.append(f"{url[:50]}: {e}")
            continue
        outs = parse_text(body)
        if outs:
            return outs, sub_info(headers), ua, []
    return [], {}, None, errors or [f"{url[:50]}: в ответе нет серверов"]


def merge_outs(groups):
    """Concatenate outbound lists with unique tags, leaving the cached originals untouched."""
    seen, res = set(), []
    for group in groups:
        for o in group:
            o = dict(o)
            while o["tag"] in seen:
                o["tag"] += "*"
            seen.add(o["tag"])
            res.append(o)
    return res


# ---------- config build ----------
def build_config(outs, chosen, ru_direct, extra_direct):
    tags = [o["tag"] for o in outs]
    proxy_out = {"type": "selector", "tag": "proxy", "outbounds": tags, "default": chosen if chosen in tags else tags[0]}
    if chosen == "AUTO" and len(tags) > 1:
        proxy_out = {"type": "urltest", "tag": "proxy", "outbounds": tags, "url": "https://www.gstatic.com/generate_204",
                     "interval": "3m"}
    domains = list(extra_direct)
    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    rule_sets = []
    if ru_direct:
        rules.append({"domain_suffix": RU_SUFFIXES, "outbound": "direct"})
        for tag in ("geosite-ru", "geoip-ru"):
            path = rule_path(tag)
            if path:
                rules.append({"rule_set": [tag], "outbound": "direct"})
                rule_sets.append({"tag": tag, "type": "local", "format": "binary", "path": path})
    if domains:
        rules.insert(3, {"domain_suffix": domains, "outbound": "direct"})
    dns_rules = []
    if ru_direct:
        dns_rules.append({"domain_suffix": RU_SUFFIXES, "server": "local"})
        if any(rs["tag"] == "geosite-ru" for rs in rule_sets):
            dns_rules.append({"rule_set": ["geosite-ru"], "server": "local"})
    if domains:
        dns_rules.append({"domain_suffix": domains, "server": "local"})
    # proxy server hostnames must resolve via local dns (not through the tunnel)
    srv = sorted({o["server"] for o in outs if not re.match(r"^[\d.:]+$", o["server"])})
    if srv:
        dns_rules.insert(0, {"domain": srv, "server": "local"})
    cfg = {
        "log": {"level": "info", "timestamp": True, "output": LOGFILE},
        "dns": {"servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
                            {"type": "udp", "tag": "local", "server": "77.88.8.8"}],
                "rules": dns_rules, "final": "remote", "strategy": "ipv4_only"},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": TUN_NAME, "address": ["172.19.0.1/30"], "auto_route": True,
             "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": MIXED_PORT},
        ],
        "outbounds": outs + [proxy_out, {"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "rule_set": rule_sets, "final": "proxy", "auto_detect_interface": True,
                  "default_domain_resolver": "local"},
    }
    if not rule_sets:
        del cfg["route"]["rule_set"]
    return cfg


# ---------- GUI ----------
INK = "#12151B"
PAPER = "#F6F7F8"
BG = "#E3E5E8"
BLUE = "#1E3CFF"
MUTE = "#555C67"
RED = "#C8102E"
WHITE = "#FFFFFF"
S = 1.0  # dpi scale, set once the root window exists


def P(n):
    return max(1, int(round(n * S)))


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def karing_running():
    try:
        out = subprocess.run(["tasklist"], capture_output=True, text=True, creationflags=NOWIN).stdout.lower()
        return any(n in out for n in ("karing.exe", "karingservice.exe", "v2rayn.exe", "hiddify.exe", "nekoray.exe"))
    except Exception:
        return False


def enable_clipboard(w):
    """Ctrl+C/V/X/A and a right-click menu that work on ANY keyboard layout (Tk binds by keysym,
    so on the Russian layout Ctrl+V does nothing by default)."""
    def on_key(e):
        if e.keycode == 86:
            w.event_generate("<<Paste>>")
        elif e.keycode == 67:
            w.event_generate("<<Copy>>")
        elif e.keycode == 88:
            w.event_generate("<<Cut>>")
        elif e.keycode == 65:
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
    menu.add_command(label="Вставить", command=lambda: w.event_generate("<<Paste>>"))
    menu.add_command(label="Копировать", command=lambda: w.event_generate("<<Copy>>"))
    menu.add_command(label="Вырезать", command=lambda: w.event_generate("<<Cut>>"))
    menu.add_separator()
    menu.add_command(label="Выделить всё", command=select_all)

    def popup(e):
        w.focus_set()
        menu.tk_popup(e.x_root, e.y_root)
    w.bind("<Control-KeyPress>", on_key)
    w.bind("<Button-3>", popup)


class Flat(tk.Label):
    """Hard-edged text button: ink outline, inverts on hover and keyboard focus."""
    def __init__(self, master, text, command, font):
        super().__init__(master, text=text, font=font, bg=PAPER, fg=INK, padx=P(12), pady=P(4), cursor="hand2",
                         highlightthickness=P(2), highlightbackground=INK, highlightcolor=INK, takefocus=1)
        self.command = command
        for ev, bg, fg in (("<Enter>", INK, PAPER), ("<Leave>", PAPER, INK),
                           ("<FocusIn>", INK, PAPER), ("<FocusOut>", PAPER, INK)):
            self.bind(ev, lambda e, bg=bg, fg=fg: self.config(bg=bg, fg=fg))
        self.bind("<Button-1>", lambda e: self.command())
        self.bind("<space>", lambda e: self.command())
        self.bind("<Return>", lambda e: self.command())


class Check(tk.Frame):
    def __init__(self, master, text, var, font):
        super().__init__(master, bg=BG, cursor="hand2", takefocus=1, highlightthickness=P(2),
                         highlightbackground=BG, highlightcolor=BLUE)
        self.var = var
        self.box = tk.Label(self, width=2, font=font, highlightthickness=P(2), highlightbackground=INK, bd=0)
        self.box.pack(side="left")
        self.lbl = tk.Label(self, text=text, font=font, bg=BG, fg=INK)
        self.lbl.pack(side="left", padx=P(10))
        for w in (self, self.box, self.lbl):
            w.bind("<Button-1>", self.toggle)
        self.bind("<space>", self.toggle)
        var.trace_add("write", lambda *a: self.paint())
        self.paint()

    def toggle(self, e=None):
        self.var.set(not self.var.get())

    def paint(self):
        on = self.var.get()
        self.box.config(text="✓" if on else "", bg=BLUE if on else PAPER, fg=WHITE)


class Power(tk.Canvas):
    """The one loud element: a slab with a hard shadow that presses in, fills blue when connected."""
    def __init__(self, master, command, fam):
        self.H = P(132)
        super().__init__(master, height=self.H, bg=BG, highlightthickness=0, cursor="hand2", takefocus=1)
        self.command = command
        self.fam = fam
        self.state, self.server, self.clock = "off", "", ""
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

    def set(self, state, server, clock, blink=True):
        if (state, server, clock, blink) != (self.state, self.server, self.clock, self.blink):
            self.state, self.server, self.clock, self.blink = state, server, clock, blink
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
        w, h, o = self.winfo_width(), self.H, P(9)
        d = o if self.pressed else 0
        x1, y1 = w - o + d, h - o + d
        self.create_rectangle(o, o, w, h, fill=INK, outline=INK)
        on = self.state == "on"
        fill = BLUE if on else PAPER
        fg = WHITE if on else INK
        sub = "#C9D1FF" if on else MUTE
        self.create_rectangle(d + 2, d + 2, x1, y1, fill=fill, outline=INK, width=P(3))
        title = {"off": "Подключить", "connecting": "Подключаю", "on": "Отключить"}[self.state]
        if self.state == "connecting":
            title += " █" if self.blink else ""
        self.create_text(d + P(24), d + P(40), text=title, anchor="w", fill=fg, font=(self.fam, int(24 * S) if S > 1 else 24, "bold"))
        if self.clock:
            self.create_text(x1 - P(22), d + P(40), text=self.clock, anchor="e", fill=fg, font=("Consolas", 16, "bold"))
        name = self.server if len(self.server) <= 40 else self.server[:39] + "…"
        self.create_text(d + P(24), y1 - P(30), text=name, anchor="w", fill=sub, font=(self.fam, 11))
        if self.focused:
            self.create_rectangle(d + P(10), d + P(10), x1 - P(8), y1 - P(8), outline=fg, dash=(3, 3))


PROTO = {"shadowsocks": "SS", "hysteria2": "HY2", "vless": "VLESS", "vmess": "VMESS", "trojan": "TROJAN", "tuic": "TUIC"}

# ---------- speed test ----------
TEST_BASE_PORT = 21080
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
TOP_FOR_SPEED = 8


TUN_NAME = "FimaTUN"


def build_test_config(outs, nic=None):
    """One local mixed inbound per server, each pinned to its server. No TUN, no admin needed.
    `nic` = physical adapter name: bind outbound sockets to it so the test bypasses a running VPN."""
    inbounds = [{"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1", "listen_port": TEST_BASE_PORT + i}
                for i in range(len(outs))]
    rules = [{"inbound": [f"in{i}"], "outbound": o["tag"]} for i, o in enumerate(outs)]
    cfg = {"log": {"level": "warn", "output": TESTLOG},
           "dns": {"servers": [{"type": "udp", "tag": "local", "server": "77.88.8.8"}], "strategy": "ipv4_only"},
           "inbounds": inbounds, "outbounds": outs + [{"type": "direct", "tag": "direct"}],
           "route": {"rules": rules, "final": "direct", "default_domain_resolver": "local"}}
    if nic:
        cfg["route"]["default_interface"] = nic
    return cfg


def physical_nic():
    """Name of the real network adapter (lowest-metric IPv4 default route that is not our TUN), or None."""
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
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | "
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
    return "" if ms is None else ("нет" if ms < 0 else f"{ms:.0f} мс")


def fmt_speed(v):
    """None = not tested yet, negative = tested but no download source answered."""
    return "" if v is None else ("—" if v < 0 else (f"{v:.0f} Мбит/с" if v >= 10 else f"{v:.1f} Мбит/с"))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        global S
        S = max(1.0, float(self.tk.call("tk", "scaling")) / 1.3333)
        def on_error(*a):
            log_crash(*a)
            messagebox.showerror(TITLE, "Ошибка: " + str(a[1]) + "\nПодробности: %APPDATA%\\FimaVPN\\crash.log")
        self.report_callback_exception = on_error
        self.title(TITLE)
        try:
            self.iconbitmap(os.path.join(BASE, "icon.ico"))
        except Exception:
            pass
        self.configure(bg=BG)
        self.geometry(f"{P(480)}x{P(800)}")
        self.minsize(P(440), P(720))
        fams = set(tkfont.families())
        fam = next((f for f in ("Bahnschrift SemiCondensed", "Bahnschrift", "Segoe UI") if f in fams), "Segoe UI")
        self.fam = fam
        self.f_h, self.f_b, self.f_s = (fam, 12, "bold"), (fam, 11), (fam, 10)
        self.proc = None
        self.test_proc = None
        self.testing = False
        self.test_stop = threading.Event()
        self.results = {}
        self.outs = []
        self.subs = {}  # url -> last good fetch {"outs", "info", "time", "ua"}; cached on disk
        self.sub_fail = {}  # url -> time of the last failed fetch
        self.inline = []  # outbounds from share links pasted directly
        self.loading = False
        self.reload_pending = False
        self.rules_busy = False
        self.uiq = queue.Queue()  # callables from worker threads, run by pump() on the Tk thread
        self._pick = None  # row the app selected itself (see on_select)
        self._pump_id = self._tick_id = None
        self.state = "off"
        self.active = ""
        self.t0 = 0.0
        self.blink = True
        self.n = 0
        self._pos = 0
        self.cfg = {"sources": "", "chosen": "AUTO", "ru_direct": True, "extra": "", "rules_ok": 0, "rules_try": 0}
        try:
            self.cfg.update(json.load(open(SETTINGS, encoding="utf-8-sig")))
        except Exception:
            pass
        try:
            self.subs = json.load(open(SUBCACHE, encoding="utf-8"))
        except Exception:
            pass

        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("T.Treeview", background=PAPER, fieldbackground=PAPER, foreground=INK, borderwidth=0,
                     rowheight=P(30), font=self.f_b)
        st.map("T.Treeview", background=[("selected", INK)], foreground=[("selected", WHITE)])
        st.layout("T.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.layout("Flat.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "ns"})])
        st.configure("Flat.Vertical.TScrollbar", background=INK, troughcolor=PAPER, borderwidth=0, width=P(10))

        side = P(22)
        root = tk.Frame(self, bg=BG)
        root.pack(fill="both", expand=True, padx=side, pady=(P(18), P(16)))

        if not is_admin():
            tk.Label(root, text="Нужны права администратора", font=self.f_s, bg=RED, fg=WHITE,
                     padx=P(8), pady=P(4)).pack(fill="x", pady=(0, P(12)))

        self.power = Power(root, self.toggle, fam)
        self.power.pack(fill="x")
        self.status = tk.Label(root, text="", font=self.f_s, bg=BG, fg=MUTE, anchor="w", justify="left",
                               wraplength=P(430))
        self.status.pack(fill="x", pady=(P(6), 0))

        # servers
        row = self.section(root, "Серверы")
        self.count = tk.Label(row, text="", font=self.f_s, bg=BG, fg=MUTE)
        self.count.pack(side="right", padx=(P(10), 0))
        self.test_btn = Flat(row, "Тест скорости", self.run_test, self.f_s)
        self.test_btn.pack(side="right")
        frame = tk.Frame(root, bg=INK, padx=P(2), pady=P(2))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, style="T.Treeview", columns=("name", "ping", "speed", "proto"), show="",
                                 selectmode="browse", height=6)
        self.tree.column("name", anchor="w", stretch=True, width=P(150))
        self.tree.column("ping", anchor="e", width=P(58), stretch=False)
        self.tree.column("speed", anchor="e", width=P(88), stretch=False)
        self.tree.column("proto", anchor="e", width=P(62), stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", style="Flat.Vertical.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda e: self.toggle() if self.state == "off" else None)

        # routing
        self.section(root, "Маршрут")
        self.ru = tk.BooleanVar(value=self.cfg["ru_direct"])
        Check(root, "Российские сайты напрямую, без VPN", self.ru, self.f_b).pack(anchor="w")
        tk.Label(root, text="Свои домены напрямую, через пробел", font=self.f_s, bg=BG, fg=MUTE,
                 anchor="w").pack(fill="x", pady=(P(10), P(4)))
        eb = tk.Frame(root, bg=INK, padx=P(2), pady=P(2))
        eb.pack(fill="x")
        inner = tk.Frame(eb, bg=PAPER)
        inner.pack(fill="x")
        self.extra = tk.Entry(inner, font=self.f_b, bg=PAPER, fg=INK, relief="flat", bd=0, highlightthickness=0,
                              insertbackground=INK, selectbackground=BLUE, selectforeground=WHITE)
        self.extra.pack(fill="x", ipady=P(5), padx=P(6))
        self.extra.insert(0, self.cfg["extra"])

        # subscriptions
        row = self.section(root, "Подписки")
        Flat(row, "Обновить", self.load, self.f_s).pack(side="right")
        Flat(row, "Вставить", self.paste_clip, self.f_s).pack(side="right", padx=(0, P(8)))
        self.sub_note = tk.Label(row, text="", font=self.f_s, bg=BG, fg=MUTE)
        self.sub_note.pack(side="left", padx=(P(10), 0))
        sbx = tk.Frame(root, bg=INK, padx=P(2), pady=P(2))
        sbx.pack(fill="x")
        self.src = tk.Text(sbx, height=3, wrap="char", font=("Consolas", 9), bg=PAPER, fg=INK, relief="flat", bd=0,
                           highlightthickness=0, insertbackground=INK, selectbackground=BLUE,
                           selectforeground=WHITE, padx=P(6), pady=P(5))
        self.src.pack(fill="x")
        self.src.insert("1.0", self.cfg["sources"])

        # log (folded)
        self.log_open = False
        self.log_head = tk.Label(root, text="▸ Лог", font=self.f_h, bg=BG, fg=INK, cursor="hand2", anchor="w")
        self.log_head.pack(fill="x", pady=(P(16), P(4)))
        self.log_head.bind("<Button-1>", lambda e: self.toggle_log())
        self.log_box = tk.Frame(root, bg=INK, padx=P(2), pady=P(2))
        self.log = tk.Text(self.log_box, height=8, state="disabled", bg=INK, fg="#C9CED6", font=("Consolas", 9),
                           relief="flat", bd=0, highlightthickness=0, selectbackground=BLUE, padx=P(6), pady=P(5))
        self.log.pack(fill="both", expand=True)

        for w in (self.src, self.extra, self.log):
            enable_clipboard(w)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh_power()
        self.show_cached()
        self.clean_done = threading.Event()

        def clean():
            try:
                n = kill_stale_cores({p.pid for p in (self.proc, self.test_proc) if p})
                if n:
                    self._ui(lambda: self.say("Закрыл зависшее ядро VPN от прошлого запуска."))
            finally:
                self.clean_done.set()
        threading.Thread(target=clean, daemon=True).start()
        self._pump_id = self.after(50, self.pump)
        self.after(300, self.refresh_due)
        self._tick_id = self.after(500, self.tick)

    # ----- small helpers -----
    def section(self, parent, title):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(P(18), P(6)))
        tk.Label(row, text=title, font=self.f_h, bg=BG, fg=INK).pack(side="left")
        return row

    def toggle_log(self, force=None):
        self.log_open = (not self.log_open) if force is None else force
        self.log_head.config(text=("▾ Лог" if self.log_open else "▸ Лог"))
        if self.log_open:
            self.log_box.pack(fill="x")
            self.geometry("")
        else:
            self.log_box.pack_forget()

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
        return "Быстрейший из списка" if sel[0] == "auto" else self.outs[int(sel[0])]["tag"]

    def refresh_power(self):
        clock = ""
        if self.state == "on":
            s = int(time.time() - self.t0)
            clock = f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
        name = self.active if self.state != "off" else self.sel_name()
        self.power.set(self.state, name, clock, self.blink)

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
            return messagebox.showinfo(TITLE, "Буфер обмена пуст.")
        cur = self.src.get("1.0", "end").strip()
        self.src.delete("1.0", "end")
        self.src.insert("1.0", (cur + "\n" if cur else "") + txt.strip())
        self.load()

    def show_cached(self):
        """Show the servers saved from the last good fetch right away, before touching the network."""
        urls, inline = split_sources(self.cfg["sources"])
        self.subs = {u: s for u, s in self.subs.items() if u in urls and s.get("outs")}
        self.inline = [o for line in inline for o in parse_text(line)]
        if self.subs or self.inline:
            self.apply_outs()

    def load(self, silent=False, only=None):
        """Fetch subscriptions in the background: all of them (button, paste) or just `only` (timer)."""
        manual = only is None
        if self.testing:
            if manual:
                self.say("Идёт тест скорости. Дождись конца или остановь его.", err=True)
            return
        if self.loading:
            self.reload_pending = self.reload_pending or manual
            return
        if manual:
            self.cfg["sources"] = self.src.get("1.0", "end").strip()
            self.count.config(text="Загрузка…")
        urls, inline = split_sources(self.cfg["sources"])
        targets = urls if manual else [u for u in only if u in urls]
        prefer = {u: self.subs.get(u, {}).get("ua") for u in targets}
        self.loading = True
        self.sub_note.config(text="обновляю…")

        def work():
            got = {u: fetch_source(u, prefer[u]) for u in targets}
            inline_outs = [o for line in inline for o in parse_text(line)]
            self._ui(lambda: self.loaded(got, inline_outs, urls, manual, silent))
        threading.Thread(target=work, daemon=True).start()

    def loaded(self, got, inline_outs, urls, manual, silent):
        self.loading = False
        now = time.time()
        errors, changed = [], manual
        for u, (outs, info, ua, errs) in got.items():
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
            self.count.config(text="Пусто")
            self.say("Серверов нет. Проверь ссылку или ключ.", err=True)
            if manual and not silent:
                messagebox.showerror(TITLE, "Не удалось получить серверы.\n" +
                                     ("\n".join(errors) if errors else "Проверь ссылку или ключ."))
            return
        if manual:
            self.say("Не все подписки обновились, показаны сохранённые серверы." if errors else "", err=bool(errors))
        if len(outs) > 1:
            self.tree.insert("", "end", iid="auto", values=("Быстрейший из списка", "", "", "AUTO"))
        for i, o in enumerate(outs):
            ping, speed = self.results.get(o["tag"], (None, None))
            self.tree.insert("", "end", iid=str(i), values=(o["tag"], fmt_ping(ping), fmt_speed(speed),
                                                            PROTO.get(o["type"], o["type"].upper())))
        if self.results:
            self.sort_rows()
        pick = next((str(i) for i, o in enumerate(outs) if o["tag"] == keep), None)
        pick = pick or ("auto" if len(outs) > 1 else "0")
        self.select(pick)
        if first or manual:
            self.tree.see(pick)
        else:
            self.tree.yview_moveto(top)
        self.count.config(text=str(len(outs)))
        self.save(sources=manual)

    def note_subs(self):
        """'обновлено в 14:05' = when the least fresh subscription was last fetched successfully."""
        times = [s.get("time", 0) for s in self.subs.values()]
        if not times:
            return self.sub_note.config(text="")
        t = time.localtime(min(times))
        today = time.strftime("%d.%m") == time.strftime("%d.%m", t)
        self.sub_note.config(text=time.strftime("обновлено в %H:%M" if today else "обновлено %d.%m", t))

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
        if (self.rules_busy or self.state != "on" or not self.ru.get() or now - self.t0 < 20
                or now - self.cfg.get("rules_ok", 0) < RULES_EVERY
                or now - self.cfg.get("rules_try", 0) < RULES_RETRY):
            return
        self.rules_busy = True
        self.cfg["rules_try"] = now

        def work():
            try:
                n = update_rule_sets(MIXED_PORT)
            except Exception:
                n = 0
            self._ui(lambda: self.rules_done(n))
        threading.Thread(target=work, daemon=True).start()

    def rules_done(self, n):
        self.rules_busy = False
        if n == len(RULE_SETS):
            self.cfg["rules_ok"] = time.time()
            self.say("Списки российских сайтов обновлены.")
        self.save(sources=False)

    # ----- speed test -----
    def run_test(self):
        if self.testing:
            self.test_stop.set()
            return self.test_btn.config(text="Останавливаю…")
        if not self.outs:
            return self.say("Сначала добавь подписку и нажми «Обновить».", err=True)
        self.testing = True
        self.test_stop.clear()
        self.test_btn.config(text="Остановить")
        self.say("Другой VPN-клиент включён, замеры могут быть неточными." if karing_running() else "")
        threading.Thread(target=self._test_worker, args=(list(self.outs),), daemon=True).start()

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
            self._pump_id = self.after(50, self.pump)

    def on_select(self, e=None):
        """Remember the server the user picked. Selections the app makes itself (self._pick) do not count,
        so a temporarily shorter list never overwrites the saved choice."""
        sel = self.tree.selection()
        if sel and sel[0] != self._pick:
            self._pick = sel[0]
            self.cfg["chosen"] = self.chosen()
        self.refresh_power()

    def select(self, iid):
        self._pick = iid
        self.tree.selection_set(iid)

    def _cell(self, i, ping=None, speed=None):
        tag = self.outs[i]["tag"] if i < len(self.outs) else None
        if tag is None:
            return
        p, s = self.results.get(tag, (None, None))
        self.results[tag] = (ping if ping is not None else p, speed if speed is not None else s)
        p, s = self.results[tag]
        if self.tree.exists(str(i)):
            self.tree.set(str(i), "ping", fmt_ping(p))
            self.tree.set(str(i), "speed", fmt_speed(s))

    def _test_worker(self, outs):
        err = None
        try:
            # Always measure around any tunnel (ours, a leftover core, Karing...), not through it: sockets are bound
            # to the real adapter. Without a VPN this changes nothing, so no need to guess whether one is up.
            nic = physical_nic()
            if not nic and self.state != "off":
                raise RuntimeError("не нашёл сетевой адаптер для замера мимо VPN")
            outs = resolve_servers(outs)
            write_json(TESTCFG, build_test_config(outs, nic))
            open(TESTLOG, "w").close()
            chk = subprocess.run([CORE, "check", "-c", TESTCFG], capture_output=True, text=True, creationflags=NOWIN)
            if chk.returncode != 0:
                raise RuntimeError("конфиг не прошёл проверку: " + (chk.stderr or chk.stdout).strip()[-200:])
            self.test_proc = subprocess.Popen([CORE, "run", "-c", TESTCFG], cwd=DATA, creationflags=NOWIN,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            own(self.test_proc)
            last = TEST_BASE_PORT + len(outs) - 1
            deadline = time.time() + 10
            while True:
                if self.test_proc.poll() is not None:
                    raise RuntimeError("ядро не запустилось")
                try:
                    socket.create_connection(("127.0.0.1", last), 0.3).close()
                    break
                except OSError:
                    if time.time() > deadline:
                        raise RuntimeError("ядро не отвечает")
                    time.sleep(0.2)

            pings = {}
            done = 0
            with ThreadPoolExecutor(8) as ex:
                futs = {ex.submit(lambda i=i: None if self.test_stop.is_set() else probe_ping(TEST_BASE_PORT + i)): i
                        for i in range(len(outs))}
                for f in as_completed(futs):
                    i = futs[f]
                    ms = f.result()
                    done += 1
                    if ms is None and self.test_stop.is_set():
                        continue  # skipped after Stop, leave the row untested
                    pings[i] = ms
                    shown = -1 if ms is None else ms
                    self._ui(lambda i=i, shown=shown, d=done: (self._cell(i, ping=shown),
                                                               self.count.config(text=f"Пинг {d}/{len(outs)}")))
            top = sorted((i for i, ms in pings.items() if ms is not None), key=lambda i: pings[i])[:TOP_FOR_SPEED]
            urls = list(SPEED_URLS)  # one source for the whole run so servers are compared on equal terms
            self.speed_host = ""
            for n, i in enumerate(top, 1):
                if self.test_stop.is_set():
                    break
                self._ui(lambda n=n, t=len(top): self.count.config(text=f"Скорость {n}/{t}"))
                sp, used = probe_speed(TEST_BASE_PORT + i, urls=urls)
                if used:
                    urls.remove(used)
                    urls.insert(0, used)
                    self.speed_host = urlsplit(used).hostname or ""
                if sp is None and self.test_stop.is_set():
                    break
                self._ui(lambda i=i, sp=(-1 if sp is None else sp): self._cell(i, speed=sp))
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
            self._ui(lambda: self.test_done(err))

    def test_done(self, err):
        self.testing = False
        self.test_btn.config(text="Тест скорости")
        self.count.config(text=str(len(self.outs)))
        if err:
            return self.say("Тест не удался: " + err, err=True)
        def res(i):
            return self.results.get(self.outs[i]["tag"], (None, None))

        alive = [i for i in range(len(self.outs)) if res(i)[0] is not None and res(i)[0] >= 0]
        if not alive:
            return self.say("Ни один сервер не ответил." if any(res(i)[0] is not None for i in range(len(self.outs)))
                            else "Тест остановлен до первых результатов.", err=True)
        with_speed = [i for i in alive if res(i)[1] is not None and res(i)[1] >= 0]
        best = max(with_speed, key=lambda i: res(i)[1]) if with_speed else min(alive, key=lambda i: res(i)[0])

        self.sort_rows()
        self.cfg["chosen"] = self.outs[best]["tag"]
        self.select(str(best))
        self.tree.see(str(best))
        p, sp = res(best)
        what = f"{fmt_speed(sp)}, {fmt_ping(p)}" if sp is not None and sp >= 0 else fmt_ping(p)
        if with_speed:
            skipped = sum(1 for i in alive if res(i)[1] is not None and res(i)[1] < 0)
            if skipped:
                what += f"; у {skipped} серверов скорость не замерилась"
        src = f" Скорость измерена загрузкой с {self.speed_host}." if getattr(self, "speed_host", "") else ""
        self.say(f"Выбран самый быстрый: {self.outs[best]['tag']} ({what}).{src}")

    def sort_rows(self):
        """Measured speed (desc), then ping (asc), unreachable and untested last; "auto" stays on top."""
        def key(i):
            p, sp = self.results.get(self.outs[i]["tag"], (None, None))
            ok = p is not None and p >= 0
            fast = sp is not None and sp >= 0
            return (not ok, not fast, -(sp if fast else 0), p if ok else 0)
        start = 1 if self.tree.exists("auto") else 0
        for pos, i in enumerate(sorted(range(len(self.outs)), key=key)):
            self.tree.move(str(i), "", pos + start)

    # ----- connection -----
    def toggle(self):
        if self.proc and self.proc.poll() is None:
            return self.stop()
        if not is_admin():
            self.say("Запусти приложение от имени администратора: без этого не создать сетевой адаптер.", err=True)
            return messagebox.showerror(TITLE, "Запусти приложение от имени администратора (нужно для TUN).")
        if not self.outs:
            return self.say("Сначала добавь подписку и нажми «Обновить».", err=True)
        if self.testing:
            return self.say("Идёт тест скорости. Дождись конца или остановь его.", err=True)
        self.clean_done.wait(8)  # leftover cores from a previous run are being closed
        self.save()
        if karing_running() and not messagebox.askyesno(
                TITLE, "Запущен другой VPN-клиент (Karing / v2rayN / Hiddify / NekoRay).\n"
                     "Два VPN сразу конфликтуют. Отключи его и нажми «Да», либо «Нет» для отмены."):
            return
        cfg = build_config(self.outs, self.chosen(), self.ru.get(), self.extra.get().split())
        json.dump(cfg, open(RUNCFG, "w", encoding="utf-8"), indent=1)
        open(LOGFILE, "w").close()
        self._pos = 0
        chk = subprocess.run([CORE, "check", "-c", RUNCFG], capture_output=True, text=True, creationflags=NOWIN)
        if chk.returncode != 0:
            self.toggle_log(True)
            self.say("Конфиг не прошёл проверку, подробности в логе.", err=True)
            return messagebox.showerror(TITLE, "Ошибка конфига:\n" + (chk.stderr or chk.stdout)[-800:])
        self.proc = subprocess.Popen([CORE, "run", "-c", RUNCFG], cwd=DATA, creationflags=NOWIN,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        own(self.proc)
        self.active = self.sel_name()
        self.state = "connecting"
        self.say("")
        self.refresh_power()
        self.after(2500, self.check_alive)

    def check_alive(self):
        if self.state != "connecting":
            return
        if self.proc and self.proc.poll() is None:
            self.state = "on"
            self.t0 = time.time()
            self.refresh_power()
        else:
            self.fail()

    def fail(self):
        self.stop()
        self.say("Ядро остановилось, подробности в логе.", err=True)
        self.toggle_log(True)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        self.proc = None
        self.state = "off"
        self.active = ""
        self.refresh_power()

    def tick(self):
        self.n += 1
        self.blink = not self.blink
        if self.state in ("on", "connecting"):
            self.refresh_power()
        if self.n % 2 == 0:
            self.tail()
        if self.n % 120 == 0:  # every minute
            self.refresh_due()
            self.update_rules_due()
        if self.proc and self.proc.poll() is not None and self.state != "off":
            self.fail()
        self._tick_id = self.after(500, self.tick)

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

    def on_close(self):
        self.save()
        self.test_stop.set()
        p = self.test_proc
        if p and p.poll() is None:
            p.kill()
        self.stop()
        self.destroy()

    def destroy(self):
        for aid in (self._pump_id, self._tick_id):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        super().destroy()


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    sys.excepthook = log_crash
    threading.excepthook = lambda a: log_crash(a.exc_type, a.exc_value, a.exc_traceback)
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\FimaVPN-single-instance")
    if ctypes.windll.kernel32.GetLastError() == 183 and "--selftest" not in sys.argv:  # ERROR_ALREADY_EXISTS
        ctypes.windll.user32.MessageBoxW(0, "Приложение уже запущено.", TITLE, 0x40)
        sys.exit(0)
    if "--selftest" in sys.argv:
        outs = parse_text(sys.stdin.read())
        json.dump(build_config(outs, "AUTO", True, ["example.com"]), open(RUNCFG, "w"), indent=1)
        print(len(outs), "outbounds")
        sys.exit(0)
    App().mainloop()
