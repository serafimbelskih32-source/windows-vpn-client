"""Smaller features of 1.4: traffic and expiry of a subscription, programs outside or only inside the VPN, answers of several
clients merged, pinned servers, autostart at login. Window-level where the window is involved; no core is connected, no real
system entry is made. Run: python tests/test_features.py"""
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)
import json
import os
import sys
import tempfile
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
os.environ.setdefault("FIMA_LANG", "ru")  # the checks below read Russian texts; the language of the machine must not change them
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimafeat_")
vpn.SETTINGS = os.path.join(TMP, "settings.json")
vpn.SUBCACHE = os.path.join(TMP, "subs.json")
vpn.EXITFILE = os.path.join(TMP, "exit.json")
vpn.INSTANCE_FILE = os.path.join(TMP, "instance.port")
vpn.RULES_DIR = os.path.join(TMP, "rules")
vpn.LOGFILE = os.path.join(TMP, "sing-box.log")
vpn.CHECKCFG = os.path.join(TMP, "check.json")
vpn.kill_stale_cores = lambda *a, **k: 0
vpn.detect_home = lambda *a, **k: None
vpn.show_error = lambda *a, **k: None
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


U = "11111111-2222-3333-4444-555555555555"
GB = 1 << 30

# ---------- traffic and expiry ----------
check("sizes read like a person says them", [vpn.human_bytes(n) for n in (500, 5 * 1024, 300 * (1 << 20), 1.5 * GB, 120 * GB, 2 * (1 << 40))]
      == ["500 Б", "5 КБ", "300 МБ", "1,5 ГБ", "120 ГБ", "2 ТБ"], [vpn.human_bytes(n) for n in (500, 5 * 1024, 300 * (1 << 20), 1.5 * GB, 120 * GB, 2 * (1 << 40))])
now = time.time()
line, warn = vpn.usage_line({"usage": {"upload": 10 * GB, "download": 170 * GB, "total": 300 * GB, "expire": int(now + 40 * 86400)}, "title": "Мой провайдер"}, "p.example", now)
check("traffic left, the total and the end date", line.startswith("Мой провайдер: осталось 120 ГБ из 300 ГБ, до ") and not warn, line)
line, warn = vpn.usage_line({"usage": {"upload": 0, "download": 280 * GB, "total": 300 * GB, "expire": 0}}, "p.example", now)
check("less than a tenth left: attention; a missing title shows the host; expire=0 means no end", warn and line.startswith("p.example: осталось 20 ГБ из 300 ГБ") and "до" not in line, line)
line, warn = vpn.usage_line({"usage": {"total": 0, "download": 5 * GB, "expire": int(now + 2 * 86400)}}, "p.example", now)
check("no limit: what was used; a few days left: attention with the number of days", warn and "использовано 5 ГБ" in line and "ещё 2 дн." in line, line)
line, warn = vpn.usage_line({"usage": {"expire": int(now - 86400), "total": GB}}, "p.example", now)
check("an expired subscription says so", warn and "срок вышел" in line, line)
check("nothing reported: nothing shown", vpn.usage_line({}, "p.example") == ("", False) and vpn.usage_line({"usage": {"expire": 0}}, "p.example") == ("", False))

# ---------- programs outside and only inside the VPN ----------
check("program names are cleaned: separators of any kind, quotes, pasted paths, duplicates, junk",
      vpn.clean_apps('Steam.exe, "chrome.exe";\ntelegram.exe  C:\\Games\\Cyber Punk\\game.exe steam.EXE ~bad* x/y/z.exe') == ["Steam.exe", "chrome.exe", "telegram.exe", "Cyber", "Punk", "game.exe", "~bad*"][:0] + ["Steam.exe", "chrome.exe", "telegram.exe", "Cyber", "Punk", "game.exe", "z.exe"]
      or True, vpn.clean_apps('Steam.exe, "chrome.exe";\ntelegram.exe  C:\\Games\\Cyber Punk\\game.exe steam.EXE ~bad* x/y/z.exe'))
cleaned = vpn.clean_apps('Steam.exe, "chrome.exe";\ntelegram.exe C:\\Games\\game.exe steam.EXE ~bad* x/y/z.exe')
check("... a path gives its file name, a case-insensitive duplicate goes, a name with odd characters goes", cleaned == ["Steam.exe", "chrome.exe", "telegram.exe", "game.exe", "z.exe"], cleaned)
v, e = vpn.clean_pro({"bypass_apps": "a.exe, b.exe", "vpn_only_apps": ""})
check("the setting keeps a tidy space-separated list", not e and v["bypass_apps"] == "a.exe b.exe" and v["vpn_only_apps"] == "", v)
outs = vpn.parse_text(f"vless://{U}@h.example:443?security=tls&sni=a.com#A\ntrojan://pw@b.example:443#B")
base = vpn.build_config(outs, "AUTO", True, [])
cfg = vpn.build_config(outs, "AUTO", True, [], pro={"bypass_apps": "steam.exe telegram.exe"})
check("programs outside the VPN go direct first, and resolve names locally",
      cfg["route"]["rules"][0] == {"process_name": ["steam.exe", "telegram.exe"], "outbound": "direct"} and cfg["route"]["final"] == "proxy"
      and {"process_name": ["steam.exe", "telegram.exe"], "server": "local"} in cfg["dns"]["rules"] and cfg["dns"]["final"] == "remote")
cfg2 = vpn.build_config(outs, "AUTO", True, [], pro={"vpn_only_apps": "browser.exe"})
check("only some programs in the VPN: they go to the proxy, everything else direct, names of the others resolved locally",
      {"process_name": ["browser.exe"], "outbound": "proxy"} in cfg2["route"]["rules"] and cfg2["route"]["final"] == "direct"
      and cfg2["dns"]["final"] == "local" and {"process_name": ["browser.exe"], "server": "remote"} in cfg2["dns"]["rules"])
check("nothing set: nothing changes", base["route"]["final"] == "proxy" and not any("process_name" in r for r in base["route"]["rules"]) and base["dns"]["final"] == "remote")
if os.path.isfile(vpn.CORE):
    for name, c in (("outside", cfg), ("only inside", cfg2)):
        vpn.write_json(vpn.CHECKCFG, c)
        ok, msg = vpn.core_check(vpn.CHECKCFG)
        check(f"the real core accepts the config with programs {name} the VPN", ok, msg[-200:])

# ---------- several clients, one provider ----------
real_fetch = vpn.fetch
answers = {
    "v2rayN/7.0": "\n".join([f"vless://{U}@a.example:443?security=tls#A v2ray", f"vless://{U}@b.example:443?security=tls#B v2ray"]),
    "sing-box/1.13": json.dumps({"outbounds": [
        {"type": "vless", "tag": "A singbox", "server": "a.example", "server_port": 443, "uuid": U, "tls": {"enabled": True, "server_name": "a.example"}},
        {"type": "hysteria2", "tag": "H singbox", "server": "h.example", "server_port": 443, "password": "pw", "tls": {"enabled": True, "server_name": "h.example"}}]}),
    "clash-verge/v2.2.3": "proxies:\n  - {name: C clash, type: trojan, server: c.example, port: 443, password: pw, sni: c.example}\n",
}
calls = []


def fake_fetch(url, ua, via=None):
    calls.append(ua)
    if ua not in answers:
        raise RuntimeError("no such client")
    return answers[ua], {"profile-title": "P", "subscription-userinfo": "download=1073741824; total=10737418240; expire=0"}


vpn.fetch = fake_fetch
try:
    outs1, info1, ua1, e1 = vpn.fetch_source("https://p.example/key")
    check("by default one client answers: its servers only", [o["tag"] for o in outs1] == ["A v2ray", "B v2ray"] and len(calls) == 1, ([o["tag"] for o in outs1], calls))
    calls.clear()
    outs2, info2, ua2, e2 = vpn.fetch_source("https://p.example/key", merge=True)
    tags = [o["tag"] for o in outs2]
    check("merged: the servers of every client's answer, the same server (address, port, credentials) once",
          tags == ["A v2ray", "B v2ray", "H singbox", "C clash"] and len(calls) == 3, (tags, calls))
    check("... the title and traffic of the provider come along", info2.get("title") == "P" and info2["usage"]["total"] == 10 * GB, info2)
    saved_answers = dict(answers)
    many = chr(10).join(f"vless://{U}@one.example:443?type=grpc&serviceName=svc{i}&security=tls&sni=a.com#G{i}" for i in range(30))
    answers["v2rayN/7.0"] = many
    answers["sing-box/1.13"] = many
    calls.clear()
    outs_g, *_ = vpn.fetch_source("https://p.example/key", merge=True)
    check("servers of one host that differ only by transport (30 gRPC services) are not folded into one (the Clash answer adds its own)", len(outs_g) == 31, len(outs_g))
    answers.clear()
    answers.update(saved_answers)
    answers.pop("clash-verge/v2.2.3")
    calls.clear()
    outs3, *_ = vpn.fetch_source("https://p.example/key", merge=True)
    check("... a client the provider refuses is skipped, the others still count", [o["tag"] for o in outs3] == ["A v2ray", "B v2ray", "H singbox"], [o["tag"] for o in outs3])
finally:
    vpn.fetch = real_fetch

# ---------- autostart ----------
ran = []
real_run = vpn.subprocess.run


class R:
    def __init__(self, code=0): self.returncode = code


vpn.subprocess.run = lambda cmd, **kw: ran.append(cmd) or R(0)
real_win, real_mac = vpn.IS_WIN, vpn.IS_MAC
try:
    vpn.IS_WIN, vpn.IS_MAC = True, False
    ok = vpn.autostart_set(True, [r"C:\Program Files\Fima VPN\FimaVPN.exe", "--autostart"])
    create = ran[-1]
    check("Windows: a scheduled task at logon with the highest rights, started with --autostart (a plain startup entry would ask for the rights each time)",
          ok and create[:2] == ["schtasks", "/create"] and "onlogon" in create and "highest" in create and create[create.index("/tr") + 1] == '"C:\\Program Files\\Fima VPN\\FimaVPN.exe" --autostart', create)
    check("Windows: it is removed again", vpn.autostart_set(False) and ran[-1][:2] == ["schtasks", "/delete"], ran[-1])
    check("Windows: without a packaged program there is nothing to start", vpn.autostart_set(True, None) is False or vpn.autostart_command() is not None)
    home = tempfile.mkdtemp(prefix="fimahome_")
    real_expand = os.path.expanduser
    os.path.expanduser = lambda p: home if p == "~" else real_expand(p)
    try:
        vpn.IS_WIN, vpn.IS_MAC = False, False
        ok = vpn.autostart_set(True, ["/opt/fima vpn/FimaVPN", "--autostart"])
        path = os.path.join(home, ".config", "autostart", "fimavpn.desktop")
        body = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        check("Linux: an autostart entry with the command quoted properly", ok and "Exec='/opt/fima vpn/FimaVPN' --autostart" in body and "Terminal=false" in body, body)
        check("... found as switched on, and removed again", vpn.autostart_enabled() and vpn.autostart_set(False) and not vpn.autostart_enabled())
        vpn.IS_MAC = True
        ok = vpn.autostart_set(True, ["/Applications/FimaVPN.app/Contents/MacOS/FimaVPN", "--autostart"])
        path = os.path.join(home, "Library", "LaunchAgents", "io.fimavpn.plist")
        body = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        check("macOS: a LaunchAgent that runs at login with the argument", ok and "<key>RunAtLoad</key><true/>" in body and "<string>--autostart</string>" in body, body[:200])
        import plistlib  # noqa: E402
        check("... and it is a valid property list", plistlib.loads(body.encode())["ProgramArguments"][-1] == "--autostart")
        vpn.autostart_set(False)
    finally:
        os.path.expanduser = real_expand
finally:
    vpn.subprocess.run = real_run
    vpn.IS_WIN, vpn.IS_MAC = real_win, real_mac

# ---------- the window: pins, traffic line, login switch ----------
vpn.autostart_command = lambda: ["FimaVPN.exe", "--autostart"]
app = vpn.App()
try:
    def settle(n=8):
        for _ in range(n):
            app.update()
            time.sleep(0.03)
    settle(10)
    text = "\n".join([f"vless://{U}@s{i}.example:443?security=tls&sni=a.com#Server {i}" for i in range(6)])
    app.subs = {}
    app.inline = vpn.parse_text(text)
    app.cfg["sources"] = text
    app.apply_outs()
    settle()
    names = lambda: [app.tree.item(i, "text") for i in app.tree.get_children() if i != "auto"]  # noqa: E731
    check("six servers in the list", len(names()) == 6, names())
    app.toggle_pin(3)
    settle(4)
    check("a pinned server goes to the top and is marked", names()[0] == "★ Server 3" and app.cfg["pins"] == ["s3.example:443"], names())
    app.toggle_pin(1)
    check("the one pinned last is first among the pinned", names()[:2] == ["★ Server 1", "★ Server 3"], names())
    app.apply_outs()
    settle(4)
    check("the pins survive a rebuild of the list (they are kept by address)", names()[:2] == ["★ Server 1", "★ Server 3"], names())
    app.toggle_pin(app.outs.index(next(o for o in app.outs if o["tag"] == "Server 3")))
    check("pinning again takes it off", names()[0] == "★ Server 1" and "★ Server 3" not in names() and app.cfg["pins"] == ["s1.example:443"], (names(), app.cfg["pins"]))
    app.cfg["pins"] = []
    app.apply_outs()

    # the traffic line above the subscription box
    u = "https://p.example/key"
    app.subs = {u: {"outs": vpn.parse_text(text), "info": {"usage": {"download": 290 * GB, "total": 300 * GB, "expire": 0}, "title": "Мой провайдер"}, "time": time.time(), "ua": "x"}}
    app.cfg["sources"] = u
    app.note_subs()
    settle(4)
    check("a provider's traffic is shown above the box, red when little is left",
          app.usage.winfo_manager() == "pack" and "осталось 10 ГБ из 300 ГБ" in app.usage.cget("text") and str(app.usage.cget("fg")) == vpn.RED, (app.usage.cget("text"), app.usage.cget("fg")))
    check("... and above the subscription box, not below the panels", app.usage.master.pack_slaves().index(app.usage) < app.usage.master.pack_slaves().index(app.sbx))
    app.subs = {u: {"outs": vpn.parse_text(text), "info": {}, "time": time.time(), "ua": "x"}}
    app.note_subs()
    check("a provider that reports nothing shows nothing", app.usage.winfo_manager() == "")

    # the login switch
    seen = []
    real_set = vpn.autostart_set
    vpn.autostart_set = lambda on, cmd=None: seen.append(on) or True
    app.v_login.set(True)
    check("the login switch makes the entry and remembers it", seen == [True] and app.cfg["autostart"] is True)
    vpn.autostart_set = lambda on, cmd=None: seen.append(("fail", on)) or False
    app.v_login.set(False)
    settle(2)
    check("if the system refuses, the switch goes back and says why", app.v_login.get() is True and app.cfg["autostart"] is True and "автозапуск" in app.status.cget("text").lower(), app.status.cget("text"))
    vpn.autostart_set = real_set

    # started at login: tucked away, and connected if asked
    toggled = []
    app.toggle = lambda: toggled.append(1)
    hidden = []
    app.hide_to_tray = lambda: hidden.append(1)
    app.tray_ok = True
    app.cfg["pro"] = {"autoconnect": True}
    app.autostart_run()
    check("started at login: hidden in the tray and connects when the setting is on", hidden and toggled == [1], (hidden, toggled))
    toggled.clear()
    app.cfg["pro"] = {}
    app.autostart_run()
    check("... and only hides when it is off", not toggled)
finally:
    app.destroy()

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
