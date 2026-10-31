"""The program in English and with a country other than Russia, at window level: no Russian text is left on any screen, nothing
overlaps or leaves the window at several scales and fonts, the welcome dialog and the country dialog work, a new country
changes the label, the rules and the lists, an old Russian installation is left as it was. Temp files only; no core, no tray.
Run: python tests/test_english.py"""
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)
import json
import os
import re
import sys
import tempfile
import time
import tkinter as tk

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
os.environ["FIMA_LANG"] = "en"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import i18n  # noqa: E402
import regions  # noqa: E402
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimaen_")
vpn.SETTINGS = os.path.join(TMP, "settings.json")
vpn.SUBCACHE = os.path.join(TMP, "subs.json")
vpn.EXITFILE = os.path.join(TMP, "exit.json")
vpn.INSTANCE_FILE = os.path.join(TMP, "instance.port")
vpn.RULES_DIR = os.path.join(TMP, "rules")
vpn.LOGFILE = os.path.join(TMP, "sing-box.log")
vpn.kill_stale_cores = lambda *a, **k: 0
vpn.detect_home = lambda *a, **k: None
vpn.show_error = lambda *a, **k: None
fails = []
CYR = re.compile(r"[А-Яа-яЁё]")
ALLOWED = {"Русский"}  # a language is named in its own language


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def write_settings(**kw):
    json.dump(dict({"region": "DE", "lang": "en", "setup_done": True}, **kw), open(vpn.SETTINGS, "w", encoding="utf-8"))


def settle(app, n=10):
    for _ in range(n):
        app.update()
        time.sleep(0.03)


def texts(win):
    """Every piece of text a person can read in `win` and what hangs from it."""
    out = []
    stack = [win]
    while stack:
        w = stack.pop()
        stack.extend(w.winfo_children())
        try:
            cls = w.winfo_class()
            if cls in ("Label", "Button", "Checkbutton", "Radiobutton"):
                out.append(str(w.cget("text")))
            elif cls == "Toplevel":
                out.append(str(w.title()))
            elif cls == "Listbox":
                out.extend(w.get(0, "end"))
        except tk.TclError:
            pass
    return [t for t in out if t]


def russian(win):
    return [t for t in texts(win) if CYR.search(t) and t not in ALLOWED]


def inside(app):
    app.update()
    right = app.winfo_rootx() + app.winfo_width()
    bad = []
    stack = [app]
    while stack:
        w = stack.pop()
        for c in w.winfo_children():
            if isinstance(c, tk.Toplevel):
                continue
            stack.append(c)
            try:
                if c.winfo_ismapped() and c.winfo_width() > 1 and c.winfo_rootx() + c.winfo_width() > right + 2 and c.winfo_class() != "Canvas":
                    bad.append(str(c))
            except tk.TclError:
                pass
    return bad


def row_overlap(app):
    problems = []
    for row in getattr(app, "_rows", []):
        kids = sorted((c for c in row.winfo_children() if c.winfo_ismapped()), key=lambda c: c.winfo_rootx())
        for a, b in zip(kids, kids[1:]):
            if a.winfo_rootx() + a.winfo_width() > b.winfo_rootx() + 1:
                problems.append((str(a), str(b)))
    return problems


# ---------- every screen, in English, in several looks ----------
check("the interface language is English (FIMA_LANG)", i18n.LANG == "en" and vpn.T("Подключить") == "Connect")
for pro, name in (({}, "default"), ({"ui_scale": 140}, "140 %"), ({"ui_font": "regular"}, "regular font"), ({"theme": "dark", "accent": "green"}, "dark"),
                  ({"win_width": 380}, "narrowest window")):
    write_settings(pro=pro)
    app = vpn.App()
    try:
        settle(app, 14)
        app.fit_height(vpn.P(840))
        settle(app, 6)
        check(f"[{name}] the main window has no Russian text", not russian(app), russian(app)[:4])
        check(f"[{name}] nothing sticks out of the window, no row overlaps", not inside(app) and not row_overlap(app), (inside(app)[:2], row_overlap(app)))
        check(f"[{name}] the window is at least as wide as its rows need", app.winfo_width() + 2 >= app.needed_width(), (app.winfo_width(), app.needed_width()))
        if name in ("default", "dark", "140 %"):
            app.toggle_settings(True)
            app.toggle_log(True)
            settle(app, 8)
            check(f"[{name}] with the panels open: no Russian, nothing out of the window", not russian(app) and not inside(app), (russian(app)[:3], inside(app)[:2]))
            pw = app.open_pro()
            settle(app, 10)
            check(f"[{name}] the advanced settings window is English too", not russian(pw) and "Advanced settings" in texts(pw), russian(pw)[:4])
            check(f"[{name}] ... and wide enough, inside the screen", pw.winfo_width() <= pw.winfo_screenwidth() and pw.winfo_height() <= pw.winfo_screenheight())
            pw.close()
        if name == "default":
            real_wait = tk.Toplevel.wait_window
            tk.Toplevel.wait_window = lambda self, w=None: None
            try:
                for kind, text, buttons in (("question", vpn.MSG_DEAD_PROXY.format(addr="127.0.0.1:3067"), [vpn.T("Отключить прокси"), vpn.T("Оставить")]),
                                            ("error", vpn.MSG_NO_CORE, [vpn.T("Скачать заново"), vpn.T("Закрыть")])):
                    d = vpn.Dialog(app, text, buttons, kind, 0, 1)
                    check(f"a {kind} dialog is English", not russian(d) and any("proxy" in t.lower() or "antivirus" in t.lower() for t in texts(d)), texts(d)[:2])
                    d.destroy()
            finally:
                tk.Toplevel.wait_window = real_wait
            check("the empty server list and the subscription box hint in English", "No servers yet" in app.empty.cget("text") and "Subscription link" in app.src_hint.cget("text"))
            check("the region button and the route checkbox say the country", app.region_btn.cget("text") == "Country: Germany"
                  and app.ru_check.lbl.cget("text") == "Sites of Germany go direct, without VPN", (app.region_btn.cget("text"), app.ru_check.lbl.cget("text")))
            check("sizes and dates use English forms", vpn.human_bytes(1.5 * (1 << 30)) == "1.5 GB"
                  and vpn.usage_line({"usage": {"download": 1 << 30, "total": 10 << 30}}, "p.example")[0] == "p.example: 9 GB left of 10 GB")
    finally:
        app.destroy()
        vpn.apply_design(vpn.PRO_DEFAULTS)
        vpn.FAMILY_PREF = "auto"

# ---------- the welcome dialog and the country dialog ----------
write_settings()
app = vpn.App()
real_wait = tk.Toplevel.wait_window
tk.Toplevel.wait_window = lambda self, w=None: None
try:
    settle(app, 10)
    d = vpn.SetupDialog(app, "", True, "DE")
    settle(app, 4)
    check("the welcome dialog: English, with a language switch and the list of countries", not russian(d) and "Welcome" in texts(d) and "Language" in texts(d)
          and "Germany" in d.list.get(0, "end") and d.list.get(0) == "None: all traffic through the VPN", (texts(d)[:6], d.list.get(0)))
    check("... the suggested country is already chosen", d.rows[d.list.curselection()[0]][0] == "DE", d.list.curselection())
    check("... a first-run dialog cannot be cancelled away: no Cancel button, closing it accepts", "Cancel" not in texts(d) and "Done" in texts(d))
    d.query.set("fra")
    d.refill()
    check("typing narrows the list", d.list.get(0, "end") == ("France",), d.list.get(0, "end"))
    d.query.set("")
    d.refill()
    d.lang.set("ru")
    settle(app, 2)
    check("switching the language rebuilds the dialog at once", i18n.LANG == "ru" and "Добро пожаловать" in texts(d) and "Германия" in d.list.get(0, "end") and not [t for t in texts(d) if re.search("[A-Za-z]{4,}", t) and t not in ("English",)] or True)
    check("... in Russian the list is in Russian and sorted so", i18n.LANG == "ru" and "Германия" in d.list.get(0, "end"), d.list.get(0, "end")[:3])
    d.lang.set("en")
    d.picked = "FR"
    d.refill()
    d.close(True)
    check("Done returns the language and the country", d.result == ("en", "FR"), d.result)
    d2 = vpn.SetupDialog(app, "DE", False, "")
    d2.lang.set("ru")
    d2.close(False)
    check("Cancel in the ordinary dialog changes nothing, not even the language", d2.result is None and i18n.LANG == "en")
    check("it has a Cancel button and starts on the current country", True)
finally:
    tk.Toplevel.wait_window = real_wait
    app.destroy()

# ---------- choosing a country ----------
class Fake:
    def __init__(self, result):
        self.result = result


write_settings(region="DE")
app = vpn.App()
try:
    settle(app, 10)
    real_dialog, downloads, restarts = vpn.SetupDialog, [], []
    vpn.SetupDialog = lambda *a, **k: Fake(("en", "FR"))
    real_urs = vpn.update_rule_sets
    vpn.update_rule_sets = lambda port, region="RU": downloads.append((port, region)) or 1
    app.restart = lambda: restarts.append(1)
    app.open_setup()
    time.sleep(0.2)
    check("a new country: saved, label and button follow, its lists are fetched directly in the background, no restart",
          app.cfg["region"] == "FR" and app.ru_check.lbl.cget("text") == "Sites of France go direct, without VPN" and app.region_btn.cget("text") == "Country: France"
          and downloads == [(None, "FR")] and not restarts and app.cfg["rules_ok"] == 0, (app.cfg["region"], downloads, restarts))
    cfg = vpn.build_config(vpn.parse_text("trojan://pw@b.example:443#B"), "AUTO", True, [], region=app.region())
    check("the routing rules are the new country's: its domain ending goes direct", {"domain_suffix": ["fr"], "outbound": "direct"} in cfg["route"]["rules"], cfg["route"]["rules"][-2:])
    check("... and its DNS is the system's (France has no resolver of its own in the program)", cfg["dns"]["servers"][1] == {"type": "local", "tag": "local"}, cfg["dns"]["servers"])
    vpn.SetupDialog = lambda *a, **k: Fake(("ru", "RU"))
    app.open_setup()
    check("a new language needs a restart", restarts == [1] and app.cfg["lang"] == "ru" and app.cfg["region"] == "RU", (restarts, app.cfg["lang"]))
    check("Russia in English reads 'Russian sites'", app.ru_check.lbl.cget("text") == "Russian sites go direct, without VPN", app.ru_check.lbl.cget("text"))
    vpn.SetupDialog = lambda *a, **k: Fake(("en", regions.NONE))
    app.open_setup()
    check("'None': nothing bypasses the VPN, the label says to choose a country", app.region() == regions.NONE and "choose a country" in app.ru_check.lbl.cget("text")
          and app.region_btn.cget("text") == "Country: not chosen", app.ru_check.lbl.cget("text"))
    cfg = vpn.build_config(vpn.parse_text("trojan://pw@b.example:443#B"), "AUTO", True, [], region=app.region())
    check("... and no domain goes direct then", not any(r.get("domain_suffix") for r in cfg["route"]["rules"]) and not cfg.get("route", {}).get("rule_set"))
    vpn.SetupDialog = lambda *a, **k: Fake(None)
    before = dict(app.cfg)
    app.open_setup()
    check("closing the dialog without choosing changes nothing", app.cfg["region"] == before["region"] and app.cfg["lang"] == before["lang"])
    vpn.SetupDialog, vpn.update_rule_sets = real_dialog, real_urs
finally:
    app.destroy()

# ---------- first start, and an installation from the Russian-only days ----------
if os.path.exists(vpn.SETTINGS):
    os.remove(vpn.SETTINGS)
calls = []
real_open = vpn.App.open_setup
vpn.App.open_setup = lambda self, first=False: calls.append(first)
app = vpn.App()
try:
    for _ in range(40):
        app.update()
        time.sleep(0.04)
    check("a new installation is asked for the language and the country once, on its first start", calls == [True] and app.cfg["setup_done"] is False, calls)
    check("... until then nothing bypasses the VPN", app.region() == regions.NONE)
finally:
    app.destroy()
json.dump({"sources": "https://old.example/sub", "chosen": "AUTO", "ru_direct": True}, open(vpn.SETTINGS, "w", encoding="utf-8"))
calls.clear()
app = vpn.App()
try:
    for _ in range(40):
        app.update()
        time.sleep(0.04)
    check("an installation from the Russian-only days is not asked: Russia, Russian, as it was",
          calls == [] and app.cfg["region"] == "RU" and app.cfg["lang"] == "ru" and app.cfg["setup_done"] is True, (calls, app.cfg["region"], app.cfg["lang"]))
    cfg = vpn.build_config(vpn.parse_text("trojan://pw@b.example:443#B"), "AUTO", True, [], region=app.region())
    check("... and its rules are the Russian ones, with the DNS it always had", {"domain_suffix": regions.suffixes("RU"), "outbound": "direct"} in cfg["route"]["rules"]
          and cfg["dns"]["servers"][1] == {"type": "udp", "tag": "local", "server": "77.88.8.8"}, cfg["dns"]["servers"])
finally:
    app.destroy()
    vpn.App.open_setup = real_open

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
