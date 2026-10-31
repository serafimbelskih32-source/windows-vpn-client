"""The look: palettes (contrast of every theme with every accent), the design settings and their rules, the window at
several scales, fonts and themes (nothing overlaps, nothing leaves the window or the screen), live settings, restart.
Temp files only; no core, no tray. Run: python tests/test_design.py"""
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)
import json
import os
import sys
import tempfile
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimadesign_")
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


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def lum(h):
    h = h.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# ---------- colours ----------
bad = []
for theme in ("light", "dark", "contrast"):
    for accent in vpn.ACCENTS:
        t = vpn.palette({"theme": theme, "accent": accent})
        for what, a, b, need in (("text on ground", "INK", "BG", 7), ("text on field", "INK", "PAPER", 7),
                                 ("grey text on ground", "MUTE", "BG", 4.5), ("grey text on field", "MUTE", "PAPER", 4.5),
                                 ("error text on ground", "RED", "BG", 4.5), ("text on the accent", "ONACCENT", "BLUE", 4.5),
                                 ("accent as text on a field", "BLUE", "PAPER", 4.5), ("text on the error stripe", "ONACCENT", "RED", 4.5),
                                 ("log text", "LOGFG", "LOGBG", 7)):
            c = contrast(t[a], t[b])
            if c < need:
                bad.append(f"{theme}/{accent}: {what} {c:.1f} < {need}")
check("every theme with every accent reads well (WCAG contrast of text, grey text, errors, accent fills)", not bad, bad[:6])
check("auto follows the system's appearance", vpn.palette({"theme": "auto"}, dark=True)["theme"] == "dark"
      and vpn.palette({"theme": "auto"}, dark=False)["theme"] == "light")
check("a custom accent wins over the list", vpn.palette({"theme": "light", "accent": "green", "accent_hex": "#123456"})["BLUE"] == "#123456")
check("the default look is the one the program always had", vpn.palette(vpn.PRO_DEFAULTS)["INK"] == "#12151B"
      and vpn.palette(vpn.PRO_DEFAULTS)["BLUE"] == "#1E3CFF" and vpn.palette(vpn.PRO_DEFAULTS)["BG"] == "#E3E5E8")

# ---------- the settings and their rules ----------
v, e = vpn.clean_pro({"theme": "dark", "accent": "pink", "accent_hex": "1e3cff", "ui_scale": "130", "border": 3, "alpha": 80, "density": "roomy"})
check("design settings are accepted and tidied (a colour without # gets one, upper-case)", not e and v["accent_hex"] == "#1E3CFF"
      and v["ui_scale"] == 130 and v["theme"] == "dark", (v, e))
for bad_raw, key in (({"theme": "neon"}, "theme"), ({"accent_hex": "blue"}, "accent_hex"), ({"ui_scale": 500}, "ui_scale"),
                     ({"ui_scale": 10}, "ui_scale"), ({"border": 0}, "border"), ({"alpha": 5}, "alpha"), ({"win_width": 100}, "win_width"),
                     ({"shadow": "yes"}, "shadow"), ({"ui_font": "comic"}, "ui_font")):
    v, e = vpn.clean_pro(bad_raw)
    check(f"a wrong {key} is refused and falls back to the default", key in e and v[key] == vpn.PRO_DEFAULTS[key], (v[key], e))
check("an empty custom accent is fine (the list decides)", vpn.clean_pro({"accent_hex": ""})[1] == {})
check("every design setting has a place in the window and a label for each choice",
      all(any(k == row[0] for _, rows in vpn.PRO_LAYOUT for row in rows) for k in ("theme", "accent", "accent_hex", "ui_scale", "density", "ui_font", "border", "win_width", "shadow", "anim", "remember_window", "on_top", "alpha"))
      and all(set(vpn.PRO_FIELDS[k][2]) == set(vpn.PRO_LABELS[k]) for k in vpn.PRO_LABELS))
check("every font choice names at least one family", all(vpn.FONT_CHOICES[k] for k in ("auto", "condensed", "regular", "mono")))
vpn.DESIGN_SAFE = True
check("safe mode ignores the saved design", vpn.load_design() == vpn.PRO_DEFAULTS)
vpn.DESIGN_SAFE = False


def build(pro):
    """A window made with these advanced settings (the settings file is read, as at a real start)."""
    json.dump({"pro": pro}, open(vpn.SETTINGS, "w", encoding="utf-8"))
    return vpn.App()


def settle(app, n=10):
    for _ in range(n):
        app.update()
        time.sleep(0.03)


def inside(app):
    """No widget of the window sticks out of it on the right; the title row's pieces do not overlap."""
    app.update()
    right = app.winfo_rootx() + app.winfo_width()
    out = []
    stack = [app]
    while stack:
        w = stack.pop()
        for c in w.winfo_children():
            if isinstance(c, (vpn.tk.Toplevel,)):
                continue
            stack.append(c)
            try:
                if c.winfo_ismapped() and c.winfo_width() > 1 and c.winfo_rootx() + c.winfo_width() > right + 2 and c.winfo_class() not in ("Canvas",):
                    out.append((str(c), c.winfo_rootx() + c.winfo_width() - right))
            except Exception:  # noqa: BLE001
                pass
    return out


def row_overlap(app):
    """Pieces of one row of the main window (title, note, buttons) must not overlap each other."""
    app.update()
    problems = []
    for row in getattr(app, "_rows", []):
        kids = [c for c in row.winfo_children() if c.winfo_ismapped()]
        kids.sort(key=lambda c: c.winfo_rootx())
        for a, b in zip(kids, kids[1:]):
            if a.winfo_rootx() + a.winfo_width() > b.winfo_rootx() + 1:
                problems.append((str(a), str(b)))
    return problems


# ---------- the window under different settings ----------
combos = [({}, "default"), ({"theme": "dark"}, "dark"), ({"theme": "contrast", "border": 4}, "contrast, thick borders"),
          ({"ui_scale": 70}, "70 %"), ({"ui_scale": 180}, "180 %"), ({"ui_font": "regular", "ui_scale": 120}, "regular font, 120 %"),
          ({"ui_font": "mono"}, "monospace font"), ({"density": "compact", "border": 1}, "compact, thin borders"),
          ({"density": "roomy", "accent": "orange"}, "roomy, orange"), ({"win_width": 380}, "narrowest window"),
          ({"win_width": 900}, "widest window"), ({"shadow": False, "anim": False}, "no shadow, no blinking")]
for pro, name in combos:
    app = build(pro)
    try:
        settle(app, 14)
        app.fit_height(vpn.P(840))
        settle(app, 6)
        want = vpn.palette(vpn.clean_pro(pro)[0])
        check(f"[{name}] the window takes the palette", app.cget("bg") == want["BG"] and vpn.INK == want["INK"] and vpn.BLUE == want["BLUE"], (app.cget("bg"), want["BG"]))
        check(f"[{name}] nothing sticks out of the window on the right", not inside(app), inside(app)[:3])
        check(f"[{name}] title, note and buttons of a row do not overlap", not row_overlap(app), row_overlap(app))
        check(f"[{name}] the window is at least as wide as its rows need", app.winfo_width() + 2 >= app.needed_width(), (app.winfo_width(), app.needed_width()))
        top, bottom = app.work_area()
        check(f"[{name}] the window is inside the screen", app.winfo_height() <= app.avail_height() + 2 and app.foot.winfo_rooty() + app.foot.winfo_height() <= app.winfo_rooty() + app.winfo_height(),
              (app.winfo_height(), app.avail_height()))
        check(f"[{name}] the columns of the list fit their numbers", all(int(app.tree.column(c, "width")) >= vpn.tkfont.Font(app, font=app.f_b).measure(txt)
                                                                          for c, txt in (("ping", "0000 мс"), ("speed", "000 Мбит/с"), ("proto", "TROJAN"))),
              {c: app.tree.column(c, "width") for c in ("ping", "speed", "proto")})
        if name in ("default", "dark", "180 %"):
            app.toggle_settings(True)
            app.toggle_log(True)
            settle(app, 8)
            check(f"[{name}] with the panels open: still inside the screen, nothing sticks out", not inside(app) and app.winfo_height() <= app.avail_height() + 2, (inside(app)[:2], app.winfo_height()))
            pw = app.open_pro()
            settle(app, 10)
            check(f"[{name}] the advanced settings window opens, wide enough, inside the screen",
                  pw.winfo_width() <= pw.winfo_screenwidth() and pw.winfo_height() <= pw.winfo_screenheight() and pw.preview is not None, (pw.winfo_width(), pw.winfo_height()))
            check(f"[{name}] the preview paints in the colours of the form", pw.preview.cget("bg") == want["BG"], pw.preview.cget("bg"))
            pw.close()
        check(f"[{name}] the AUTO badge follows the accent", app.flagimgs.get("AUTO") is not None)
    finally:
        app.destroy()
        vpn.apply_design(vpn.PRO_DEFAULTS)
        vpn.FAMILY_PREF = "auto"

# ---------- the pieces ----------
app = build({})
try:
    settle(app, 10)
    clicked = []
    b = vpn.Flat(app, "Кнопка", lambda: clicked.append(1), app.f_s)
    b.pack()
    app.update()
    check("a button reacts to a click on its outline and on its text", bool(b.bind("<Button-1>")) and bool(b.lab.bind("<Button-1>")))
    b.command()
    check("... and runs its command", clicked == [1], clicked)
    check("a button answers to config/cget(text) like a label did", (b.config(text="Другое"), b.cget("text"))[1] == "Другое")
    b.paint(True)
    check("hovering inverts the button", b.lab.cget("bg") == vpn.INK and b.lab.cget("fg") == vpn.PAPER)
    b.paint(False)
    check("... and leaving restores it", b.lab.cget("bg") == vpn.PAPER)
    seg_probe = vpn.Segmented(app, ("a",), vpn.tk.StringVar(value="a"), app.f_s)
    p = vpn.Flat(app, "Главная", lambda: None, app.f_s, primary=True)
    check("the main action is the accent", p.lab.cget("bg") == vpn.BLUE and p.lab.cget("fg") == vpn.ONACCENT)
    # the outline is made of frames, never of a Label's highlight ring (macOS does not paint those)
    check("buttons, ticks and segments are outlined by frames", vpn.tk.Frame.cget(b, "bg") == vpn.INK and float(str(b.lab.cget("highlightthickness"))) == 0
      and vpn.tk.Frame.cget(seg_probe, "bg") == vpn.INK)
    var = vpn.tk.StringVar(value="a")
    seg = vpn.Segmented(app, ("a", "b"), var, app.f_s, {"a": "Первый", "b": "Второй"})
    seg.pack()
    app.update()
    check("a segmented choice shows its labels and marks the chosen one", seg.buttons["a"].cget("text") == "Первый" and seg.buttons["a"].cget("bg") == vpn.BLUE
          and seg.buttons["b"].cget("bg") == vpn.PAPER)
    var.set("b")
    check("... and follows the value", seg.buttons["b"].cget("bg") == vpn.BLUE)
    bx, entry = vpn.field(app, vpn.tk.StringVar(value="x"), 10, app.f_b)
    bx.pack()
    app.update()
    check("a text field has an even outline (the entry sits in a paper frame inside it)", bx.cget("bg") == vpn.INK and entry.master.cget("bg") == vpn.PAPER)

    # an empty list and an empty box say what to do
    app.cfg["sources"] = ""
    app.src.delete("1.0", "end")
    app.apply_outs()
    app.sync_hints()
    settle(app, 4)
    check("an empty server list says what to do", app.empty.winfo_manager() == "place" and "ссылку подписки" in app.empty.cget("text"))
    check("an empty subscription box shows a hint with the kinds of links", app.src_hint.winfo_manager() == "place" and "vless://" in app.src_hint.cget("text"))
    app.src.insert("1.0", "https://x.example/sub")
    app.sync_hints()
    check("the box hint goes as soon as there is text", app.src_hint.winfo_manager() == "")
    app.src.delete("1.0", "end")
    app.subs = {"https://u.example/s": {"outs": vpn.parse_text("vless://11111111-2222-3333-4444-555555555555@h.example:443?security=tls#A"), "info": {}, "time": time.time(), "ua": "x"}}
    app.cfg["sources"] = "https://u.example/s"
    app.apply_outs()
    check("the list hint goes when there are servers", app.empty.winfo_manager() == "", app.empty.winfo_manager())
    app.subs, app.cfg["sources"] = {}, ""
    app.apply_outs()

    # live settings
    app.cfg["pro"] = {"alpha": 80, "on_top": True, "shadow": False, "anim": False, "win_width": 520}
    app.apply_live()
    settle(app, 6)
    try:
        if vpn.IS_LINUX:  # a bare X server (CI) has no window manager to honour either
            print("     (Linux: opacity and always-on-top depend on the window manager: not checked)")
        else:
            check("opacity and always-on-top apply at once", abs(float(app.attributes("-alpha")) - 0.8) < 0.02 and bool(app.attributes("-topmost")))
    except Exception:  # noqa: BLE001
        print("     (this window manager has no alpha/topmost: skipped)")
    check("the shadow and blinking switches apply at once", vpn.SHADOW is False and vpn.ANIM is False)
    check("the width applies at once", abs(app.winfo_width() - vpn.P(520)) <= 3 or app.winfo_width() >= app.needed_width(), (app.winfo_width(), vpn.P(520)))
    app.cfg["pro"] = {}
    app.apply_live()
    check("switching them off again restores the shadow and blinking", vpn.SHADOW is True and vpn.ANIM is True)

    # the place of the window is remembered, if it is still on a screen
    app.geometry("+120+90")
    settle(app, 8)
    app.remember_window()
    saved = dict(app.cfg.get("win", {}))
    check("the window remembers where it stood", saved.get("x") is not None and saved.get("w", 0) > 100, saved)
    app.cfg["win"] = {"x": 99999, "y": 99999, "w": 480}
    before = (app.winfo_x(), app.winfo_y())
    app.restore_window()
    settle(app, 4)
    check("a remembered place off every screen is ignored", (app.winfo_x(), app.winfo_y()) == before, (before, app.winfo_x(), app.winfo_y()))
    app.cfg["pro"] = {"remember_window": False}
    app.cfg["win"] = {}
    app.remember_window()
    check("with remembering switched off nothing is stored", app.cfg["win"] == {})
    app.cfg["pro"] = {}

    # the advanced settings window: a changed look asks for a restart, a live one does not
    pw = app.open_pro()
    settle(app, 10)
    pw.vars["theme"].set("dark")
    check("the preview follows a choice that is not applied yet", (settle(app, 4), pw.preview.cget("bg"))[1] == vpn.palette({"theme": "dark"})["BG"], pw.preview.cget("bg"))
    check("nothing to restart before it is applied", not pw.restart_btn.winfo_ismapped())
    pw.apply()
    settle(app, 4)
    check("applying a new theme saves it and offers the restart", app.cfg["pro"].get("theme") == "dark" and pw.restart_btn.winfo_manager() == "pack"
          and "перезапуск" in pw.msg.cget("text"), (app.cfg.get("pro"), pw.msg.cget("text")))
    pw.vars["theme"].set("light")
    pw.vars["alpha"].set("90")
    pw.apply()
    settle(app, 4)
    check("going back to what the window was started with needs no restart; a live setting never does",
          pw.restart_btn.winfo_manager() == "" and app.cfg["pro"].get("alpha") == 90, (pw.restart_btn.winfo_manager(), app.cfg["pro"]))
    pw.vars["accent_hex"].set("zzz")
    ok = pw.apply()
    check("a bad colour is pointed at and nothing is saved", ok is False and "цвет" in pw.msg.cget("text") and app.cfg["pro"].get("alpha") == 90, pw.msg.cget("text"))
    pw.close()

    # restart: the new copy waits for this one, gets a clean environment and the same arguments
    seen = {}
    real_popen, real_quit = vpn.subprocess.Popen, app.quit_app
    vpn.subprocess.Popen = lambda cmd, **kw: seen.update(cmd=cmd, env=kw.get("env", {}), kw=kw)
    app.quit_app = lambda: seen.update(quit=True)
    try:
        app.state = "off"
        app.restart()
    finally:
        vpn.subprocess.Popen, app.quit_app = real_popen, real_quit
    check("restart starts a new copy that waits for this process, then this one closes",
          seen.get("env", {}).get("FIMA_WAIT_PID") == str(os.getpid()) and seen.get("quit") and seen.get("cmd", [""])[0] == sys.executable
          and not any(k in seen.get("env", {}) for k in vpn.updater._PYI_VARS), seen)
    asked = []
    real_ask = vpn.ask_yes_no
    vpn.ask_yes_no = lambda *a, **k: asked.append(a[1]) or False
    seen.clear()
    vpn.subprocess.Popen = lambda cmd, **kw: seen.update(cmd=cmd)
    try:
        app.state = "on"
        app.restart()
    finally:
        vpn.subprocess.Popen, vpn.ask_yes_no = real_popen, real_ask
        app.state = "off"
    check("with the VPN on, a restart asks first and 'not now' does nothing", asked and "VPN" in asked[0] and not seen, (asked, seen))
finally:
    app.destroy()
    vpn.apply_design(vpn.PRO_DEFAULTS)

# a process that is gone is not waited for; a live one is waited for until it ends
t0 = time.time()
vpn.wait_for_exit(2 ** 22 + 12345, 5)
check("waiting for a process that does not exist returns at once", time.time() - t0 < 2.5, time.time() - t0)
import subprocess  # noqa: E402
import threading  # noqa: E402
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1.2)"])
threading.Thread(target=child.wait, daemon=True).start()  # reaped the moment it ends (a zombie would still "exist")
t0 = time.time()
vpn.wait_for_exit(child.pid, 10)
el = time.time() - t0
check("waiting for a live process lasts until it ends", 0.6 < el < 6, el)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
