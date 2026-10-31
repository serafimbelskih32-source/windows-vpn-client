"""Pictures of every window of the program in its main states, for looking at the design on a given system.
Nothing real is touched: temp settings, no core, no tray. Needs a screen (Windows, macOS, Linux under xvfb) and Pillow.
Run: python tests/shots.py <folder> [scale=1.0] [screen_height] [name=value ...]   (extra name=value pairs are advanced
settings, e.g. theme=dark accent=green)"""
import faulthandler; faulthandler.dump_traceback_later(240, exit=True)  # a hang must end the run, not the build
import os
import sys
import tempfile
import time
import tkinter as tk

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vpn  # noqa: E402

out_dir = sys.argv[1] if len(sys.argv) > 1 else "shots"
scale = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
screen_h = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 0
extra = dict(a.split("=", 1) for a in sys.argv[3:] if "=" in a)
os.makedirs(out_dir, exist_ok=True)

TMP = tempfile.mkdtemp(prefix="fimashots_")
vpn.SETTINGS = os.path.join(TMP, "settings.json")
vpn.SUBCACHE = os.path.join(TMP, "subs.json")
vpn.EXITFILE = os.path.join(TMP, "exit.json")
vpn.INSTANCE_FILE = os.path.join(TMP, "instance.port")
vpn.RULES_DIR = os.path.join(TMP, "rules")
vpn.LOGFILE = os.path.join(TMP, "sing-box.log")
vpn.kill_stale_cores = lambda *a, **k: 0  # never touch a real running core
vpn.detect_home = lambda *a, **k: None
if extra:
    import json
    pro = {k: (v if not v.isdigit() else int(v)) for k, v in extra.items()}
    pro = {k: (True if v == "true" else False if v == "false" else v) for k, v in pro.items()}
    json.dump({"pro": pro}, open(vpn.SETTINGS, "w", encoding="utf-8"))

orig_init = tk.Tk.__init__


def init(self, *a, **k):
    orig_init(self, *a, **k)
    if scale != 1.0:
        self.tk.call("tk", "scaling", float(self.tk.call("tk", "scaling")) * scale)


tk.Tk.__init__ = init
if screen_h:
    vpn.App.winfo_screenheight = lambda self: screen_h

NAMES = ["🇩🇪 Германия, Франкфурт 1", "🇫🇮 Финляндия, Хельсинки", "🇳🇱 Нидерланды, Амстердам", "🇸🇪 Швеция, Стокгольм",
         "🇺🇸 США, Нью-Йорк, очень длинное название сервера, которое не помещается в строку", "🇷🇺 Россия, Москва",
         "🇯🇵 Япония, Токио", "🇹🇷 Турция, Стамбул", "🇰🇿 Казахстан, Алматы", "🇦🇪 ОАЭ, Дубай", "🇵🇱 Польша, Варшава",
         "🇬🇧 Великобритания, Лондон"]
UUID = "11111111-2222-3333-4444-555555555555"


def link(name, i):
    return (f"vless://{UUID}@10.0.0.{i + 1}:443?type=tcp&security=reality&pbk=Y8bq6x0Q4s2v3m3pXw4m0hJq0kQy7Q3v1xk3nq0o3gE"
            f"&fp=chrome&sni=www.microsoft.com&sid=ab12&flow=xtls-rprx-vision#{name}")


app = vpn.App()


def pump(n=12, d=0.05):
    for _ in range(n):
        app.update()
        time.sleep(d)


def shot(win, name):
    pump(6)
    try:
        win.attributes("-topmost", True)
    except tk.TclError:
        pass
    win.lift()
    pump(8)
    from PIL import ImageGrab
    x, y, w, h = win.winfo_rootx(), win.winfo_rooty(), win.winfo_width(), win.winfo_height()
    box = (max(0, x - 10), max(0, y - 44), x + w + 10, y + h + 14)
    try:
        ImageGrab.grab(bbox=box).save(os.path.join(out_dir, name + ".png"))
        print("shot", name, f"{w}x{h}", flush=True)
    except Exception as e:  # noqa: BLE001  (no screen permission / no display: say so, do not fail the build)
        print("no shot", name, e, flush=True)
    try:
        win.attributes("-topmost", False)
    except tk.TclError:
        pass


pump(14)
app.src.insert("1.0", "")
app.say("")
shot(app, "00_empty")

app.subs = {"https://sub.example/x": {"outs": vpn.parse_text("\n".join(link(n, i) for i, n in enumerate(NAMES))), "info": {}, "time": time.time(), "ua": "v2rayN/7.0"}}
app.cfg["sources"] = "https://sub.example/x"
app.src.delete("1.0", "end")
app.src.insert("1.0", "https://sub.example/x")
app.apply_outs()
for i, o in enumerate(app.outs):
    app.results[o["tag"]] = (None, None) if i == 5 else (38.0 + i * 17, 140.0 - i * 9 if i % 4 else -1)
    app.alive[o["tag"]] = i != 5
    app._cell(i, ping=app.results[o["tag"]][0], speed=app.results[o["tag"]][1])
app.sort_rows()
app.say("Самый быстрый: Финляндия (140 Мбит/с, 55 мс). Скорость измерена загрузкой с speed.cloudflare.com.")
shot(app, "01_main_off")

app.state, app.api, app.current, app.t0 = "on", ("x", "y"), app.outs[1]["tag"], time.time() - 3725
app.refresh_power()
app.say("Подключено. В Windows включён прокси 127.0.0.1:3067 (другая программа): браузер идёт через него, а не через этот VPN.", err=False)
shot(app, "02_main_on")
app.state, app.api, app.current = "off", None, ""
app.refresh_power()

app.say("Не получилось получить подписку sub.example: сайт не ответил вовремя. Возможно, его блокирует провайдер: включи другой VPN и нажми «Обновить».", err=True)
app.toggle_settings(True)
shot(app, "03_main_settings")
app.toggle_log(True)
app.log.config(state="normal")
app.log.insert("end", "+0300 2026-10-31 12:00:01 INFO inbound/tun[tun-in]: started at FimaTUN\n" * 6)
app.log.config(state="disabled")
shot(app, "04_main_settings_log")
app.toggle_settings(False)
app.toggle_log(False)
app.say("")

pro = app.open_pro()
pump(10)
shot(pro, "05_pro")
try:
    pro.canvas.yview_moveto(1.0)
    shot(pro, "06_pro_bottom")
except Exception:  # noqa: BLE001
    pass
pro.close()

tk.Toplevel.wait_window = lambda self, w=None: None  # let a dialog stay open for the picture
for kind, text, buttons in (("question", vpn.MSG_DEAD_PROXY.format(addr="127.0.0.1:3067"), ["Отключить прокси", "Оставить"]),
                            ("error", vpn.MSG_NO_CORE, ["Скачать заново", "Закрыть"])):
    d = vpn.Dialog(app, text, buttons, kind, 0, 1)
    shot(d, "07_dialog_" + kind)
    d.destroy()

app.destroy()
print("done", flush=True)
