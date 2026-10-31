"""The window side of changing the server while connected and of the auto mode that weighs ping and speed: what a click
on another row does, what happens while connecting, how the auto mode picks, stays, fails over and re-measures.
The core is stood in for by a few functions (the real core is in test_switch.py). Run: python tests/test_autochoice.py"""
import faulthandler; faulthandler.dump_traceback_later(240, exit=True)
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

TMP = tempfile.mkdtemp(prefix="fimaauto_")
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

# ---------- a core that is only a few functions ----------
core = {"sel": vpn.AUTO_TAG, "pick": "Near", "calls": [], "refuse": set(), "delay": {}, "up": True}


def fake_switch(api, tag, interrupt=True):
    core["calls"].append(tag)
    if tag in core["refuse"]:
        return False, "refused"
    core["sel"] = tag
    return True, ""


def fake_current(api, raw=False):
    if not core["up"]:
        return None  # a core that is not answering yet
    if core["sel"] == vpn.AUTO_TAG and not raw:
        return core["pick"]
    return core["sel"]


def fake_delay(api, tag, url, timeout_ms=4000):
    return core["delay"].get(tag, 40.0)


vpn.switch_server, vpn.current_server, vpn.server_delay = fake_switch, fake_current, fake_delay

json.dump({"region": "RU", "lang": "ru", "setup_done": True}, open(vpn.SETTINGS, "w", encoding="utf-8"))
app = vpn.App()
try:
    def settle(n=8):
        for _ in range(n):
            app.update()
            time.sleep(0.03)

    def wait(cond, secs=3.0):
        end = time.time() + secs
        while time.time() < end:
            app.update()
            if cond():
                return True
            time.sleep(0.03)
        return cond()

    settle(10)
    ran_tests = []
    app.run_test = lambda quick=False: ran_tests.append(quick)  # the real one would start a core: not in a test
    names = ["Near", "Fast", "Far", "Slow"]
    text = "\n".join(f"vless://{U}@{n.lower()}.example:443?security=tls&sni=a.com#{n}" for n in names)
    app.subs, app.inline = {}, vpn.parse_text(text)
    app.cfg["sources"] = text
    app.apply_outs()
    settle()
    iid = {o["tag"]: str(i) for i, o in enumerate(app.outs)}

    def connect_state(sel="auto"):
        """The window as it is when the connection is up and the core has been started with all four servers."""
        core.update(sel=vpn.AUTO_TAG, pick="Near", calls=[], refuse=set(), delay={}, up=True)
        app.state, app.api, app.proc = "on", (1, "s"), None
        app.core_tags, app.core_sel, app.smart_tag = set(names), vpn.AUTO_TAG, None
        app.current, app.t0 = "Near", time.time()
        app.switching = app.switch_again = False
        app.skip_auto, app.bad_checks = {}, 0
        app.results, app.alive, app.speed_time = {}, {}, {}
        app.cfg["pro"] = {}
        app.v_ping.set(True)
        app.v_speed.set(True)
        app.select("auto" if sel == "auto" else iid[sel])
        settle(3)
        core["calls"].clear()

    def click(tag):
        """What a user does: pick a row (not an app's own selection, which on_select ignores)."""
        app.tree.selection_set("auto" if tag == "auto" else iid[tag])

    # ----- a click on another row while connected -----
    connect_state()
    click("Fast")
    check("nothing is switched at the moment of the click (a moment is waited for further clicks)", core["calls"] == [])
    check("a click on another row while connected switches the running core to that server", wait(lambda: core["calls"] == ["Fast"]), core["calls"])
    wait(lambda: not app.switching)
    check("... the window then says so and shows the server the core is on", app.core_sel == "Fast" and app.current == "Fast" and app.live_tag == "Fast", (app.core_sel, app.current))
    check("... in the status line", "Fast" in app.status.cget("text") and "Теперь" in app.status.cget("text"), app.status.cget("text"))
    check("... and what was picked is what is saved for the next start", app.cfg["chosen"] == "Fast")

    core["calls"].clear()
    for t in ("Far", "Slow", "Near"):  # arrow keys through the list
        click(t)
        settle(2)
    check("going through the list quickly switches only once, to the last row", wait(lambda: core["calls"] == ["Near"]) and wait(lambda: not app.switching), core["calls"])

    core["calls"].clear()
    click("auto")
    check("picking «Быстрейший из списка» puts the core on its own group", wait(lambda: core["calls"] == [vpn.AUTO_TAG]), core["calls"])
    wait(lambda: not app.switching)
    check("... and the window shows the server the group picked", app.current == "Near" and app.smart_tag is None)

    core["calls"].clear()
    click("auto")
    settle(3)
    check("picking what is already in use changes nothing", not wait(lambda: core["calls"], 0.8), core["calls"])

    # a server the core was not started with cannot be switched to: said so, nothing pretended
    connect_state()
    app.core_tags = {"Near", "Fast", "Far"}
    click("Slow")
    wait(lambda: "не было в списке" in app.status.cget("text"))
    check("a server that came after the connection was made is not switched to; the user is told what to do",
          core["calls"] == [] and "не было в списке" in app.status.cget("text") and "Near" in app.status.cget("text"), (core["calls"], app.status.cget("text")))

    # a refused switch leaves the connection where it was and says so
    connect_state()
    core["refuse"] = {"Far"}
    click("Far")
    wait(lambda: "Не получилось" in app.status.cget("text"))
    check("a switch the core refuses is reported, and the window keeps showing the server it is really on",
          "Не получилось" in app.status.cget("text") and app.core_sel == vpn.AUTO_TAG and app.current == "Near", (app.status.cget("text"), app.core_sel, app.current))

    # a server that does not answer: said so, and that nothing leaks
    connect_state()
    core["delay"]["Slow"] = None
    click("Slow")
    wait(lambda: "не отвечает" in app.status.cget("text"))
    check("a server that does not answer is said not to, with the assurance that nothing leaves around the VPN",
          "не отвечает" in app.status.cget("text") and "мимо VPN ничего не уходит" in app.status.cget("text"), app.status.cget("text"))

    # nothing happens while not connected: only the choice is remembered
    connect_state()
    app.state, app.api = "off", None
    click("Far")
    check("while disconnected a click only picks (nothing to switch)", not wait(lambda: core["calls"], 0.8) and app.cfg["chosen"] == "Far", core["calls"])

    # picked while connecting: applied as soon as the core is up
    connect_state()
    app.state, app.t_conn = "connecting", time.time()
    core["up"] = False
    click("Fast")
    check("picked while connecting: nothing is sent to a core that is not up yet", not wait(lambda: core["calls"], 0.8), core["calls"])
    core["up"] = True
    app.got_current("Near", app.api)
    check("... and sent the moment the core answers", app.state == "on" and wait(lambda: core["calls"] == ["Fast"]), (app.state, core["calls"]))
    wait(lambda: not app.switching)

    # ----- stopping forgets the connection -----
    app.api = None
    app.stop()
    check("disconnecting forgets what the core had", app.core_tags == set() and app.core_sel == "" and app.smart_tag is None and not app.switching)

    # ----- the auto mode: ping and speed together -----
    DATA = {"Near": (25, 5), "Fast": (60, 150), "Far": (180, 300), "Slow": (400, 2)}

    def measured(data=DATA):
        for t, (p, sp) in data.items():
            app.results[t] = (p, sp)
            app.speed_time[t] = time.time()
            app.alive[t] = True

    connect_state()
    app.current = "Near"
    measured()
    check("with speeds measured, the lowest ping on a thin pipe is not what the auto mode picks", app.smart_pick() == "Fast", app.smart_pick())
    app.apply_smart()
    check("... the auto mode moves the connection to the better server", wait(lambda: core["calls"] == ["Fast"]) and app.smart_tag == "Fast", (core["calls"], app.smart_tag))
    wait(lambda: not app.switching)
    check("... and says what it picked and why (ping and speed)", "Автовыбор" in app.status.cget("text") and "Fast" in app.status.cget("text") and "150" in app.status.cget("text"), app.status.cget("text"))
    check("... still «Быстрейший из списка» in the list and on the button", app.chosen() == "AUTO" and app.live_tag == "Fast")

    core["calls"].clear()
    app.results["Far"] = (50, 160)  # a bit better, not clearly
    app.apply_smart()
    check("a server that is only a little better does not make it switch", not wait(lambda: core["calls"], 0.6) and app.smart_tag == "Fast", core["calls"])
    app.results["Far"] = (20, 600)
    app.apply_smart()
    check("a clearly better one does", wait(lambda: core["calls"] == ["Far"]) and app.smart_tag == "Far", core["calls"])
    wait(lambda: not app.switching)

    # what the user cares about
    connect_state()
    FOCUS_DATA = {"Near": (15, 20), "Fast": (90, 100), "Far": (150, 500), "Slow": (400, 2)}
    measured(FOCUS_DATA)
    app.current = ""
    check("balanced: a middle way", app.smart_pick() == "Fast", app.smart_pick())
    app.cfg["pro"] = {"auto_focus": "latency"}
    check("response time first: the nearest", app.smart_pick() == "Near", app.smart_pick())
    app.cfg["pro"] = {"auto_focus": "speed"}
    check("speed first: the thickest pipe", app.smart_pick() == "Far", app.smart_pick())

    # switched off
    connect_state()
    measured()
    app.cfg["pro"] = {"auto_speed": False}
    check("with the speed option off the auto mode is left to the core's group (ping only)", app.smart_pick() is None)
    app.cfg["pro"] = {}
    app.v_speed.set(False)
    check("... and when speed is switched off in Settings, nothing is measured or weighed", app.smart_pick() is None and not app.use_speed())
    app.v_speed.set(True)
    app.v_ping.set(False)
    check("... the same without ping", not app.use_speed())
    app.v_ping.set(True)
    connect_state()
    check("nothing measured yet: the core's group decides", app.smart_pick() is None)
    connect_state("Far")
    measured()
    app.apply_smart()
    check("a server picked by hand is never replaced by the auto mode", not wait(lambda: core["calls"], 0.6) and app.smart_tag is None, core["calls"])

    # ----- the server it picked stops answering -----
    connect_state()
    measured()
    app.apply_smart()
    wait(lambda: core["calls"] == ["Fast"])
    wait(lambda: not app.switching)
    core["calls"].clear()
    app.health_done(app.api, "Fast", None)
    check("one lost answer is not yet a dead server", app.smart_tag == "Fast" and core["calls"] == [])
    app.health_done(app.api, "Fast", 55.0)
    app.health_done(app.api, "Fast", None)
    check("... and an answer in between starts the count again", app.smart_tag == "Fast")
    app.health_done(app.api, "Fast", None)
    check("two in a row: it goes to the next best and keeps away from the dead one", wait(lambda: core["calls"] == ["Far"]) and "Fast" in app.skip_auto, (core["calls"], app.skip_auto))
    wait(lambda: not app.switching)
    check("... and tells the user", "Автовыбор" in app.status.cget("text") or "перестал отвечать" in app.status.cget("text"), app.status.cget("text"))
    core["calls"].clear()
    for t in ("Far", "Near", "Slow"):
        app.skip_auto[t] = time.time() + 600
    app.health_done(app.api, "Far", None)
    app.health_done(app.api, "Far", None)
    check("when every server has failed, the core's own group takes over", wait(lambda: core["calls"] == [vpn.AUTO_TAG]) and app.smart_tag is None, core["calls"])
    wait(lambda: not app.switching)

    # ----- measuring now and then -----
    connect_state()
    ran = []
    app.run_test = lambda quick=False: ran.append(quick)
    app.review_auto()
    check("no speeds yet: the background test is started", ran == [True], ran)
    ran.clear()
    measured()
    app.review_auto()
    check("fresh speeds: no test, the choice is made at once", ran == [] and wait(lambda: app.smart_tag == "Fast"), (ran, app.smart_tag))
    wait(lambda: not app.switching)
    ran.clear()
    for t in app.speed_time:
        app.speed_time[t] = time.time() - vpn.REVIEW_EVERY - 5
    app.review_auto()
    check("speeds older than half an hour are measured again", ran == [True], ran)
    ran.clear()
    app.testing = True
    app.review_auto()
    check("never while another test is running", ran == [])
    app.testing = False
    connect_state("Far")
    app.review_auto()
    check("a server picked by hand: no measuring on the user's line", ran == [])
    app.run_test = lambda quick=False: ran_tests.append(quick)

    # ----- the order of the list is the order of advice -----
    connect_state()
    measured()
    app.sort_rows()
    order = [app.outs[int(i)]["tag"] for i in app.tree.get_children() if i != "auto"]
    check("the list is ordered by ping and speed together, not by speed alone or ping alone", order[:2] == ["Far", "Fast"] or order[:2] == ["Fast", "Far"], order)
    check("... a thin pipe at the lowest ping is not first", order[0] != "Near", order)
    measured(FOCUS_DATA)
    app.cfg["pro"] = {"auto_focus": "latency"}
    app.sort_rows()
    order = [app.outs[int(i)]["tag"] for i in app.tree.get_children() if i != "auto"]
    check("... and the order follows what the user cares about", order[0] == "Near", order)
    app.cfg["pro"] = {}

    # ----- what the test says -----
    connect_state()
    app.state, app.api = "off", None
    measured()
    app.exit_cc = {}
    app.test_done(None)
    say = app.status.cget("text")
    check("the test names the best choice and why it is not the lowest ping",
          "Лучший выбор: Fast" in say and "Near" in say and "скорость" in say, say)
    app.test_quick = True
    app.testing = True
    app.test_done(None)
    check("the background test says nothing of its own", app.testing is False and app.test_quick is False and "Лучший выбор" not in app.status.cget("text"), app.status.cget("text"))

    # ----- the speed option is in the advanced settings -----
    keys = [k for _, rows in vpn.PRO_LAYOUT for k, *_ in rows]
    check("the advanced settings offer both: what matters more, and whether speed counts", "auto_focus" in keys and "auto_speed" in keys)
    check("the defaults weigh ping and speed equally and measure speed", vpn.PRO_DEFAULTS["auto_focus"] == "balanced" and vpn.PRO_DEFAULTS["auto_speed"] is True)
    v, e = vpn.clean_pro({"auto_focus": "speed", "auto_speed": False})
    check("... and they take what is typed, and refuse nonsense", v["auto_focus"] == "speed" and v["auto_speed"] is False and not e
          and "auto_focus" in vpn.clean_pro({"auto_focus": "loud"})[1])
finally:
    app.destroy()

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
