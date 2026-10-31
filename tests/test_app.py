"""The program as a whole, with the window: subscriptions, speed test, flags, settings, tray, update install, connecting,
reconnect, repair of a refused config. Local fake servers, temp files, no real core connection, never the real
settings. Run: python tests/test_app.py"""
import faulthandler; faulthandler.dump_traceback_later(420, exit=True)  # a hang must leave a traceback, not a silent wait
import base64
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # test names are Russian; a Windows runner's console is cp1252
WIP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, WIP)
os.environ["FIMA_NO_TRAY"] = "1"  # no real tray icons from tests
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimatest_")
vpn.SETTINGS = os.path.join(TMP, "settings.json")
vpn.SUBCACHE = os.path.join(TMP, "subs.json")
vpn.EXITFILE = os.path.join(TMP, "exit.json")
vpn.INSTANCE_FILE = os.path.join(TMP, "instance.port")  # never the real one
vpn.RULES_DIR = os.path.join(TMP, "rules")
vpn.LOGFILE = os.path.join(TMP, "sing-box.log")
vpn.kill_stale_cores = lambda *a, **k: 0  # never touch the real running core in tests
vpn.detect_home = lambda *a, **k: None  # nor start a real core to ask which country the machine is in
vpn.PRO_FIELDS["merge_subs"] = (False, "bool", None)  # this suite counts requests per User-Agent: one answer per subscription (merging has its own test)
vpn.PRO_DEFAULTS["merge_subs"] = False

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


# ---------------- fake providers ----------------
UUID = "11111111-2222-3333-4444-555555555555"


def vless(name, host="1.2.3.4"):
    return (f"vless://{UUID}@{host}:443?type=tcp&security=reality&pbk=Y8bq6x0Q4s2v3m3pXw4m0hJq0kQy7Q3v1xk3nq0o3gE"
            f"&fp=chrome&sni=www.microsoft.com&sid=ab12&flow=xtls-rprx-vision#{name}")


STATE = {"s1_nodes": ["Германия", "Финляндия"], "s1_fail": False, "hits": {}}
TITLE2 = "❤️ daneeke."


def singbox_json(names):
    outs = [{"type": "selector", "tag": "select", "outbounds": names}, {"type": "direct", "tag": "direct"}]
    for n in names:
        outs.append({"type": "vless", "tag": n, "server": "5.6.7.8", "server_port": 443, "uuid": UUID,
                     "tls": {"enabled": True, "server_name": "a.com", "utls": {"enabled": True, "fingerprint": "safari"}},
                     "transport": {"type": "grpc", "service_name": "x"}})
    return json.dumps({"dns": {}, "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30"}], "outbounds": outs})


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        path = self.path.split("?")[0]
        key = path.rsplit("/", 1)[-1] + "|" + ua
        STATE["hits"][key] = STATE["hits"].get(key, 0) + 1
        if path.endswith("/s1"):
            if STATE["s1_fail"]:
                return self.send_error(500)
            if "v2rayN" in ua:  # Remnawave answers v2rayN with a huge Xray JSON array
                body = json.dumps([{"remarks": "x", "outbounds": [{"protocol": "vless"}]}] * 50)
            else:
                body = singbox_json(STATE["s1_nodes"])
            hdr = {"profile-update-interval": "1", "subscription-userinfo": "expire=1794620492",
                   "profile-title": "iovpn"}
        elif path.endswith("/s2"):
            body = base64.b64encode("\n".join([vless("Швеция"), vless("Литва")]).encode()).decode()
            hdr = {"profile-update-interval": "4",
                   "subscription-userinfo": "upload=0; download=72084811300; total=0; expire=0",
                   "profile-title": "base64:" + base64.b64encode(TITLE2.encode()).decode()}
        elif path.endswith(".srs"):  # served through the "proxy" for the rule-set updater
            if "bad" in path:
                body, hdr = "<html>blocked</html>", {}
            else:
                data = b"SRS\x01" + os.urandom(2000)
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        else:
            return self.send_error(404)
        data = body.encode()
        self.send_response(200)
        for k, v in hdr.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
S1, S2, BAD = (f"http://127.0.0.1:{PORT}/s1", f"http://127.0.0.1:{PORT}/s2", f"http://127.0.0.1:{PORT}/nope")

# ---------------- pure functions ----------------
info1 = vpn.sub_info({"profile-update-interval": "1", "subscription-userinfo": "expire=1794620492",
                      "profile-title": "iovpn"})
check("sub_info sub#1", info1 == {"interval_h": 1.0, "usage": {"expire": 1794620492}, "title": "iovpn"}, info1)
info2 = vpn.sub_info({"profile-update-interval": "4",
                      "subscription-userinfo": "upload=0; download=72084811300; total=0; expire=0",
                      "profile-title": "base64:" + base64.b64encode(TITLE2.encode()).decode()})
check("sub_info sub#2", info2 == {"interval_h": 4.0, "usage": {"upload": 0, "download": 72084811300, "total": 0,
                                                               "expire": 0}, "title": TITLE2}, info2)
check("sub_info garbage", vpn.sub_info({"profile-update-interval": "soon", "subscription-userinfo": "a=b;;"}) == {})

urls, inline = vpn.split_sources(f"  {S1}\n\n{vless('Inline')}\nHTTPS://x.y/z \n")
check("split_sources", urls == [S1, "HTTPS://x.y/z"] and inline == [vless("Inline")], (urls, inline))

def _o(tag):
    return {"tag": tag, "type": "vless", "server": "h.example", "server_port": 443, "uuid": "11111111-2222-3333-4444-555555555555"}
a = [_o("A"), _o("B")]
b = [_o("A")]
m1 = vpn.merge_outs([a, b])
m2 = vpn.merge_outs([a, b])
check("merge_outs dedups", [o["tag"] for o in m1] == ["A", "B", "A*"], [o["tag"] for o in m1])
check("merge_outs stable + no mutation", [o["tag"] for o in m2] == ["A", "B", "A*"] and b[0]["tag"] == "A")

outs, info, ua, errs = vpn.fetch_source(S1)
check("fetch_source falls back to sing-box UA", ua == "sing-box/1.13" and [o["tag"] for o in outs] == STATE["s1_nodes"],
      (ua, [o["tag"] for o in outs], errs))
check("fetch_source keeps only nodes from sing-box JSON", all(o["type"] == "vless" for o in outs))
before = dict(STATE["hits"])
vpn.fetch_source(S1, prefer="sing-box/1.13")
new = {k: v - before.get(k, 0) for k, v in STATE["hits"].items() if v != before.get(k, 0)}
check("fetch_source tries remembered UA first (1 request, no 1 MB JSON)", new == {"s1|sing-box/1.13": 1}, new)
outs, info, ua, errs = vpn.fetch_source(BAD)
check("fetch_source reports failure", outs == [] and ua is None and errs, errs)

# ---------------- config ----------------
nodes = vpn.parse_text(vless("X"))
cfg = vpn.build_config(nodes, "AUTO", True, ["example.com"])
rs = {r["tag"]: r for r in cfg["route"].get("rule_set", [])}
check("config has both RU rule-sets", set(rs) == {"geosite-ru", "geoip-ru"}, list(rs))
check("bundled rule-set paths used", all(os.path.dirname(r["path"]) == vpn.CORE_DIR for r in rs.values()))
check("route rules reference both", {"rule_set": ["geosite-ru"], "outbound": "direct"} in cfg["route"]["rules"]
      and {"rule_set": ["geoip-ru"], "outbound": "direct"} in cfg["route"]["rules"])
check("dns uses local resolver for RU domains", {"rule_set": ["geosite-ru"], "server": "local"} in cfg["dns"]["rules"])
cfg_off = vpn.build_config(nodes, "AUTO", False, [])
check("ru_direct off: no rule-sets", "rule_set" not in cfg_off["route"]
      and not any("rule_set" in r for r in cfg_off["dns"]["rules"]))

# ---------------- RU-list updater through a "proxy" ----------------
vpn.RULE_SETS = {"geosite-ru": ("http://example.test/bad-geosite.srs", "http://example.test/geosite.srs"),
                 "geoip-ru": ("http://example.test/geoip.srs",)}
n = vpn.update_rule_sets(PORT)  # our fake server answers absolute-URI GETs like an HTTP proxy
check("update_rule_sets downloads both (falls back past a non-SRS answer)", n == 2, n)
check("downloaded copy wins", vpn.rule_path("geosite-ru") == os.path.join(vpn.RULES_DIR, "geosite-ru.srs"))
open(os.path.join(vpn.RULES_DIR, "geoip-ru.srs"), "wb").write(b"<html>")
check("corrupt download falls back to bundled", vpn.rule_path("geoip-ru") == os.path.join(vpn.CORE_DIR, "geoip-ru.srs"))
check("no tmp leftovers", not [f for f in os.listdir(vpn.RULES_DIR) if f.endswith(".tmp")])
check("update fails cleanly when proxy is down", vpn.update_rule_sets(1) == 0)

# ---------------- App: startup, refresh by interval, failure keeps cache ----------------
vpn.write_json(vpn.SETTINGS, {"sources": f"{S1}\n{S2}\n{vless('Inline')}", "chosen": "Литва"})


def pump(app, cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        app.update()
        if cond():
            return True
        time.sleep(0.03)
    return False


app = vpn.App()
app.withdraw()
check("first start loads all subscriptions", pump(app, lambda: len(app.outs) == 5), [o["tag"] for o in app.outs])
check("selection restored from settings", app.chosen() == "Литва", app.chosen())
check("cache written", set(json.load(open(vpn.SUBCACHE, encoding="utf-8"))) == {S1, S2})
check("sub note shows time", app.sub_note.cget("text").startswith("обновлено в "), app.sub_note.cget("text"))
check("provider interval stored", app.subs[S1]["info"]["interval_h"] == 1 and app.subs[S2]["info"]["interval_h"] == 4)

iid = next(str(i) for i, o in enumerate(app.outs) if o["tag"] == "Швеция")
app.tree.selection_set(iid)  # what a user click does
pump(app, lambda: app.cfg["chosen"] == "Швеция", 2)
check("user click is remembered", app.cfg["chosen"] == "Швеция", app.cfg["chosen"])
app.subs[S2]["time"] -= 4 * 3600 + 1
app.refresh_due()
pump(app, lambda: not app.loading and app.subs[S2]["time"] > time.time() - 60, 5)
check("user choice survives a refresh", app.chosen() == "Швеция" and app.cfg["chosen"] == "Швеция",
      (app.chosen(), app.cfg["chosen"]))
iid = next(str(i) for i, o in enumerate(app.outs) if o["tag"] == "Литва")
app.tree.selection_set(iid)
pump(app, lambda: app.cfg["chosen"] == "Литва", 2)

before = dict(STATE["hits"])
app.refresh_due()
pump(app, lambda: not app.loading, 3)
check("nothing refreshed before the interval", STATE["hits"] == before)

STATE["s1_nodes"] = ["Германия", "Финляндия", "Нидерланды"]
app.subs[S1]["time"] -= 3601  # sub#1 interval is 1 h
before = dict(STATE["hits"])
app.refresh_due()
check("due subscription refreshed in background", pump(app, lambda: len(app.outs) == 6), len(app.outs))
new = {k: v - before.get(k, 0) for k, v in STATE["hits"].items() if v != before.get(k, 0)}
check("only sub#1 fetched, with the remembered UA", new == {"s1|sing-box/1.13": 1}, new)
check("selection kept across background refresh", app.chosen() == "Литва", app.chosen())

STATE["s1_fail"] = True
app.subs[S1]["time"] -= 3601
app.say("")
app.refresh_due()
pump(app, lambda: not app.loading and S1 in app.sub_fail, 5)
check("failed background refresh keeps cached servers", len(app.outs) == 6, len(app.outs))
check("failed background refresh stays quiet", app.status.cget("text") == "", app.status.cget("text"))
before = dict(STATE["hits"])
app.refresh_due()
pump(app, lambda: not app.loading, 2)
check("failure backoff: no immediate retry", STATE["hits"] == before)

app.load()  # manual refresh while sub#1 is down
pump(app, lambda: not app.loading, 5)
check("manual refresh with a failing sub keeps its cached servers", len(app.outs) == 6, len(app.outs))
check("manual refresh reports partial failure", "Не все подписки" in app.status.cget("text"), app.status.cget("text"))

app.testing = True
app.subs[S2]["time"] -= 5 * 3600
before = dict(STATE["hits"])
app.refresh_due()
pump(app, lambda: False, 1)
check("no refresh during a speed test", STATE["hits"] == before)
app.testing = False

# what a user really pastes: an "open in the app" link, an address in quotes inside a sentence, an address without a scheme
STATE["s1_fail"] = False
STATE["s1_nodes"] = ["Германия", "Финляндия", "Нидерланды"]
from urllib.parse import quote  # noqa: E402
prev_src = app.src.get("1.0", "end").strip()
app.src.delete("1.0", "end")
app.src.insert("1.0", f"sing-box://import-remote-profile?url={quote(S1, safe='')}#Моя подписка\nВот вторая: \"{S2}\", держи.\n")
app.load()
pump(app, lambda: not app.loading and S1 in app.subs and S2 in app.subs, 6)
box = app.src.get("1.0", "end").strip().splitlines()
check("a deep link and an address in a sentence are tidied in the box (and saved so)", box == [S1, S2] and app.cfg["sources"] == f"{S1}\n{S2}", (box, app.cfg["sources"]))
check("... and both subscriptions load", len(app.outs) >= 4, len(app.outs))
STATE["s1_nodes"] = ["Германия", "Финляндия", "Нидерланды"]  # back to what the rest of the suite expects
STATE["s1_fail"] = True
app.src.delete("1.0", "end")
app.src.insert("1.0", prev_src)
app.load()
pump(app, lambda: not app.loading and len(app.outs) == 6, 6)
app.destroy()

STATE["s1_fail"] = True  # provider unreachable at the next start: cached list must still show instantly
app2 = vpn.App()
app2.withdraw()
check("next start shows cached servers before any network", len(app2.outs) == 6, len(app2.outs))
pump(app2, lambda: not app2.loading, 5)
check("still 6 after the failed startup refresh", len(app2.outs) == 6, len(app2.outs))
app2.destroy()

# ---------------- stale-core cleanup parsing ----------------
data = r"C:\Users\User3\AppData\Roaming\FimaVPN"
raw = "\n".join([
    r"7568|C:\Users\User3\AppData\Local\Temp\_MEI1\core\sing-box.exe run -c C:\Users\User3\AppData\Roaming\FimaVPN\run.json",
    r"123|c:\users\user3\appdata\roaming\fimavpn\test.json run",
    r"9999|sing-box.exe run -c D:\other\config.json",
    "abc|garbage", "", "42|"])
check("parse_stale finds our leftover cores only", vpn.parse_stale(raw, data, {123}) == [7568], vpn.parse_stale(raw, data, {123}))
check("parse_stale: own pids skipped, case-insensitive", vpn.parse_stale(raw, data, set()) == [7568, 123])


# ---------------- ping on an established connection ----------------
class KA(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        time.sleep(0.3)  # "handshake" cost, paid once per connection
        super().setup()

    def do_GET(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


ka = ThreadingHTTPServer(("127.0.0.1", 0), KA)
threading.Thread(target=ka.serve_forever, daemon=True).start()
vpn.PING_URL = "http://example.test/generate_204"
t0 = time.perf_counter()
ms = vpn.probe_ping(ka.server_address[1])
total = (time.perf_counter() - t0) * 1000
check("probe_ping does not count connection setup", ms is not None and ms < 150 and total >= 300, (ms, total))
check("probe_ping is None when nothing listens", vpn.probe_ping(1) is None)

# ---------------- speed probe: User-Agent, source order, tuple result ----------------
SEEN = []


class BIG(BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append((self.path, self.headers.get("User-Agent", "")))
        if "blocked" in self.path:  # Cloudflare-style answer to a bot UA
            return self.send_error(403)
        self.send_response(200)
        self.send_header("Content-Length", str(3_000_000))
        self.end_headers()
        try:
            self.wfile.write(b"x" * 3_000_000)
        except Exception:
            pass

    def log_message(self, *a):
        pass


big = ThreadingHTTPServer(("127.0.0.1", 0), BIG)
threading.Thread(target=big.serve_forever, daemon=True).start()
bp = big.server_address[1]
urls = ["http://a.test/blocked.bin", "http://b.test/ok.bin", "http://c.test/never.bin"]
sp, used = vpn.probe_speed(bp, secs=2, urls=urls)
check("probe_speed returns (Mbit/s, url) from the first source that answers", sp and sp > 1 and used == urls[1], (sp, used))
check("probe_speed sends a browser User-Agent", all("Mozilla" in ua for _, ua in SEEN), SEEN)
check("probe_speed never reaches later sources once one answered", not any("never" in p for p, _ in SEEN))
check("probe_speed (None, None) when every source fails", vpn.probe_speed(bp, secs=1, urls=["http://a.test/blocked.bin"]) == (None, None))
check("speed sources: Cloudflare first, no dead hosts, Russian only as fallback",
      "cloudflare" in vpn.SPEED_URLS[0] and not any(h in " ".join(vpn.SPEED_URLS) for h in ("hetzner", "thinkbroadband"))
      and [u for u in vpn.SPEED_URLS if ".ru/" in u] == list(vpn.SPEED_URLS[-2:]))

# ---------------- the speed test must not change what the user picked ----------------
app3 = vpn.App()
app3.withdraw()
pump(app3, lambda: len(app3.outs) >= 5, 10)
for i, o in enumerate(app3.outs):
    app3.results[o["tag"]] = (50 + i * 10, 10.0 + i)  # the LAST server is the fastest by speed
fastest = len(app3.outs) - 1
app3.tree.selection_set("auto")
app3.update()
app3.test_done(None)
app3.update()
check("AUTO stays selected after the test", app3.tree.selection() == ("auto",) and app3.chosen() == "AUTO",
      (app3.tree.selection(), app3.chosen()))
check("saved choice is still AUTO", app3.cfg["chosen"] == "AUTO", app3.cfg["chosen"])
check("fastest server is the first row after AUTO", app3.tree.get_children()[1] == str(fastest), app3.tree.get_children()[:3])
check("status names the fastest and explains AUTO", app3.outs[fastest]["tag"] in app3.status.cget("text")
      and "переключаться" in app3.status.cget("text"), app3.status.cget("text"))
app3.tree.selection_set("1")
app3.update()
app3.test_done(None)
app3.update()
check("a manually picked server stays picked", app3.tree.selection() == ("1",) and app3.cfg["chosen"] == app3.outs[1]["tag"],
      (app3.tree.selection(), app3.cfg["chosen"]))
check("no AUTO hint when a server is picked", "переключаться" not in app3.status.cget("text"))
app3.destroy()

# ---------------- which server is the connection on (auto mode) ----------------
class API(BaseHTTPRequestHandler):
    NOW = "B"

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer s3cret":
            return self.send_error(401)
        if self.path != "/proxies/proxy":
            return self.send_error(404)
        body = json.dumps({"name": "proxy", "type": "URLTest", "now": API.NOW, "all": ["A", "B"]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


api_srv = ThreadingHTTPServer(("127.0.0.1", 0), API)
threading.Thread(target=api_srv.serve_forever, daemon=True).start()
ap = api_srv.server_address[1]
check("current_server reads 'now' from the core API", vpn.current_server((ap, "s3cret")) == "B")
check("current_server needs the secret", vpn.current_server((ap, "wrong")) is None)
check("current_server is None when the core is gone", vpn.current_server((1, "s3cret")) is None)
fp = vpn.free_port()
check("free_port gives a usable port", 1024 <= fp <= 65535)
cfg = vpn.build_config(vpn.parse_text(vless("X")), "AUTO", True, [], (fp, "abc"))
check("config exposes the local API on loopback with a secret",
      cfg["experimental"]["clash_api"] == {"external_controller": f"127.0.0.1:{fp}", "secret": "abc"})
check("no API section when not requested", "experimental" not in vpn.build_config(vpn.parse_text(vless("X")), "AUTO", True, []))

app4 = vpn.App()
app4.withdraw()
pump(app4, lambda: len(app4.outs) >= 5, 10)
tags = [o["tag"] for o in app4.outs]
app4.tree.selection_set("auto")
app4.update()
app4.state, app4.api, app4.t0 = "on", (ap, "s3cret"), time.time()
API.NOW = tags[2]
app4.poll_current()
check("window picks up the live server", pump(app4, lambda: app4.current == tags[2], 5), app4.current)
check("big block names the real server in auto mode", app4.power.server == f"Авто: {tags[2]}", app4.power.server)
check("exactly one row is marked live, and it is the right one",
      [iid for iid in app4.tree.get_children() if "live" in app4.tree.item(iid, "tags")] == ["2"],
      [(iid, app4.tree.item(iid, "tags")) for iid in app4.tree.get_children()][:4])
API.NOW = tags[4]
app4.poll_current()
check("follows an automatic switch", pump(app4, lambda: app4.current == tags[4], 5), app4.current)
check("old row unmarked after the switch", [iid for iid in app4.tree.get_children() if "live" in app4.tree.item(iid, "tags")] == ["4"])
app4.tree.selection_set("1")
app4.update()
app4.refresh_power()
check("fixed server: shows its own name, no 'Авто:'", app4.power.server == tags[4] and not app4.power.server.startswith("Авто"), app4.power.server)
app4.stop()
check("stop clears the live mark and the name", app4.current == "" and not [i for i in app4.tree.get_children() if "live" in app4.tree.item(i, "tags")])
app4.destroy()

# ---------------- flag from the real exit country ----------------
class TRACE(BaseHTTPRequestHandler):
    LOC = "NL"

    def do_GET(self):
        body = f"fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nts=1\nloc={TRACE.LOC}\ncolo=AMS\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


tr = ThreadingHTTPServer(("127.0.0.1", 0), TRACE)
threading.Thread(target=tr.serve_forever, daemon=True).start()
tp = tr.server_address[1]
check("probe_exit reads the country Cloudflare reports", vpn.probe_exit(tp, ("http://a.test/cdn-cgi/trace",)) == "NL")
TRACE.LOC = "XX"
check("probe_exit ignores 'unknown' (XX)", vpn.probe_exit(tp, ("http://a.test/cdn-cgi/trace",)) is None)
TRACE.LOC = "fi"
check("probe_exit upper-cases the code", vpn.probe_exit(tp, ("http://a.test/cdn-cgi/trace",)) == "FI")
check("probe_exit is None when nothing answers", vpn.probe_exit(1, ("http://a.test/cdn-cgi/trace",)) is None)
check("okey is the address, not the name", vpn.okey({"server": "1.2.3.4", "server_port": 443, "tag": "x"}) == "1.2.3.4:443")

app5 = vpn.App()
app5.withdraw()
pump(app5, lambda: len(app5.outs) >= 5, 10)
o0 = app5.outs[0]
name_code = vpn.flags.code_for(o0["tag"])
check("before the test the flag comes from the name", app5.flag_code(o0) == name_code and name_code != "NL", (o0["tag"], name_code))
img_before = str(app5.tree.item("0", "image"))
app5.set_exit(0, "NL")
check("a real exit country overrides the name", app5.flag_code(o0) == "NL")
check("the list row is redrawn with the real flag", app5.tree.item("0", "image")[0] == str(app5.flagimgs.get("NL"))
      and str(app5.tree.item("0", "image")) != img_before, (img_before, app5.tree.item("0", "image")))
app5.set_exit(0, "ZW")
check("a real country without a drawing gets the neutral tile, never the name's flag", app5.flag_code(o0) == "??")
app5.set_exit(0, "NL")
app5.state, app5.api, app5.current, app5.t0 = "on", ("x", "y"), o0["tag"], time.time()
app5.refresh_power()
check("the main button shows the real flag of the connected server", app5.power.flag is app5.flagimgs.get("NL"))
app5.state, app5.api, app5.current = "off", None, ""
vpn.write_json(vpn.EXITFILE, {o0["server"] + ":" + str(o0["server_port"]): "SE", "junk": 5})
app5b = vpn.App()
app5b.withdraw()
check("exit countries survive a restart (and junk is ignored)", app5b.exit_cc == {o0["server"] + ":" + str(o0["server_port"]): "SE"}, app5b.exit_cc)
app5b.destroy()

# test_done reports servers whose name and real exit disagree
for i, o in enumerate(app5.outs):
    app5.results[o["tag"]] = (50 + i, 10.0 + i)
app5.exit_cc.clear()
named = [o for o in app5.outs if vpn.flags.code_for(o["tag"]) != "??"]
app5.exit_cc[vpn.okey(named[0])] = "JP" if vpn.flags.code_for(named[0]["tag"]) != "JP" else "US"
app5.speed_host = "speed.cloudflare.com"
app5.test_done(None)
check("test_done tells about a name/exit mismatch", "не совпала" in app5.status.cget("text") and "флаг показан по выходу" in app5.status.cget("text"), app5.status.cget("text"))
app5.exit_cc.clear()
app5.test_done(None)
check("no mismatch note when all agree", "не совпала" not in app5.status.cget("text"))
app5.destroy()

# ---------------- settings: flags / ping / speed are independent ----------------
app6 = vpn.App()
app6.withdraw()
pump(app6, lambda: len(app6.outs) >= 5, 10)
N = len(app6.outs)
BASE = vpn.TEST_BASE_PORT
DEAD = 3
calls = {"ping": [], "exit": [], "speed": []}


def fake_ping(port):
    calls["ping"].append(port)
    return None if port - BASE == DEAD else 50.0 + (port - BASE)


def fake_exit(port):
    calls["exit"].append(port)
    return None if port - BASE == DEAD else "NL"


def fake_speed(port, secs=4.0, urls=None):
    calls["speed"].append(port)
    return 10.0 + (port - BASE), (urls or vpn.SPEED_URLS)[0]


real_probes = (vpn.probe_ping, vpn.probe_exit, vpn.probe_speed)
vpn.probe_ping, vpn.probe_exit, vpn.probe_speed = fake_ping, fake_exit, fake_speed


def run(plan):
    for k in calls:
        calls[k].clear()
    app6.results.clear()
    app6.alive.clear()
    app6.exit_cc.clear()
    app6.test_stop.clear()
    app6._probe_all(list(app6.outs), plan)
    pump(app6, lambda: False, 0.4)  # let the UI callbacks run


tags = [o["tag"] for o in app6.outs]
run((True, True, True))
check("all on: every server is pinged", sorted(calls["ping"]) == [BASE + i for i in range(N)], calls["ping"])
check("all on: country asked for the servers that answered", sorted(calls["exit"]) == [BASE + i for i in range(N) if i != DEAD])
check("all on: speed only for the best by ping (max 8), never for a dead one",
      DEAD + BASE not in calls["speed"] and len(calls["speed"]) == min(vpn.TOP_FOR_SPEED, N - 1), calls["speed"])
check("all on: dead server shows no ping and is marked dead", app6.results[tags[DEAD]][0] == -1 and app6.alive[tags[DEAD]] is False)

run((False, False, True))
check("speed only: ping is NOT measured for servers that answer (only a fallback alive check on the dead one)",
      calls["ping"] == [BASE + DEAD], calls["ping"])
check("speed only: no ping stored", all(app6.results[t][0] is None for t in tags if t != tags[DEAD]), app6.results)
check("speed only: with no ranking every server that answered is tried",
      sorted(calls["speed"]) == [BASE + i for i in range(N) if i != DEAD], calls["speed"])
check("speed only: a dead server is a dash in the speed column", app6.results[tags[DEAD]][1] == -1)

run((False, True, False))
check("ping only: nothing is downloaded", calls["speed"] == [])
check("ping only: flags are off, so no country is asked", calls["exit"] == [])
check("ping only: ping is stored", app6.results[tags[0]][0] == 50.0)

run((True, False, False))
check("flags only: ping is not measured", calls["ping"] == [BASE + DEAD], calls["ping"])
check("flags only: nothing is downloaded", calls["speed"] == [])
check("flags only: countries are learned", app6.exit_cc.get(vpn.okey(app6.outs[0])) == "NL")

run((False, True, True))
check("ping+speed without flags: no country request", calls["exit"] == [])

vpn.probe_ping, vpn.probe_exit, vpn.probe_speed = real_probes

# the view
for v in (app6.v_flags, app6.v_ping, app6.v_speed):
    v.set(True)
app6.update()
check("all on: the three columns", tuple(app6.tree.cget("displaycolumns")) == ("ping", "speed", "proto"), app6.tree.cget("displaycolumns"))
app6.v_flags.set(False)
app6.update()
check("flags off: rows have no images, the rest stays",
      all(not app6.tree.item(i, "image") for i in app6.tree.get_children())
      and tuple(app6.tree.cget("displaycolumns")) == ("ping", "speed", "proto"))
check("flags off: the setting is saved", app6.cfg["show_flags"] is False and app6.cfg["show_ping"] is True)
app6.state, app6.api, app6.current, app6.t0 = "on", ("x", "y"), tags[0], time.time()
app6.refresh_power()
check("flags off: no flag on the main button either", app6.power.flag is None)
app6.state, app6.api, app6.current = "off", None, ""
app6.v_flags.set(True)
app6.v_ping.set(False)
app6.update()
check("ping off: only the ping column goes away", tuple(app6.tree.cget("displaycolumns")) == ("speed", "proto")
      and all(app6.tree.item(i, "image") for i in app6.tree.get_children()))
app6.v_ping.set(True)
app6.v_speed.set(False)
app6.update()
check("speed off: only the speed column goes away", tuple(app6.tree.cget("displaycolumns")) == ("ping", "proto"))
check("button says what it will do", app6.test_btn.cget("text") == "Тест пинга")
app6.v_ping.set(False)
check("only flags on: the button offers to find countries", app6.test_btn.cget("text") == "Определить страны")
app6.v_flags.set(False)
check("everything off: columns = just the protocol", tuple(app6.tree.cget("displaycolumns")) == ("proto",))
app6.run_test()
check("nothing to measure: no test starts and the reason is shown",
      not app6.testing and "выключено всё" in app6.status.cget("text"), app6.status.cget("text"))
for v in (app6.v_flags, app6.v_ping, app6.v_speed):
    v.set(True)
check("back to full view: button text restored", app6.test_btn.cget("text") == "Тест скорости")

# the test measures around any VPN (sockets bound to the real adapter), so another VPN client running is no reason to doubt it
real_karing, real_worker = vpn.karing_running, app6._test_worker
vpn.karing_running = lambda: True
app6._test_worker = lambda *a, **k: None
app6.outs = app6.outs or [{"tag": "x", "type": "vless", "server": "1.2.3.4", "server_port": 443}]
app6.run_test()
check("another VPN client is running: the test starts and says nothing about inaccurate numbers",
      app6.testing and "неточн" not in app6.status.cget("text") and "Другой VPN" not in app6.status.cget("text"), app6.status.cget("text"))
app6.testing = False
app6.test_btn.config(text=app6.test_label())
vpn.karing_running, app6._test_worker = real_karing, real_worker
check("pinging every server at once is the default (waiting for the dead ones is what takes the time)",
      vpn.PRO_DEFAULTS["test_parallel"] >= 32, vpn.PRO_DEFAULTS["test_parallel"])

# result messages follow what is on
for i, t in enumerate(tags):
    app6.results[t] = (50.0 + i, 10.0 + i)
    app6.alive[t] = True
app6.v_speed.set(False)
app6.test_done(None)
check("ping on, speed off: ranks by response time", app6.status.cget("text").startswith("Самый быстрый по отклику"), app6.status.cget("text"))
app6.v_speed.set(True)
app6.v_ping.set(False)
app6.test_done(None)
txt = app6.status.cget("text")
check("speed on, ping off: ranks by speed and does not quote a ping", txt.startswith("Самый быстрый:") and "мс" not in txt.split(")")[0], txt)
app6.v_ping.set(True)
app6.v_speed.set(False)
app6.results.clear()
app6.test_done(None)
check("nothing ranked: just says how many answered", app6.status.cget("text").startswith(f"Ответили {N} из {N}"), app6.status.cget("text"))

# the quiet footer
app6.v_speed.set(True)
check("settings are folded by default", app6.set_box.winfo_manager() == "" and app6.set_head.cget("fg") == vpn.MUTE)
app6.toggle_settings()
app6.update()
order = app6.sbx.master.pack_slaves()
check("the settings link opens the panel right below the content; the footer is first in the packing order (never the part that is cut)",
      app6.set_box.winfo_manager() == "pack" and app6.foot.master.pack_slaves()[0] is app6.foot
      and order.index(app6.sbx) < order.index(app6.set_box), [str(w) for w in order])
app6.toggle_log(True)
app6.update()
order = app6.sbx.master.pack_slaves()
check("with the log open too: content, settings, log, and the footer still first in the order",
      app6.foot.master.pack_slaves()[0] is app6.foot and order.index(app6.sbx) < order.index(app6.set_box) < order.index(app6.log_box))
app6.toggle_log(False)
app6.update()
app6.toggle_settings()
app6.update()
check("... and closes it again", app6.set_box.winfo_manager() == "")
app6.destroy()

# ---------------- tray: closing the window, the menu, the title ----------------
class FakeTray:
    def __init__(self):
        self.updates, self.notes, self.stopped = [], [], False

    def update(self, connected, title):
        self.updates.append((connected, title))

    def notify(self, message, title="VPN"):
        self.notes.append(message)

    def stop(self):
        self.stopped = True


app7 = vpn.App()
app7.withdraw()
pump(app7, lambda: len(app7.outs) >= 5, 10)
ft = FakeTray()
app7.tray, app7.tray_ok = ft, True
app7.deiconify()
app7.update()
app7.on_close()
check("X with a tray: the window hides, the app stays alive", app7.wm_state() == "withdrawn" and app7.winfo_exists())
check("... and the user is told once how to really quit", len(ft.notes) == 1 and app7.cfg["tray_hint_shown"] is True)
app7.show_window()
app7.update()
check("show_window brings it back", app7.wm_state() == "normal")
app7.on_close()
check("the hint is not repeated", len(ft.notes) == 1 and app7.wm_state() == "withdrawn")
calls7 = []
app7.toggle = lambda: calls7.append("toggle")
app7.toggle_from_tray()
check("Connect from the tray shows the window first (prompts need it) and toggles", app7.wm_state() == "normal" and calls7 == ["toggle"])
app7.state = "off"
check("tray title: off", app7.tray_title() == "VPN: выключено")
app7.state, app7.current = "connecting", ""
check("tray title: connecting", app7.tray_title() == "VPN: подключаю…")
tags7 = [o["tag"] for o in app7.outs]
app7.state, app7.current = "on", tags7[0]
check("tray title: connected + server name without the flag emoji",
      app7.tray_title() == "VPN: подключено, " + vpn.flags.strip_flag(tags7[0]), app7.tray_title())
app7.n = 1
app7.tick()
check("tick pushes state to the tray", bool(ft.updates) and ft.updates[-1] == (True, app7.tray_title()), ft.updates[-1:])
app7.state, app7.current = "off", ""
app7.cfg["tray_on_close"] = False
app7.on_close()
check("setting off: X quits for real and the tray icon is removed", ft.stopped is True)
try:
    app7.winfo_exists()
    gone = False
except Exception:
    gone = True
check("... the window is destroyed", gone)

app8 = vpn.App()
app8.withdraw()
check("no tray (FIMA_NO_TRAY / unsupported desktop): X quits as before", app8.tray_ok is False and app8.tray is None)
app8.on_close()
try:
    app8.winfo_exists()
    gone8 = False
except Exception:
    gone8 = True
check("... and the window is gone", gone8)

# ---------------- dialogs in the app's style, and a second launch ----------------
app9 = vpn.App()
app9.withdraw()
pump(app9, lambda: len(app9.outs) >= 5, 10)


def dialog_of(app):
    found = [w for w in app.winfo_children() if isinstance(w, vpn.Dialog)]
    return found[0] if found else None


def act_later(app, fn, delay=150):
    def go():
        d = dialog_of(app)
        if d is None:
            return app.after(50, go)
        fn(d)
    app.after(delay, go)


seen = {}
act_later(app9, lambda d: (seen.update(yes_bg=d.buttons[0].cget("bg"), no_bg=d.buttons[1].cget("bg"),
                                       stripe=d.winfo_children()[0].winfo_children()[0].cget("bg")), d.buttons[0].command()))
check("ask_yes_no: the first button means yes", vpn.ask_yes_no(app9, "Продолжить?") is True)
check("the default button is blue, the other is paper; a question has a blue stripe",
      seen.get("yes_bg") == vpn.BLUE and seen.get("no_bg") == vpn.PAPER and seen.get("stripe") == vpn.BLUE, seen)
act_later(app9, lambda d: d.buttons[1].command())
check("ask_yes_no: the second button means no", vpn.ask_yes_no(app9, "Продолжить?") is False)
act_later(app9, lambda d: (d.focus_force(), d.event_generate("<Escape>")))
check("Esc cancels a question", vpn.ask_yes_no(app9, "Продолжить?") is False)
act_later(app9, lambda d: (d.focus_force(), d.event_generate("<Return>")))
check("Enter takes the default (blue) button", vpn.ask_yes_no(app9, "Продолжить?") is True)
seen.clear()
act_later(app9, lambda d: (seen.update(stripe=d.winfo_children()[0].winfo_children()[0].cget("bg")), d.buttons[0].command()))
vpn.show_error(app9, "Ошибка конфига")
check("an error has a red stripe", seen.get("stripe") == vpn.RED, seen)
act_later(app9, lambda d: d.buttons[0].command())
vpn.show_info(app9, "Буфер обмена пуст.")
check("show_info / show_error return after OK", dialog_of(app9) is None)

shown = []
app9.show_window = lambda: shown.append(1)
check("a second launch reaches the running copy", vpn.signal_running_instance() is True)
pump(app9, lambda: bool(shown), 3)
check("... and that window is told to come forward", shown == [1], shown)
app9.destroy()
check("closing the app removes its own entry", not os.path.exists(vpn.INSTANCE_FILE))
check("with no running copy the signal says so", vpn.signal_running_instance() is False)

# ---- «Быстрейший из списка» and the user's own country ----
app10 = vpn.App()
def srv(tag, i):
    return {"tag": tag, "type": "vless", "server": f"h{i}.example", "server_port": 443}
app10.outs = [srv("🇷🇺 Россия", 0), srv("Обход глушилок [WS 5]", 1), srv("netherlands #5", 2), srv("Германия", 3)]
app10.exit_cc = {}
app10.tree.delete(*app10.tree.get_children())
app10.tree.insert("", "end", iid="auto", text=vpn.AUTO_LABEL)
for i, o in enumerate(app10.outs):
    app10.tree.insert("", "end", iid=str(i), text=o["tag"])
all_tags = [o["tag"] for o in app10.outs]
app10.home_cc = None
check("home unknown: nothing is passed over", app10.skip_cc() is None and app10.auto_pool() == all_tags)
app10.set_home("RU")
check("in Russia: servers named Россия are passed over by «Быстрейший из списка»",
      app10.skip_cc() == "RU" and app10.is_home_exit(app10.outs[0]) and app10.auto_pool() == all_tags[1:], app10.auto_pool())
check("... the choice is saved for the next start", json.load(open(vpn.SETTINGS, encoding="utf-8")).get("home_cc") == "RU")
app10.exit_cc[vpn.okey(app10.outs[1])] = "RU"   # a server with a foreign name that really exits in Russia
app10.exit_cc[vpn.okey(app10.outs[0])] = "DE"   # a server named Россия that really exits in Germany
check("the real exit decides, not the name",
      app10.is_home_exit(app10.outs[1]) and not app10.is_home_exit(app10.outs[0]), app10.auto_pool())
check("... and the auto group follows it", app10.auto_pool() == [all_tags[0], all_tags[2], all_tags[3]], app10.auto_pool())
app10.paint_rows()
check("skipped rows are muted, the rest are plain",
      app10.tree.item("1", "tags") == ("home",) and not app10.tree.item("0", "tags") and not app10.tree.item("auto", "tags"),
      [app10.tree.item(i, "tags") for i in ("auto", "0", "1", "2", "3")])
app10.mark_live("Германия")
check("the live row stays blue next to muted ones; muted ones stay muted",
      app10.tree.item("3", "tags") == ("live",) and app10.tree.item("1", "tags") == ("home",))
app10.mark_live("Обход глушилок [WS 5]")
check("a live server that is passed over by auto (picked by hand) shows as live",
      app10.tree.item("1", "tags") == ("live",))
app10.mark_live("")
for o in app10.outs:
    app10.exit_cc[vpn.okey(o)] = "RU"
check("only Russian servers: nothing to choose from, so all stay", app10.auto_pool() == all_tags)
app10.exit_cc.clear()
app10.set_home("DE")
check("outside Russia a Russian server is as good as any: not passed over",
      app10.skip_cc() is None and not app10.is_home_exit(app10.outs[0]) and app10.auto_pool() == all_tags)
check("... and its row is not muted", not app10.tree.item("0", "tags"))
app10.set_home("RU")
cfg = vpn.build_config(app10.outs, "AUTO", True, [], None, app10.auto_pool())
grp = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
check("the core's auto group holds only the servers auto may use",
      grp["type"] == "urltest" and grp["outbounds"] == all_tags[1:], grp)
cfg = vpn.build_config(app10.outs, "🇷🇺 Россия", True, [], None, app10.auto_pool())
grp = next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")
check("picked by hand, a Russian server is still available", grp["type"] == "selector" and grp["default"] == "🇷🇺 Россия"
      and "🇷🇺 Россия" in grp["outbounds"], grp)
cfg = vpn.build_config(app10.outs, "AUTO", True, [])
check("without a narrowed list the auto group is every server",
      next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")["outbounds"] == all_tags)
calls = []
real = (vpn.probe_ping, vpn.probe_exit)
vpn.probe_ping = lambda port: 50.0
vpn.probe_exit = lambda port: calls.append(port) or "NL"
app10.home_cc = "DE"
app10._probe(0, (False, True, False))
check("ping only, not in Russia: the exit country is not asked", calls == [])
app10.home_cc = "RU"
app10._probe(0, (False, True, False))
check("ping only, in Russia: the exit country is asked anyway (auto needs it)", len(calls) == 1)
vpn.probe_ping, vpn.probe_exit = real
vpn.write_json(os.path.join(TMP, "home_check.json"), vpn.build_home_config("Ethernet"))
chk = __import__("subprocess").run([vpn.CORE, "check", "-c", os.path.join(TMP, "home_check.json")], capture_output=True, text=True)
check("the throw-away core that asks for the home country has a valid config", chk.returncode == 0, chk.stderr[-200:])
# the setting that switches it off
app10.set_home("RU")
check("the setting is on by default", app10.cfg.get("skip_home") is True and app10.v_skip.get() is True and app10.skip_cc() == "RU")
app10.paint_rows()
check("... rows of Russian servers are grey", app10.tree.item("0", "tags") == ("home",), app10.tree.item("0", "tags"))
app10.v_skip.set(False)
check("switched off: nothing is passed over, even in Russia",
      app10.skip_cc() is None and app10.auto_pool() == all_tags and not app10.is_home_exit(app10.outs[0]))
check("... the rows go back to normal at once", not app10.tree.item("1", "tags") and not app10.tree.item("0", "tags"))
check("... and the choice is saved", json.load(open(vpn.SETTINGS, encoding="utf-8")).get("skip_home") is False)
calls.clear()
vpn.probe_ping = lambda port: 50.0
vpn.probe_exit = lambda port: calls.append(port) or "NL"
app10._probe(0, (False, True, False))
check("... and a ping-only test does not ask for the exit country", calls == [])
vpn.probe_ping, vpn.probe_exit = real
cfg = vpn.build_config(app10.outs, "AUTO", True, [], None, app10.auto_pool())
check("... the core's auto group is every server again",
      next(o for o in cfg["outbounds"] if o.get("tag") == "proxy")["outbounds"] == all_tags)
app10.v_skip.set(True)
# installing an update: once, and the window closes cleanly
real_apply = vpn.updater.apply_staged
app12 = vpn.App()
calls12 = []
vpn.updater.apply_staged = lambda info, relaunch: calls12.append(relaunch) or False
app12.pending = {"path": "x"}
app12.install_now()
check("install_now: when the helper cannot start, the program says so and stays", calls12 == [True] and app12.installing is False
      and "Не удалось" in app12.status.cget("text"))
vpn.updater.apply_staged = lambda info, relaunch: calls12.append(relaunch) or True
app12.install_now()
app12.install_now() if False else None
check("install_now: handed to the helper, the window closes", calls12 == [True, True] and app12.quitting is True and app12.installing is True)
try:
    app12.install_now()
    ignored = True
except Exception as e:  # noqa: BLE001
    ignored = repr(e)
check("install_now: a second click after that does nothing (no second helper, no error)", ignored is True and calls12 == [True, True], ignored)
vpn.updater.apply_staged = real_apply
check("switched back on: it works again", app10.skip_cc() == "RU" and app10.auto_pool() == all_tags[1:], app10.auto_pool())
app10.destroy()

# ---- resilience: the loop that watches the core, error dialogs, reconnect, connecting with a bad server in the list ----
vpn.RUNCFG = os.path.join(TMP, "run.json")          # never the real run.json of a connected program
vpn.CHECKCFG = os.path.join(TMP, "check.json")
vpn.TESTCFG = os.path.join(TMP, "test.json")
crashes = []
vpn.log_crash = lambda *a: crashes.append(a)        # never the real crash.log
vpn.ask_yes_no = lambda *a, **k: True               # a dialog in a test would wait for a click that never comes
vpn.show_error = lambda *a, **k: crashes.append(("dialog", a[1] if len(a) > 1 else ""))
app13 = vpn.App()
# 1. an error inside one tick does not end the loop
real_tail = app13.tail
app13.tail = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
app13.n = 1
app13._tick_id = None
app13.tick()
check("a tick that raises is logged and the loop is rescheduled", crashes and "boom" in repr(crashes[-1][1]) and app13._tick_id is not None, crashes)
app13.tail = real_tail
# 2. a repeating error shows one dialog, not a pile
shown13 = []
real_show = vpn.show_error
vpn.show_error = lambda *a, **k: shown13.append(a[1] if len(a) > 1 else "")
app13._last_err = 0.0
for _ in range(5):
    app13.report_callback_exception(RuntimeError, RuntimeError("again"), None)
check("an error that repeats shows one dialog within 30 s (all are logged)", len(shown13) == 1 and len(crashes) >= 6, (len(shown13), len(crashes)))
vpn.show_error = real_show
# 3. the core dies on its own after a good connection
class DeadProc:
    stderr = None
    def poll(self): return 1
    def terminate(self): pass
    def wait(self, *a): return 1
    def kill(self): pass
scheduled = []
real_after = app13.after
app13.after = lambda ms, fn=None, *a: scheduled.append((ms, getattr(fn, "__name__", "?"))) or "id"
vpn.karing_running = lambda: False
msgs = []
real_say = app13.say
app13.say = lambda text, err=False: msgs.append(text)
app13.proc, app13.state, app13.t0 = DeadProc(), "on", time.time() - 120
app13.fail()
check("a core that dies after a good connection is brought back (Windows)",
      (not vpn.IS_WIN) or (("reconnect" in [n for _, n in scheduled]) and app13.state == "off" and any("заново" in m for m in msgs)), (scheduled, msgs))
if vpn.IS_WIN:
    for _ in range(2):
        app13.proc, app13.state, app13.t0 = DeadProc(), "on", time.time() - 120
        app13.fail()
    scheduled.clear(); msgs.clear()
    app13.proc, app13.state, app13.t0 = DeadProc(), "on", time.time() - 120
    app13.fail()
    check("... but not more than 3 times in 10 minutes: then it says so and stops", not scheduled and any("Соединение прервалось" in m and "Нажми" in m for m in msgs), (scheduled, msgs))
    app13.restarts = []
    scheduled.clear(); msgs.clear()
    app13.proc, app13.state, app13.t0 = DeadProc(), "connecting", time.time()
    app13.fail()
    check("a core that dies while connecting (bad config) is not retried", not scheduled and any("Соединение прервалось" in m and "Нажми" in m for m in msgs), (scheduled, msgs))
    app13.restarts = []
    vpn.karing_running = lambda: True
    toggled13 = []
    app13.toggle = lambda: toggled13.append(1)
    app13.state = "off"
    app13.reconnect()
    check("reconnect does nothing while another VPN client is running", not toggled13 and any("другой VPN-клиент" in m for m in msgs), msgs)
    vpn.karing_running = lambda: False
    app13.reconnect()
    check("reconnect connects when nothing stands in the way", toggled13 == [1])
    del app13.toggle
app13.after = real_after
app13.say = real_say
# 4. connecting with a list that holds a server the core refuses
vpn.is_admin = lambda: True
class LiveProc:
    stderr = None
    def poll(self): return None
    def terminate(self): pass
    def wait(self, *a): return 0
    def kill(self): pass
started = []
vpn.start_core = lambda path: started.append(path) or LiveProc()
UUID13 = "11111111-2222-3333-4444-555555555555"
app13.outs = vpn.parse_text(f"vless://{UUID13}@203.0.113.9:443?type=tcp&security=reality&pbk=short&sid=zz&fp=chrome&sni=a.example#Sneaky\n"
                            "trojan://pass@203.0.113.2:443?sni=example.org#Good Trojan\nhysteria2://pw@203.0.113.3:8443?sni=example.com#Good HY2")
app13.tree.delete(*app13.tree.get_children())
app13.tree.insert("", "end", iid="auto", text=vpn.AUTO_LABEL)
for i, o in enumerate(app13.outs):
    app13.tree.insert("", "end", iid=str(i), text=o["tag"])
app13.select("auto")
app13.extra.delete(0, "end")
app13.extra.insert(0, "https://Mine.Example/page ??? мой.рф,x y!")
app13.state = "off"
app13.proc = None
app13.toggle()
cfg13 = json.load(open(vpn.RUNCFG, encoding="utf-8"))
tags13 = [o.get("tag") for o in cfg13["outbounds"]]
check("connect: a server the core refuses is left out, the others connect",
      started == [vpn.RUNCFG] and app13.state == "connecting" and "Sneaky" not in tags13 and "Good Trojan" in tags13 and "Good HY2" in tags13, (started, app13.state, tags13, crashes[-1] if crashes else None))
check("... and the user is told what was repaired", "Пропущено серверов с неверными данными: 1" in app13.status.cget("text") and "повреждён" in app13.status.cget("text"), app13.status.cget("text"))
dom = next(r for r in cfg13["route"]["rules"] if r.get("domain_suffix") and r.get("outbound") == "direct" and "mine.example" in r["domain_suffix"])
check("connect: the extra domains typed by the user are cleaned before they reach the core",
      dom["domain_suffix"][:2] == ["mine.example", "xn--i1afg.xn--p1ai"], dom["domain_suffix"])
app13.state = "off"
app13.proc = None

# 5. plain-language messages: what happened and what to do
dialogs = []
vpn.show_error = lambda parent, text: dialogs.append(text)
real_dialog = vpn.Dialog
opened_urls = []
vpn.open_url = lambda url: opened_urls.append(url) or True
class FakeDialog:
    def __init__(self, parent, text, buttons, kind="info", default=0, cancel=None, **k):
        dialogs.append((text, tuple(buttons), kind))
        self.result = 0
real_core = vpn.CORE
vpn.Dialog = FakeDialog
vpn.CORE = os.path.join(TMP, "no-core-here.exe")
app13.toggle()
text, buttons, kind = dialogs[-1]
check("no core file: the dialog says what happened and what to do, and offers the download",
      buttons == ("Скачать заново", "Закрыть") and kind == "error" and "антивирус" in text and "Скачай программу заново" in text
      and "ядр" not in text.lower() and opened_urls == [vpn.RELEASES_URL], (buttons, opened_urls, text[:80]))
check("... and the status line is plain too", "ядр" not in app13.status.cget("text").lower() and "антивирус" in app13.status.cget("text"))
vpn.CORE = real_core
vpn.Dialog = real_dialog
dialogs.clear()
real_check = vpn.core_check
vpn.core_check = lambda path: (False, "FATAL initialize outbound[0]: decode public_key")
app13.state = "off"
app13.toggle()
check("config refused for good: plain steps, technical reason kept below, no terminal codes",
      dialogs and "Что сделать" in dialogs[-1] and "Обновить" in dialogs[-1] and "Техническая причина: FATAL" in dialogs[-1]
      and "\x1b" not in dialogs[-1], dialogs[-1:] )
vpn.core_check = real_check
vpn.start_core = lambda path: (_ for _ in ()).throw(PermissionError("[WinError 5] Access is denied"))
dialogs.clear()
app13.state = "off"
app13.toggle()
check("core blocked from starting: antivirus / rights explained, reason kept", dialogs and "антивирус" in dialogs[-1] and "WinError 5" in dialogs[-1], dialogs[-1:])
vpn.start_core = lambda path: started.append(path) or LiveProc()
app13.state = "off"
app13.proc = None

# 5b. a proxy left behind in Windows by another program
asked = []
disabled = []
real_asks = (vpn.ask_yes_no, vpn.local_proxy_state, vpn.disable_system_proxy)
vpn.disable_system_proxy = lambda: disabled.append(1) or True
vpn.local_proxy_state = lambda: ("127.0.0.1:3067", False)
vpn.ask_yes_no = lambda parent, text, yes="Да", no="Нет": asked.append((text, yes, no)) or True
started.clear()
app13.state = "off"
app13.proc = None
app13.toggle()
check("dead system proxy: asked in plain words, the address named, one click to switch it off",
      asked and "127.0.0.1:3067" in asked[-1][0] and "не отвечает" in asked[-1][0] and asked[-1][1:] == ("Отключить прокси", "Оставить")
      and "ядр" not in asked[-1][0].lower(), asked[-1:])
check("... agreed: the proxy is switched off, the connection goes on and the user is told",
      disabled == [1] and started and "Прокси Windows отключён" in app13.status.cget("text"), (disabled, started, app13.status.cget("text")))
vpn.ask_yes_no = lambda parent, text, yes="Да", no="Нет": asked.append((text, yes, no)) or False
disabled.clear()
started.clear()
app13.state = "off"
app13.proc = None
app13.toggle()
check("... refused: left alone, the connection still goes on, the user is warned",
      not disabled and started and "не отвечает" in app13.status.cget("text") and "могут не открываться" in app13.status.cget("text"),
      (disabled, started, app13.status.cget("text")))
vpn.local_proxy_state = lambda: ("127.0.0.1:3067", True)
asked.clear()
started.clear()
app13.state = "off"
app13.proc = None
app13.toggle()
check("a working proxy of another program: no question, only a note that the browser uses it instead of the VPN",
      not asked and started and "другая программа" in app13.status.cget("text"), (asked, app13.status.cget("text")))
vpn.local_proxy_state = lambda: (None, False)
asked.clear()
started.clear()
app13.state = "off"
app13.proc = None
app13.toggle()
check("no system proxy: nothing is asked or said about it", not asked and started and "Windows" not in app13.status.cget("text"), app13.status.cget("text"))
vpn.ask_yes_no, vpn.local_proxy_state, vpn.disable_system_proxy = real_asks
vpn.ask_yes_no = lambda *a, **k: True
app13.state = "off"
app13.proc = None

# 5c. the window never grows past the screen: the footer with «Лог» and «Настройки» stays reachable

def frame_bottom(a):
    """Bottom edge of the window's frame on the screen."""
    a.update()
    return a.winfo_rooty() + a.winfo_height() + vpn.P(8)


def inside(a, screen_h):
    top, bottom = a.work_area()
    return a.winfo_y() >= top and frame_bottom(a) <= bottom + 1 and a.foot.winfo_rooty() + a.foot.winfo_height() <= a.winfo_rooty() + a.winfo_height()


for scr in (900, 768, 600):  # screens of any height: with everything open the window stays inside, the footer in view
    app13.work_area = lambda scr=scr: (0, scr)
    for opened in ("settings", "log", "both"):
        app13.toggle_settings(opened in ("settings", "both"))
        app13.toggle_log(opened in ("log", "both"))
        app13.update()
        check(f"a {scr}-px screen, {opened} open: the whole window frame and the footer are on the screen",
              inside(app13, scr), (app13.winfo_y(), frame_bottom(app13), app13.work_area(), app13.winfo_height()))
        check("... the window can be minimised and moved: its title bar is not above the screen", app13.winfo_y() >= app13.work_area()[0], app13.winfo_y())
app13.work_area = lambda: (0, 900)
app13.toggle_settings(True); app13.toggle_log(True)
app13.update()
check("content taller than the window: the body scrolls (a bar is shown) instead of growing the window",
      app13._bar_on and app13.winfo_height() <= app13.avail_height(), (app13._bar_on, app13.winfo_height(), app13.avail_height()))
app13.canvas.yview_moveto(1.0)
app13.update()
check("... and scrolled to the end the last row is visible, the footer never moves",
      app13.foot.winfo_rooty() + app13.foot.winfo_height() <= app13.winfo_rooty() + app13.winfo_height()
      and app13.log_box.winfo_rooty() + app13.log_box.winfo_height() <= app13.foot.winfo_rooty() + 2)
app13.canvas.yview_moveto(0)
app13.work_area = lambda: (0, 2000)
app13.toggle_settings(False); app13.toggle_log(False)
app13.toggle_settings(True)
app13.update()
# (a real window cannot be taller than the real screen, and a CI runner's screen is small: so the bar is judged by what
# the window could really get, not by the pretended 2000 px)
check("tall screen: the list has its normal size again and the bar is shown only if the content really does not fit",
      int(app13.tree.cget("height")) == 6 and app13._bar_on == (app13.body.winfo_reqheight() > app13.canvas.winfo_height() + 1),
      (app13.tree.cget("height"), app13._bar_on, app13.body.winfo_reqheight(), app13.canvas.winfo_height()))
app13.toggle_settings(False)
# a window dragged down so that its lower part is off the screen is pulled back when it grows
app13.work_area = lambda: (0, 900)
app13.geometry(f"+{app13.winfo_x()}+{app13.work_area()[1] - 200}")
app13.update()
app13.toggle_settings(True)
app13.update()
check("a window low on the screen is pulled up when the panel opens", inside(app13, 900), (app13.winfo_y(), frame_bottom(app13), app13.work_area()))
app13.toggle_settings(False)
del app13.work_area  # the real screen again
app13.fit_height()

check("the smallest size the window may be shrunk to never exceeds a small screen",
      app13.minsize()[1] <= max(app13.avail_height(), 1) or app13.minsize()[1] <= vpn.P(560), app13.minsize())

# 6. advanced settings: validation, effect on the config, fallback, the window, the double click
check("pro defaults are what the program always did",
      vpn.clean_pro(None)[0] == vpn.PRO_DEFAULTS and vpn.PRO_DEFAULTS["mixed_port"] == 2080 and vpn.PRO_DEFAULTS["tun_stack"] == "mixed")
old_style = vpn.build_config(app13.outs, "AUTO", True, [], None, None)
tun = next(i for i in old_style["inbounds"] if i["type"] == "tun")
check("the default config is the old one (stack, strict route, port, dns, log, auto-test timing)",
      tun["stack"] == "mixed" and tun["strict_route"] is True and next(i for i in old_style["inbounds"] if i["type"] == "mixed")["listen_port"] == 2080
      and old_style["log"]["level"] == "info" and old_style["dns"]["servers"][0]["server"] == "1.1.1.1"
      and old_style["dns"]["servers"][1]["server"] == "77.88.8.8"
      and next(o for o in old_style["outbounds"] if o.get("tag") == "proxy")["interval"] == "3m")
custom = vpn.build_config(app13.outs, "AUTO", True, [], None, None, None,
                          {"mixed_port": 3128, "tun_stack": "gvisor", "strict_route": False, "log_level": "warn",
                           "dns_remote": "dns.google", "dns_local": "8.8.8.8", "auto_url": "https://x.example/204",
                           "auto_interval": 7, "auto_tolerance": 120})
grp = next(o for o in custom["outbounds"] if o.get("tag") == "proxy")
check("advanced settings reach the config",
      next(i for i in custom["inbounds"] if i["type"] == "tun")["stack"] == "gvisor"
      and next(i for i in custom["inbounds"] if i["type"] == "tun")["strict_route"] is False
      and next(i for i in custom["inbounds"] if i["type"] == "mixed")["listen_port"] == 3128
      and custom["log"]["level"] == "warn" and custom["dns"]["servers"][0]["server"] == "dns.google"
      and custom["dns"]["servers"][1]["server"] == "8.8.8.8" and grp["url"] == "https://x.example/204"
      and grp["interval"] == "7m" and grp["tolerance"] == 120, grp)
good_outs = vpn.parse_text("trojan://pass@203.0.113.2:443?sni=example.org#T\nhysteria2://pw@203.0.113.3:8443?sni=example.com#H")
vpn.write_json(vpn.CHECKCFG, vpn.build_config(good_outs, "AUTO", True, [], None, None, None,
                                              {"mixed_port": 3128, "tun_stack": "gvisor", "strict_route": False, "log_level": "warn",
                                               "dns_remote": "dns.google", "dns_local": "8.8.8.8", "auto_url": "https://x.example/204",
                                               "auto_interval": 7, "auto_tolerance": 120}))
check("... and the real core accepts such a config", vpn.core_check(vpn.CHECKCFG)[0], vpn.core_check(vpn.CHECKCFG)[1][:120])
# a setting the core refuses must not stop the connection
app13.cfg["pro"] = {"tun_stack": "system", "mixed_port": 3333}
real_check = vpn.core_check
def picky(path):
    text = open(path, encoding="utf-8").read()
    return (False, "FATAL stack system is not supported here") if '"stack": "system"' in text else real_check(path)
vpn.core_check = picky
started.clear()
app13.state = "off"
app13.proc = None
app13.toggle()
cfg_now = json.load(open(vpn.RUNCFG, encoding="utf-8"))
check("connect: advanced settings the core refuses are dropped, the connection still comes up",
      started == [vpn.RUNCFG] and next(i for i in cfg_now["inbounds"] if i["type"] == "tun")["stack"] == "mixed"
      and "Расширенные настройки не подошли" in app13.status.cget("text"), (started, app13.status.cget("text")))
vpn.core_check = real_check
app13.cfg["pro"] = {}
app13.state = "off"
app13.proc = None

pw = app13.open_pro()
check("the advanced window opens, once", pw.winfo_exists() and app13.open_pro() is pw and app13.pro_win is pw)
pw.vars["mixed_port"].set("3128")
pw.vars["tun_stack"].set("gvisor")
pw.vars["strict_route"].set(False)
pw.vars["dns_remote"].set("dns.google")
check("applying valid values saves them (only what differs from the defaults) to the settings file",
      pw.apply() is True and app13.cfg["pro"] == {"mixed_port": 3128, "tun_stack": "gvisor", "strict_route": False, "dns_remote": "dns.google"}
      and json.load(open(vpn.SETTINGS, encoding="utf-8"))["pro"]["mixed_port"] == 3128, app13.cfg["pro"])
check("... and the program uses them", app13.pro()["mixed_port"] == 3128 and app13.pro()["tun_stack"] == "gvisor")
pw.vars["mixed_port"].set("80")
pw.vars["auto_url"].set("ftp://nope")
before = dict(app13.cfg["pro"])
check("a wrong value is refused, named, outlined in red and nothing is saved",
      pw.apply() is False and app13.cfg["pro"] == before and "Не сохранено" in pw.msg.cget("text") and "1024" in pw.msg.cget("text")
      and pw.boxes["mixed_port"].cget("bg") == vpn.RED and pw.boxes["auto_url"].cget("bg") == vpn.RED, pw.msg.cget("text"))
pw.vars["mixed_port"].set("4000")
check("typing again clears the red outline", pw.boxes["mixed_port"].cget("bg") == vpn.INK)
pw.reset()
check("«По умолчанию» puts the defaults into the fields without saving yet",
      pw.vars["mixed_port"].get() == "2080" and pw.vars["strict_route"].get() is True and app13.cfg["pro"] == before)
pw.apply()
check("... and Apply then stores nothing but defaults", app13.cfg["pro"] == {})
app13.state = "on"
pw.vars["test_top"].set("5")
pw.apply()
check("applying while connected says the change waits for the next connection",
      "следующем подключении" in pw.msg.cget("text") and "следующем подключении" in app13.status.cget("text"))
app13.state = "off"
pw.close()
check("closing the window forgets it; opening again makes a new one", app13.pro_win is None and app13.open_pro() is not pw)
app13.pro_win.close()
# the double click on «Настройки»
app13.set_open = False
app13.set_head.open = False
app13.update()
app13.set_head.single()
check("a single click waits a moment before it acts", app13.set_open is False)
end = time.time() + 2
while time.time() < end and not app13.set_open:
    app13.update()
    time.sleep(0.02)
check("... then toggles the settings panel", app13.set_open is True)
app13.set_head.twice()
app13.update()
check("a double click after that puts the panel back and opens the advanced window",
      app13.set_open is False and app13.pro_win is not None and app13.pro_win.winfo_exists())
app13.pro_win.close()
app13.set_head.single()
app13.set_head.twice()
time.sleep(vpn.DOUBLE_CLICK_MS / 1000 + 0.2)
app13.update()
check("a double click that comes in time cancels the single one: the panel did not flicker",
      app13.set_open is False and app13.pro_win is not None)
app13.pro_win.close()
check("the hint about the double click is in the settings panel",
      any("двойной щелчок" in w.cget("text") for w in app13.set_box.winfo_children() if isinstance(w, vpn.tk.Label)))
app13.destroy()

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
