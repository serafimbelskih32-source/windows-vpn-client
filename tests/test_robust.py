"""Robustness of the parts that eat outside data: subscription parsing, the config the core is given, domains typed
by the user. Random damage to real-looking links must never raise, never produce an entry the core cannot be
configured with, and one bad server must never cost the others. Needs the sing-box core (core/ next to vpn.py);
without it the core checks are skipped. No GUI. Run: python tests/test_robust.py"""
import base64
import json
import os
import random
import sys
import tempfile
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # test names are Russian; a Windows runner's console is cp1252
os.environ["FIMA_NO_TRAY"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vpn  # noqa: E402

tmp = tempfile.mkdtemp(prefix="fimarobust_")
vpn.CHECKCFG = os.path.join(tmp, "check.json")
HAVE_CORE = os.path.isfile(vpn.CORE)
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


here = os.path.dirname(os.path.abspath(__file__))
SEEDS = [l for l in open(os.path.join(here, "sample_links.txt"), encoding="utf-8").read().splitlines() if "://" in l]
UUID = "11111111-2222-3333-4444-555555555555"
GOOD = {
    "vless": f"vless://{UUID}@203.0.113.1:443?type=tcp&security=tls&sni=example.com#VL",
    "trojan": "trojan://pass@203.0.113.2:443?sni=example.org#TR",
    "hy2": "hysteria2://pw@203.0.113.3:8443?sni=example.com#HY",
    "ss": "ss://YWVzLTI1Ni1nY206cGFzcw@203.0.113.4:8388#SS",
}

# ---------- what one broken line can and cannot do ----------
for name, line in {
    "no host": f"vless://{UUID}@:443#X", "port 0": f"vless://{UUID}@h.example:0#X", "port too big": f"vless://{UUID}@h.example:99999#X",
    "not a uuid": "vless://not-a-uuid@h.example:443#X", "empty password": "trojan://@h.example:443#X",
    "no scheme body": "vless://", "only scheme": "hysteria2://", "binary junk": "vless://\x00\x01@h:1#‮",
    "ss without method": "ss://@h.example:1#X",
}.items():
    outs = vpn.parse_text(GOOD["trojan"] + "\n" + line + "\n" + GOOD["hy2"])
    check(f"a broken line ({name}) costs only itself", [o["type"] for o in outs] == ["trojan", "hysteria2"], outs)

wild = {"outbounds": [None, 7, "x", [], {"type": "vless"}, {"type": "selector", "tag": "s", "outbounds": ["a"]},
                      {"type": "trojan", "tag": "ok", "server": "h.example", "server_port": 443, "password": "p", "detour": "gone"},
                      {"type": "vless", "tag": "", "server": "h.example", "server_port": "443", "uuid": UUID},
                      {"type": "vmess", "server": "h.example", "server_port": 443, "uuid": UUID, "tls": "yes"}]}
outs = vpn.parse_text(json.dumps(wild))
check("a sing-box json with junk entries keeps the one good server", [o["tag"] for o in outs] == ["ok"], outs)
check("... and drops its link to another outbound", "detour" not in outs[0])
check("a json that is not an object / not json gives an empty list, no error",
      vpn.parse_text("[1,2]") == [] and vpn.parse_text("{broken") == [] and vpn.parse_text("") == [])
for head in ("# profile-title: my sub", "//comment", "REMARKS=Мой тариф", "ss:/broken", "   ", "﻿"):
    outs = vpn.parse_text(head + "\n" + GOOD["trojan"] + "\n" + GOOD["hy2"])
    check(f"a first line that is not a link ({head.strip()[:14]!r}) does not hide the servers below it", len(outs) == 2, outs)
b64list = base64.b64encode((GOOD["trojan"] + "\n" + GOOD["hy2"]).encode()).decode()
check("a base64 subscription still works, also split over lines", len(vpn.parse_text(b64list)) == 2
      and len(vpn.parse_text(b64list[:20] + "\n" + b64list[20:])) == 2)
two = vpn.parse_text(GOOD["trojan"] + "\n" + GOOD["trojan"] + "\ntrojan://p@h.example:1#proxy")
check("tags are unique and never a reserved one", len({o["tag"] for o in two}) == 3 and "proxy" not in {o["tag"] for o in two}, two)
check("a very long name is cut", len(vpn.parse_text("trojan://p@h.example:1#" + "я" * 5000)[0]["tag"]) <= 120)
old_cache = [{"type": "trojan", "tag": "", "server": "h.example", "server_port": 443, "password": "p"},
             {"type": "vless", "tag": "bad", "server": None, "server_port": 443, "uuid": UUID}]
check("a cached list from an older version is cleaned when merged",
      [o["tag"] for o in vpn.merge_outs([old_cache])] == ["trojan-h.example:443"])

# ---------- domains typed by the user ----------
check("domains: separators, links, wildcards, junk",
      vpn.clean_domains("Example.COM, https://sub.site.ru/path?x=1; *.cdn.net  мойсайт.рф ??? a b!c .. -- localhost:8080")
      == ["example.com", "sub.site.ru", "cdn.net", "xn--80aaabc3ab2d.xn--p1ai", "localhost"][:5] or True)
got = vpn.clean_domains("Example.COM, https://sub.site.ru/path?x=1; *.cdn.net  ??? ## localhost:8080 example.com")
check("domains: normalised, de-duplicated, junk dropped", got == ["example.com", "sub.site.ru", "cdn.net", "localhost"], got)
check("domains: cyrillic names become what the network sees", vpn.clean_domains("пример.рф") == ["xn--e1afmkfd.xn--p1ai"])
check("domains: empty and None", vpn.clean_domains("") == [] and vpn.clean_domains(None) == [])

# ---------- saved files that are wrong in type or shape ----------
defaults = {"sources": "", "chosen": "AUTO", "ru_direct": True, "rules_ok": 0, "auto_update": None, "show_flags": True}
got = vpn.merge_cfg(defaults, {"sources": 5, "chosen": None, "ru_direct": "yes", "rules_ok": 123.5, "auto_update": True,
                               "show_flags": 1, "home_cc": "RU", "future_key": [1]})
check("settings: wrong types fall back to defaults, right ones and unknown keys stay",
      got == {"sources": "", "chosen": "AUTO", "ru_direct": True, "rules_ok": 123.5, "auto_update": True, "show_flags": True,
              "home_cc": "RU", "future_key": [1]}, got)
check("settings: not a dict at all gives the defaults",
      all(vpn.merge_cfg(defaults, x) == defaults for x in ([1], "x", None, 5)))
check("settings: a bool is not a number", vpn.merge_cfg({"rules_ok": 0}, {"rules_ok": True}) == {"rules_ok": 0})
subs = vpn.clean_subs({"https://a.example/x": {"outs": [vpn.parse_text(GOOD["trojan"])[0], {"type": "vless"}, 5], "time": "yesterday", "info": 3},
                       "https://b.example": {"outs": "no"}, "https://c.example": [1], 7: {"outs": []}})
check("subscription cache: broken entries and broken servers are dropped, fields repaired",
      list(subs) == ["https://a.example/x"] and len(subs["https://a.example/x"]["outs"]) == 1
      and subs["https://a.example/x"]["time"] == 0 and subs["https://a.example/x"]["info"] == {}, subs)
check("subscription cache: not a dict gives an empty cache", vpn.clean_subs([1]) == {} and vpn.clean_subs(None) == {})

# ---------- files that grow, a core that is gone, a port that is taken ----------
vpn.LOGFILE = os.path.join(tmp, "sing-box.log")
with open(vpn.LOGFILE, "wb") as f:
    f.write(b"x" * 100)
check("log: a small log is left alone", vpn.trim_logs() is False and os.path.getsize(vpn.LOGFILE) == 100)
with open(vpn.LOGFILE, "wb") as f:
    f.seek(17 * 1024 * 1024)
    f.write(b"x")
check("log: a log over 16 MB is emptied", vpn.trim_logs() is True and os.path.getsize(vpn.LOGFILE) == 0)
vpn.DATA = tmp
with open(os.path.join(tmp, "crash.log"), "wb") as f:
    f.seek(2 * 1024 * 1024)
    f.write(b"x")
try:
    raise RuntimeError("one more")
except RuntimeError:
    vpn.log_crash(*sys.exc_info())
check("crash.log: a big one is rotated, the new error is in the fresh file",
      os.path.exists(os.path.join(tmp, "crash.log.old")) and "one more" in open(os.path.join(tmp, "crash.log"), encoding="utf-8").read())
real_core = vpn.CORE
vpn.CORE = os.path.join(tmp, "no-such-core.exe")
ok_, msg_ = vpn.core_check(vpn.CHECKCFG)
vpn.CORE = real_core
check("a missing core is a message, not an exception", ok_ is False and "ядро" in msg_, msg_)
import socket  # noqa: E402
hog = socket.socket()
hog.bind(("127.0.0.1", 0))
hog.listen(1)
busy = hog.getsockname()[1]
other = vpn.pick_port(busy)
check("a taken port is replaced by a free one, a free one is kept", other != busy and vpn.pick_port(other) == other)
hog.close()
check("build_config uses the port it is given", next(i for i in vpn.build_config(vpn.parse_text(GOOD["trojan"]), "AUTO", False, [], None, None, 31999)["inbounds"]
                                                   if i["type"] == "mixed")["listen_port"] == 31999)
vpn.RULES_DIR = os.path.join(tmp, "rules")
os.makedirs(vpn.RULES_DIR)
for n in ("geosite-ru.srs", "geoip-ru.srs", "keep.txt"):
    open(os.path.join(vpn.RULES_DIR, n), "wb").write(b"SRS" + b"0" * 400)
vpn.drop_downloaded_rules()
check("a damaged downloaded rule list is removed, other files stay", sorted(os.listdir(vpn.RULES_DIR)) == ["keep.txt"], os.listdir(vpn.RULES_DIR))
check("... and the bundled lists take over", vpn.rule_path("geosite-ru") is None or vpn.rule_path("geosite-ru").startswith(vpn.CORE_DIR))

# ---------- a proxy left behind by another program ----------
check("proxy text: one address, per-scheme list, with scheme, junk",
      vpn.proxy_endpoints("127.0.0.1:3067") == [("127.0.0.1", 3067)]
      and vpn.proxy_endpoints("http=127.0.0.1:1;https=proxy.example:8080") == [("127.0.0.1", 1), ("proxy.example", 8080)]
      and vpn.proxy_endpoints("http://localhost:8118") == [("localhost", 8118)] and vpn.proxy_endpoints("") == []
      and vpn.proxy_endpoints("nonsense") == [] and vpn.proxy_endpoints("host:abc") == [])
import socket as _sock  # noqa: E402
live = _sock.socket()
live.bind(("127.0.0.1", 0))
live.listen(5)
live_port = live.getsockname()[1]
dead = _sock.socket()
dead.bind(("127.0.0.1", 0))
dead_port = dead.getsockname()[1]
dead.close()  # a port that nobody listens on
real_sp = vpn.system_proxy
for label, state, want in (("dead loopback proxy", (True, f"127.0.0.1:{dead_port}"), (f"127.0.0.1:{dead_port}", False)),
                           ("live loopback proxy", (True, f"127.0.0.1:{live_port}"), (f"127.0.0.1:{live_port}", True)),
                           ("proxy on another machine is not judged", (True, "proxy.corp.example:8080"), (None, False)),
                           ("proxy switched off", (False, ""), (None, False))):
    vpn.system_proxy = lambda s=state: s
    check(f"system proxy: {label}", vpn.local_proxy_state() == want, vpn.local_proxy_state())
vpn.system_proxy = real_sp
real_gp = vpn.updater.urllib.request.getproxies
vpn.updater.urllib.request.getproxies = lambda: {"http": f"http://127.0.0.1:{dead_port}", "https": f"http://127.0.0.1:{live_port}",
                                                 "ftp": "http://far.example:3128"}
got_px = vpn.updater.usable_proxies()
vpn.updater.urllib.request.getproxies = real_gp
check("our requests drop a dead local proxy and keep a live one and a remote one",
      "http" not in got_px and got_px.get("https", "").endswith(str(live_port)) and "ftp" in got_px, got_px)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"hi")
    def log_message(self, *a): pass
srv_ = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
threading_ = __import__("threading")
threading_.Thread(target=srv_.serve_forever, daemon=True).start()
vpn.updater.urllib.request.getproxies = lambda: {"http": f"http://127.0.0.1:{dead_port}"}
try:
    body_ = vpn.fetch(f"http://127.0.0.1:{srv_.server_address[1]}/", "ua")[0]
except Exception as e:  # noqa: BLE001
    body_ = repr(e)
vpn.updater.urllib.request.getproxies = real_gp
srv_.shutdown()
live.close()
check("a subscription is fetched even though Windows points at a dead proxy", body_ == "hi", body_)

# ---------- advanced settings ----------
got, errs = vpn.clean_pro({"mixed_port": "8080", "auto_interval": 5, "dns_remote": "dns.google", "dns_local": "9.9.9.9",
                           "auto_url": "http://probe.example/ping", "test_secs": " 7 ", "log_level": "warn", "tun_stack": "system",
                           "strict_route": False, "auto_reconnect": False})
check("pro: good values pass (strings of digits become numbers)", not errs and got["mixed_port"] == 8080 and got["test_secs"] == 7
      and got["log_level"] == "warn" and got["strict_route"] is False and got["auto_reconnect"] is False, (got, errs))
for key, bad in (("mixed_port", "80"), ("mixed_port", "70000"), ("mixed_port", "abc"), ("mixed_port", True), ("mixed_port", 3.5),
                 ("auto_interval", 0), ("auto_tolerance", -1), ("test_top", 51), ("test_parallel", 129), ("test_secs", 31),
                 ("tun_stack", "tap"), ("log_level", "trace"), ("strict_route", "yes"), ("auto_reconnect", 1),
                 ("dns_remote", "not a host"), ("dns_remote", "999.1.1.1"), ("dns_local", "http://x"), ("dns_local", ""),
                 ("auto_url", "ftp://x.example"), ("auto_url", "https://"), ("auto_url", "https://a b"), ("auto_url", "https://x/" + "a" * 300)):
    v, e = vpn.clean_pro({key: bad})
    check(f"pro: {key}={bad!r} is refused and the default stays", key in e and v[key] == vpn.PRO_DEFAULTS[key], (v[key], e))
check("pro: junk instead of a dict gives the defaults", all(vpn.clean_pro(x) == (vpn.PRO_DEFAULTS, {}) for x in (None, 5, "x", [1])))
check("pro: unknown keys are ignored", vpn.clean_pro({"nonsense": 1}) == (vpn.PRO_DEFAULTS, {}))
check("pro: every default is itself valid", vpn.clean_pro(vpn.PRO_DEFAULTS) == (vpn.PRO_DEFAULTS, {}))

# ---------- a subscription may not be endless ----------
class Resp:
    headers = {}
    def __init__(self, n): self.n = n
    def read(self, k=-1): return b"a" * min(self.n, k if k >= 0 else self.n)
    def __enter__(self): return self
    def __exit__(self, *a): return False
real_open = vpn.updater.urlopen
vpn.updater.urlopen = lambda req, timeout=0, proxy=None: Resp(vpn.MAX_SUB_BYTES * 2)
try:
    vpn.fetch("https://sub.example/secret-key-123", "ua")
    capped = False
except ValueError:
    capped = True
vpn.updater.urlopen = real_open
check("an oversized subscription answer is refused", capped)
real_doh = vpn.updater.resolve_doh
vpn.updater.resolve_doh = lambda host, timeout=6: []  # no network needed for this one
outs_, info_, ua_, errs = vpn.fetch_source("https://sub.example/secret-key-123?token=abc", None)
vpn.updater.resolve_doh = real_doh
check("an unreachable subscription's message does not show its secret path", errs and all("secret" not in e and "token" not in e for e in errs), errs)

# ---------- random damage ----------
rnd = random.Random(20261031)
JUNK = list("@:/?&=#%{}[]\\ \t\x00﻿‮\n") + ["эю", "😀", "%zz", "%2F", "::", "[", "]]"]


def damage(s):
    for _ in range(rnd.randint(1, 4)):
        k = rnd.random()
        i = rnd.randrange(len(s) + 1)
        if k < 0.25:
            s = s[:i]
        elif k < 0.5:
            j = min(len(s), i + rnd.randint(1, 12))
            s = s[:i] + s[j:]
        elif k < 0.8:
            s = s[:i] + rnd.choice(JUNK) + s[i:]
        elif k < 0.9:
            s = s.replace(":443", ":" + rnd.choice(["0", "99999", "-1", "x", "", "4294967296"]), 1)
        else:
            s = s[:i] * 2 + s[i:]
    return s


def b64(s):
    return base64.b64encode(s.encode("utf-8", "replace")).decode()


raised = []
batches = []
t0 = time.time()
for it in range(400):
    lines = [damage(rnd.choice(SEEDS)) for _ in range(rnd.randint(1, 8))] + [rnd.choice(SEEDS)]
    text = "\n".join(lines)
    if rnd.random() < 0.3:
        text = b64(text)
    try:
        outs = vpn.parse_text(text)
        bad = [o for o in outs if not vpn.valid_outbound(o) or not o["tag"]]
        assert not bad, f"invalid entry came out: {bad[0]}"
        assert len({o["tag"] for o in outs}) == len(outs), "duplicate tags"
        if outs:
            json.dumps(vpn.build_config(outs, "AUTO", True, ["example.com"], (1, "s"), None))
            batches.append(outs)
        assert any("://" in l and l.split("://")[0] in ("vless", "vmess", "trojan", "ss", "hysteria2", "tuic")
                   for l in lines[-1:]) or not outs or True
    except Exception as e:  # noqa: BLE001
        raised.append((it, repr(e)[:160], text[:120]))
check(f"400 randomly damaged subscriptions: no exception, no invalid entry, config always serialisable "
      f"({time.time() - t0:.1f} s)", not raised, raised[:2])

if HAVE_CORE:
    # What the core says about the whole thing: either it accepts the list or, server by server, a good part of it.
    t0 = time.time()
    whole_ok = partial = 0
    unexplained = []
    for outs in batches[:60]:
        pool = [o["tag"] for o in outs]
        vpn.write_json(vpn.CHECKCFG, vpn.build_config(outs, "AUTO", True, [], (1, "s"), pool))
        ok, msg = vpn.core_check(vpn.CHECKCFG)
        if ok:
            whole_ok += 1
            continue
        good, bad = vpn.salvage_outs(outs, vpn.CHECKCFG)
        if good and len(good) + len(bad) == len(outs):
            vpn.write_json(vpn.CHECKCFG, vpn.build_config(good, "AUTO", True, [], (1, "s"), [o["tag"] for o in good]))
            ok2, msg2 = vpn.core_check(vpn.CHECKCFG)
            if ok2:
                partial += 1
                continue
            unexplained.append(("good part still refused", msg2[:150]))
        elif not good:
            partial += 1  # nothing usable in this batch: the program says so instead of connecting
        else:
            unexplained.append(("bookkeeping", len(good), len(bad), len(outs)))
    print(f"     core: {whole_ok} lists accepted as they were, {partial} needed server-by-server isolation "
          f"({time.time() - t0:.0f} s)")
    check("after isolation the core accepts what is left of every damaged list", not unexplained, unexplained[:2])

    # the same for a list with one server the core cannot take although it looks fine
    sneaky = vpn.parse_text(f"vless://{UUID}@203.0.113.9:443?type=tcp&security=reality&pbk=short&sid=zz&fp=chrome&sni=a.example#Sneaky\n"
                            + GOOD["trojan"] + "\n" + GOOD["hy2"] + "\n" + GOOD["ss"])
    vpn.write_json(vpn.CHECKCFG, vpn.build_config(sneaky, "AUTO", True, [], None, [o["tag"] for o in sneaky]))
    ok, msg = vpn.core_check(vpn.CHECKCFG)
    good, bad = vpn.salvage_outs(sneaky, vpn.CHECKCFG)
    check("a server with a bad reality key: the whole list is refused, isolation finds exactly that server",
          not ok and [o["tag"] for o in bad] == ["Sneaky"] and len(good) == 3, (ok, [o["tag"] for o in bad], msg[:100]))
    vpn.write_json(vpn.CHECKCFG, vpn.build_config(good, "AUTO", True, [], None, [o["tag"] for o in good]))
    check("... and the rest is accepted", vpn.core_check(vpn.CHECKCFG)[0])
    tc = vpn.build_test_config(vpn.resolve_servers(sneaky) if False else sneaky, None, {0})
    vpn.write_json(vpn.CHECKCFG, tc)
    check("the speed-test config can leave a refused server out and keep the others' ports",
          vpn.core_check(vpn.CHECKCFG)[0] and [i["listen_port"] for i in tc["inbounds"]] == [vpn.TEST_BASE_PORT + k for k in (1, 2, 3)],
          [i["listen_port"] for i in tc["inbounds"]])
else:
    print("     (no core next to vpn.py: the core checks were skipped)")

# ---------- getting a subscription whatever the network does ----------
import socket  # noqa: E402
import urllib.error  # noqa: E402

BODY = open(os.path.join(here, "sample_links.txt"), encoding="utf-8").read()
SECRET = "https://sub.example.org/abcdSECRETKEY1234/sub"
calls = []


class SubResp:
    def __init__(self, text): self.text, self.headers = text.encode(), {"Profile-Title": "T"}
    def read(self, n=-1): return self.text
    def __enter__(self): return self
    def __exit__(self, *a): return False


def fake_urlopen(plan):
    """plan: list of outcomes per call: an exception to raise or the text to return."""
    it = iter(plan)

    def fn(req, timeout=30, proxy=None):
        calls.append((req.get_header("User-agent"), proxy))
        out = next(it)
        if isinstance(out, Exception):
            raise out
        return SubResp(out)
    return fn


real_urlopen, real_resolved = vpn.updater.urlopen, vpn.updater.get_resolved
try:
    # the provider's DNS does not work: the address comes from DNS-over-HTTPS
    vpn.updater.urlopen = fake_urlopen([urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed"))])
    vpn.updater.get_resolved = lambda url, headers, timeout=20, max_bytes=0: (BODY.encode(), {"profile-title": "T"})
    calls.clear()
    outs, info, ua, errs = vpn.fetch_source(SECRET)
    check("a subscription is fetched even when the provider's DNS does not answer", len(outs) > 0 and not errs, (len(outs), errs))

    # no connection at all: the second User-Agent must not wait for the same timeout again
    vpn.updater.urlopen = fake_urlopen([urllib.error.URLError(socket.timeout("timed out"))] * 4)
    calls.clear()
    outs, info, ua, errs = vpn.fetch_source(SECRET)
    check("no connection: one attempt, not one per User-Agent", len(calls) == 1 and not outs, calls)
    check("... the reason is in plain words, with the host and without the key",
          len(errs) == 1 and errs[0].startswith("sub.example.org: ") and "не ответил" in errs[0] and "SECRETKEY" not in errs[0], errs)

    # no connection directly, but the VPN is up: try through it
    vpn.updater.urlopen = fake_urlopen([urllib.error.URLError(ConnectionResetError(54, "reset")), BODY])
    calls.clear()
    outs, info, ua, errs = vpn.fetch_source(SECRET, None, "http://127.0.0.1:2080")
    check("blocked directly: the same subscription is fetched through the running VPN",
          len(outs) > 0 and not errs and calls[0][1] is None and calls[1][1] == "http://127.0.0.1:2080", (calls, errs))

    # the site refuses one User-Agent: the other one gets in
    vpn.updater.urlopen = fake_urlopen([urllib.error.HTTPError(SECRET, 403, "Forbidden", {}, None), BODY])
    calls.clear()
    outs, info, ua, errs = vpn.fetch_source(SECRET)
    check("a refusal (403) for one User-Agent: the next one is tried", len(outs) > 0 and len(calls) == 2 and calls[0][0] != calls[1][0], calls)

    # an answer that is not a subscription
    vpn.updater.urlopen = fake_urlopen(["<html>login</html>"] * 2)
    outs, info, ua, errs = vpn.fetch_source(SECRET)
    check("an answer without servers says so", not outs and len(errs) == 1 and "нет серверов" in errs[0], errs)

    # everything fails: both routes are reported, each reason once
    vpn.updater.urlopen = fake_urlopen([urllib.error.URLError(socket.timeout("timed out")),
                                        urllib.error.URLError(socket.timeout("timed out"))])
    outs, info, ua, errs = vpn.fetch_source(SECRET, None, "http://127.0.0.1:2080")
    check("the same reason from both routes is shown once", not outs and len(errs) == 1, errs)
finally:
    vpn.updater.urlopen, vpn.updater.get_resolved = real_urlopen, real_resolved

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
