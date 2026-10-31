"""Changing the server of a running connection, with the real core, on this computer: three local SOCKS "servers" (two that
work and are told apart by their counters, one that is dead), a small web server as the target, and the core's config as
the program builds it (without the TUN adapter, so no administrator rights and nothing touches the real network).
Proves: the server changes without restarting the core, open connections move with it, nothing goes around the VPN
when a server does not answer, and the core's own check of a server works. Needs core/sing-box (skipped when absent).
Run: python tests/test_switch.py"""
import faulthandler; faulthandler.dump_traceback_later(200, exit=True)
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
os.environ.setdefault("FIMA_LANG", "ru")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import regions  # noqa: E402
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimaswitch_")
vpn.LOGFILE = os.path.join(TMP, "sing-box.log")
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


# ---------- the config the program builds ----------
def server(tag, port):
    return {"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": port, "version": "5"}


plain = [server("A", 1081), server("B", 1082), server("C", 1083)]
cfg = vpn.build_config(plain, "AUTO", True, [], (1, "s"), None, 2080, None, None, regions.NONE)
byt = {o["tag"]: o for o in cfg["outbounds"]}
check("every route ends in one selector called proxy", byt["proxy"]["type"] == "selector" and cfg["route"]["final"] == "proxy")
check("the selector offers every server and the 'pick the best' group", byt["proxy"]["outbounds"] == ["A", "B", "C", vpn.AUTO_TAG])
check("the group picks among the servers (urltest)", byt[vpn.AUTO_TAG]["type"] == "urltest" and byt[vpn.AUTO_TAG]["outbounds"] == ["A", "B", "C"])
check("AUTO starts on the group", byt["proxy"]["default"] == vpn.AUTO_TAG)
check("a server picked by hand starts on that server", vpn.build_config(plain, "B", True, [], None, None, 2080, None, None, regions.NONE)["outbounds"][-2]["default"] == "B")
check("... a name that is not in the list means the group, not an error",
      next(o for o in vpn.build_config(plain, "gone", True, [], None, None, 2080, None, None, regions.NONE)["outbounds"] if o["tag"] == "proxy")["default"] == vpn.AUTO_TAG)
check("open connections move to the new server when the selector changes", byt["proxy"].get("interrupt_exist_connections") is True)
one = next(o for o in vpn.build_config(plain[:1], "AUTO", True, [], None, None, 2080, None, None, regions.NONE)["outbounds"] if o["tag"] == "proxy")
check("a single server needs no group", one["outbounds"] == ["A"] and one["default"] == "A")
pool = next(o for o in vpn.build_config(plain, "AUTO", True, [], None, ["A", "C"], 2080, None, None, regions.NONE)["outbounds"] if o["tag"] == vpn.AUTO_TAG)
check("the group keeps to the servers it is allowed", pool["outbounds"] == ["A", "C"])
import sources  # noqa: E402
check("the group's name cannot be the name of a server", vpn.AUTO_TAG in sources.RESERVED_TAGS and "proxy" in sources.RESERVED_TAGS)
check("a server called like the group is renamed", sources._unique_tags([{"type": "socks", "tag": vpn.AUTO_TAG, "server": "x", "server_port": 1}])[0]["tag"] != vpn.AUTO_TAG)

if not os.path.isfile(vpn.CORE):
    print("     (no core next to vpn.py: the live checks were skipped)")
    print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
    sys.exit(1 if fails else 0)

# ---------- the target and the "servers" ----------
hits = {"web": 0}


class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/hold":  # an answer that takes a while: a connection that is open while the server changes
            time.sleep(6)
        elif self.server.counted:
            hits["web"] += 1
        body = b"" if self.path == "/204" else b"the target"
        self.send_response(204 if self.path == "/204" else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:  # the connection was closed under the answer: the point of one of the checks
            pass

    def log_message(self, *a):
        pass


def start_web(counted):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Web)
    srv.daemon_threads = True
    srv.counted = counted
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


web, probe_web = start_web(True), start_web(False)  # the target; and what the "pick the best" group measures, which must not be counted
WPORT, PPORT = web.server_address[1], probe_web.server_address[1]


class Socks:
    """A minimal SOCKS5 server that counts the connections it was asked to make."""
    def __init__(self):
        self.count = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            c.settimeout(10)
            head = c.recv(2)
            c.recv(head[1])
            c.sendall(b"\x05\x00")
            req = c.recv(4)
            if req[3] == 1:
                host = socket.inet_ntoa(c.recv(4))
            elif req[3] == 3:
                host = c.recv(c.recv(1)[0]).decode()
            else:
                return
            port = int.from_bytes(c.recv(2), "big")
            up = socket.create_connection((host, port), 5)
            if port == WPORT:  # only what goes to the target counts, not the group's own health checks
                self.count += 1
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            c.settimeout(None)

            def pipe(a, b):
                try:
                    while True:
                        d = a.recv(65536)
                        if not d:
                            break
                        b.sendall(d)
                except OSError:
                    pass
                finally:
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            threading.Thread(target=pipe, args=(up, c), daemon=True).start()
            pipe(c, up)
        except Exception:  # noqa: BLE001
            try:
                c.close()
            except OSError:
                pass


def free():
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


A, B = Socks(), Socks()
dead_port = free()  # nobody listens here
outs = [server("🇩🇪 A", A.port), server("🇳🇱 B", B.port), server("dead", dead_port)]
API = (free(), "s3cret")
MIXED = free()
cfg = vpn.build_config(outs, "🇩🇪 A", True, [], API, ["🇩🇪 A", "🇳🇱 B"], MIXED, {"auto_url": f"http://127.0.0.1:{PPORT}/204", "auto_interval": 1}, None, regions.NONE)
cfg["inbounds"] = [i for i in cfg["inbounds"] if i["type"] != "tun"]  # no adapter: nothing here may touch the real network
cfg["route"]["rules"] = [r for r in cfg["route"]["rules"] if not r.get("ip_is_private")]  # the target is on loopback: it must go the way every address goes
check("the test sends even a loopback target through the selector (nothing is allowed to go direct)",
      cfg["route"]["final"] == "proxy" and not any(r.get("outbound") == "direct" for r in cfg["route"]["rules"]))
cpath = os.path.join(TMP, "run.json")
vpn.write_json(cpath, cfg)
ok, msg = vpn.core_check(cpath)
check("the real core accepts the config with the selector and the group", ok, msg[-300:])

proc = None
try:
    import subprocess
    proc = subprocess.Popen([vpn.CORE, "run", "-c", cpath], cwd=TMP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=vpn.NOWIN)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", MIXED), 0.3).close()
            break
        except OSError:
            time.sleep(0.2)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{MIXED}"}))

    def fetch(path="/", timeout=8):
        """Through the core, as an application would: the body, or None when nothing came."""
        try:
            return opener.open(f"http://127.0.0.1:{WPORT}{path}", timeout=timeout).read()
        except Exception:  # noqa: BLE001
            return None

    check("the core answers its local API and starts on the server that was picked", vpn.current_server(API) == "🇩🇪 A", vpn.current_server(API))
    check("a request goes through the first server", fetch() == b"the target" and (A.count, B.count) == (1, 0), (A.count, B.count))

    # ----- a change of server, with the core running all the time -----
    pid = proc.pid
    t = time.time()
    ok, why = vpn.switch_server(API, "🇳🇱 B")
    took = time.time() - t
    check("the server changes (names with flags and spaces included)", ok and vpn.current_server(API) == "🇳🇱 B", (ok, why))
    check("... at once, not after a reconnect", took < 2.0, took)
    check("the next request goes through the new server and not the old one", fetch() == b"the target" and (A.count, B.count) == (1, 1), (A.count, B.count))
    check("the core was not restarted", proc.poll() is None and proc.pid == pid)

    # ----- an open connection moves with the change -----
    # a tunnel (what HTTPS is): the core cannot quietly repeat a request that is half done, so the application must be told
    ok, _ = vpn.switch_server(API, "🇩🇪 A")
    tunnel_before = A.count
    raw = socket.create_connection(("127.0.0.1", MIXED), 5)
    raw.settimeout(5)
    raw.sendall(f"CONNECT 127.0.0.1:{WPORT} HTTP/1.1\r\nHost: 127.0.0.1:{WPORT}\r\n\r\n".encode())
    established = raw.recv(4096)
    raw.sendall(b"GET /hold HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    time.sleep(1.0)
    check("(a tunnel was open through the old server)", established.startswith(b"HTTP/1.1 200") and A.count == tunnel_before + 1, (established[:20], A.count, tunnel_before))
    vpn.switch_server(API, "🇳🇱 B")
    raw.settimeout(3)
    try:
        got = raw.recv(4096)
    except socket.timeout:
        got = None  # still waiting: the connection was left on the old server
    except OSError:
        got = b""
    raw.close()
    check("a tunnel open on the old server is closed when the server changes, so the application opens a new one", got == b"", repr(got))

    # ----- the pick-the-best group is one more choice of the same selector -----
    ok, why = vpn.switch_server(API, vpn.AUTO_TAG)
    check("the 'pick the best' mode is switched on without a restart", ok and vpn.current_server(API, raw=True) == vpn.AUTO_TAG, (ok, why))
    time.sleep(1.5)
    now = vpn.current_server(API)
    check("... and current_server then names the server the group picked", now in ("🇩🇪 A", "🇳🇱 B"), now)
    before = (A.count, B.count)
    check("... requests work in that mode too", fetch() == b"the target" and (A.count + B.count) == sum(before) + 1)
    ok, _ = vpn.switch_server(API, "🇩🇪 A")
    check("and back to a server picked by hand", ok and vpn.current_server(API) == "🇩🇪 A" and vpn.current_server(API, raw=True) == "🇩🇪 A")

    # ----- a server that does not answer: no traffic at all, not a direct one -----
    ok, _ = vpn.switch_server(API, "dead")
    web_before, counts = hits["web"], (A.count, B.count)
    body = fetch(timeout=6)
    time.sleep(0.5)
    check("a request through a server that does not answer gets nothing", body is None, body)
    check("... and nothing reached the target around the VPN (nor through another server)", hits["web"] == web_before and (A.count, B.count) == counts, (hits, counts))
    ok, _ = vpn.switch_server(API, "🇩🇪 A")
    check("choosing a working server brings the traffic back, in the same core", ok and fetch() == b"the target" and proc.poll() is None)

    # ----- what cannot be done is said, not pretended -----
    ok, why = vpn.switch_server(API, "a server nobody has")
    check("a server the core does not have is refused with a reason", not ok and why, (ok, why))
    check("... and the connection stays where it was", vpn.current_server(API) == "🇩🇪 A" and fetch() == b"the target")
    ok, why = vpn.switch_server((API[0], "wrong"), "🇳🇱 B")
    check("the core's API wants its secret", not ok and vpn.current_server(API) == "🇩🇪 A", (ok, why))
    ok, why = vpn.switch_server((free(), "x"), "🇳🇱 B")
    check("no core, no answer: said so", not ok and why, (ok, why))

    # ----- the core's own check of a server -----
    d = vpn.server_delay(API, "🇩🇪 A", f"http://127.0.0.1:{PPORT}/204")
    check("the core measures a working server without switching to it", isinstance(d, (int, float)) and 0 < d < 3000 and vpn.current_server(API) == "🇩🇪 A", d)
    check("... and says None for the one that does not answer", vpn.server_delay(API, "dead", f"http://127.0.0.1:{PPORT}/204", 2000) is None)
    check("... and for one it does not have", vpn.server_delay(API, "nobody", f"http://127.0.0.1:{PPORT}/204", 2000) is None)
finally:
    vpn.stop_proc(proc)
    web.shutdown()
    probe_web.shutdown()

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
