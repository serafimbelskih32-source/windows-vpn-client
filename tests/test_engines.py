"""The servers the core cannot run by itself: the companion Xray (XHTTP, mKCP, VLESS encryption, an HTTP header on TCP)
and WireGuard as a sing-box endpoint. Config checks by the real core and the real Xray, and a whole chain on this
computer: sing-box -> SOCKS -> Xray client -> XHTTP -> Xray server -> a small web server. No outside network.
Needs core/sing-box and core/xray (skipped when absent). Run: python tests/test_engines.py"""
import faulthandler; faulthandler.dump_traceback_later(240, exit=True)
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ["FIMA_NO_TRAY"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import engines  # noqa: E402
import sources as S  # noqa: E402
import vpn  # noqa: E402

TMP = tempfile.mkdtemp(prefix="fimaengines_")
vpn.DATA = TMP
for name in ("RUNCFG", "TESTCFG", "TESTLOG", "CHECKCFG", "XRAYCFG", "XRAYLOG", "XRAYTESTCFG", "XRAYTESTLOG", "LOGFILE"):
    setattr(vpn, name, os.path.join(TMP, name.lower() + ".json"))
HAVE_CORE, HAVE_XRAY = os.path.isfile(vpn.CORE), os.path.isfile(vpn.XRAY)
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


U = "11111111-2222-3333-4444-555555555555"
PBK = "Y8bq6x0Q4s2v3m3pXw4m0hJq0kQy7Q3v1xk3nq0o3gE"
WGK = "mHk5Q0hcX0xx6dWjLrU2uHk3WqZ0eB0a1Jq0k3x0v1U="
LINKS = {
    "xhttp reality": f"vless://{U}@xh.example:443?type=xhttp&security=reality&pbk={PBK}&sid=ab&sni=www.m.com&fp=chrome&path=%2Fx&mode=stream-one#xhttp reality",
    "xhttp tls": f"vless://{U}@xt.example:443?type=xhttp&security=tls&sni=xt.example&alpn=h2&path=/t&host=cdn.example#xhttp tls",
    "mkcp": f"vless://{U}@kc.example:443?type=kcp&headerType=wechat-video&seed=s3&security=none#mkcp",
    "tcp http header": f"vless://{U}@th.example:80?type=tcp&headerType=http&host=a.com&path=/p#tcp-http",
    "vless encryption": f"vless://{U}@en.example:443?encryption=mlkem768x25519plus.native.0rtt.{PBK}&security=tls&sni=en.example&type=tcp#enc",
    "trojan xhttp": "trojan://pw@tx.example:443?type=xhttp&sni=tx.example&path=/tr#trojan xhttp",
    "vmess xhttp": "vmess://" + __import__("base64").b64encode(json.dumps({"v": "2", "ps": "vmess xhttp", "add": "vx.example", "port": "443", "id": U, "aid": "0", "net": "xhttp", "tls": "tls", "sni": "vx.example", "path": "/vm"}).encode()).decode(),
    "wireguard": f"wireguard://{WGK.replace('=', '%3D')}@wg.example:51820?publickey={WGK.replace('=', '%3D')}&address=10.0.0.2/32&reserved=1,2,3#wg",
    "naive": "naive+https://user:pw@nv.example:443#naive",
    "ssh": "ssh://root:pw@ssh.example:22#ssh",
    "quic transport": f"vless://{U}@qt.example:443?type=quic&security=tls&sni=qt.example#quic",
    "plain": f"vless://{U}@pl.example:443?type=ws&security=tls&sni=pl.example&path=/w#plain",
}
outs = S.parse_text("\n".join(LINKS.values()))
by = {o["tag"]: o for o in outs}
check("every kind of link above is a server", len(outs) == len(LINKS), [o["tag"] for o in outs])
xs = [o for o in outs if engines.is_xray(o)]
check("the seven that only Xray can run are Xray servers, the rest are not", len(xs) == 7 and not any(engines.is_xray(by[t]) for t in ("wg", "naive", "ssh", "quic", "plain")),
      [o["tag"] for o in xs])

# ---------- pure functions ----------
check("the protocol column names them", {engines.proto_label(by["xhttp reality"]), engines.proto_label(by["mkcp"]), engines.proto_label(by["enc"])} == {"XHTTP", "MKCP", "VLESS+"}
      and engines.proto_label(by["plain"]) is None, [engines.proto_label(o) for o in xs])
ports = {o["tag"]: 22000 + i for i, o in enumerate(xs)}
cfgx = engines.xray_config(outs, ports, log_path="x.log", nic="Ethernet")
check("the companion: one local SOCKS inbound and one rule per Xray server, nothing for the others",
      len(cfgx["inbounds"]) == len(xs) == len(cfgx["outbounds"]) == len(cfgx["routing"]["rules"])
      and all(i["listen"] == "127.0.0.1" and i["protocol"] == "socks" for i in cfgx["inbounds"])
      and sorted(i["port"] for i in cfgx["inbounds"]) == sorted(ports.values()), cfgx["inbounds"])
check("... every outbound is bound to the real adapter when asked (a test goes around any VPN)",
      all(ob["streamSettings"]["sockopt"]["interface"] == "Ethernet" for ob in cfgx["outbounds"]))
check("... and not otherwise", all("sockopt" not in (ob.get("streamSettings") or {}) for ob in engines.xray_config(outs, ports)["outbounds"]))
ob, ep = engines.to_singbox(outs, ports)
check("for the core an Xray server is a SOCKS server on its local port", {o["tag"]: o["server_port"] for o in ob if o["type"] == "socks"} == ports
      and all(o["server"] == "127.0.0.1" and o["version"] == "5" for o in ob if o["type"] == "socks"))
check("... WireGuard moves to endpoints with its keys, address, reserved bytes and a peer", len(ep) == 1 and ep[0]["tag"] == "wg" and ep[0]["address"] == ["10.0.0.2/32"]
      and ep[0]["peers"][0]["reserved"] == [1, 2, 3] and ep[0]["peers"][0]["public_key"] == WGK and ep[0]["peers"][0]["address"] == "wg.example", ep)
check("... an Xray server nobody serves is left out", all(o["tag"] != "xhttp reality" for o in engines.to_singbox(outs, {})[0]))
check("... and the others stay as they are", any(o["tag"] == "plain" for o in ob) and any(o["type"] == "naive" for o in ob))
resolved = engines.xray_with_address(by["xhttp reality"], "203.0.113.7")
check("an Xray server with its address replaced by an IP keeps the name TLS and REALITY check",
      resolved["settings"]["vnext"][0]["address"] == "203.0.113.7" and resolved["streamSettings"]["realitySettings"]["serverName"] == "www.m.com"
      and by["xhttp reality"]["xray"]["settings"]["vnext"][0]["address"] == "xh.example", resolved)
noname = {"type": "xray", "tag": "n", "server": "h.example", "server_port": 443, "xray": {"protocol": "vless", "settings": {"vnext": [{"address": "h.example", "port": 443, "users": [{"id": U}]}]},
                                                                                       "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {}}}}
check("... a name that was only implied (the address) is made explicit before it is replaced", engines.xray_with_address(noname, "1.2.3.4")["streamSettings"]["tlsSettings"]["serverName"] == "h.example")

# ---------- the real core and the real Xray look at the configs ----------
if HAVE_CORE:
    cfg = vpn.build_config(outs, "AUTO", True, [], None, None, 2080, None, ports)
    vpn.write_json(vpn.RUNCFG, cfg)
    ok, msg = vpn.core_check(vpn.RUNCFG)
    check("the core accepts a config with every kind of server (Xray ones, WireGuard endpoint, naive, SSH, QUIC transport)", ok, msg[-300:])
    check("... the tunnel's rules let the companion's own traffic out first", cfg["route"]["rules"][0] == {"process_name": ["xray.exe", "xray"], "outbound": "direct"})
    check("... and without an Xray server there is no such rule", not any("process_name" in r for r in vpn.build_config([by["plain"]], "AUTO", True, [])["route"]["rules"]))
    check("... a WireGuard server is an endpoint and is offered to auto mode", cfg["endpoints"][0]["tag"] == "wg" and "wg" in next(o for o in cfg["outbounds"] if o["tag"] == "proxy")["outbounds"])
    tc = vpn.build_test_config(outs, None, (), ports)
    vpn.write_json(vpn.TESTCFG, tc)
    check("the core accepts the test config of all of them", vpn.core_check(vpn.TESTCFG)[0], vpn.core_check(vpn.TESTCFG)[1][-200:])
    tc2 = vpn.build_test_config(outs, None, (), {})
    check("the test config leaves out Xray servers nobody serves, and keeps the others' ports",
          len(tc2["inbounds"]) == len(outs) - len(xs) and all(i["listen_port"] >= vpn.TEST_BASE_PORT for i in tc2["inbounds"]))
    good, bad = vpn.salvage_outs(outs)
    check("isolation tests an Xray server with a stand-in port and accepts it", len(good) == len(outs) and not bad, [o["tag"] for o in bad])
else:
    print("     (no core next to vpn.py: the core checks were skipped)")
if HAVE_XRAY:
    for name in ("xhttp reality", "xhttp tls", "mkcp", "tcp http header", "vless encryption", "trojan xhttp", "vmess xhttp"):
        o = S.parse_text(LINKS[name])[0]
        path = os.path.join(TMP, "one.json")
        vpn.write_json(path, engines.xray_config([o], {o["tag"]: 22100}))
        ok, msg = vpn.xray_check(path)
        check(f"Xray accepts the config of '{name}'", ok, msg[-200:])
    bad_o = dict(by["xhttp tls"], xray={"protocol": "vless", "settings": {"vnext": [{"address": "h", "port": 443, "users": [{"id": U}]}]}, "streamSettings": {"network": "nonsense"}})
    vpn.write_json(os.path.join(TMP, "bad.json"), engines.xray_config([bad_o], {bad_o["tag"]: 22101}))
    check("... and refuses a broken one", not vpn.xray_check(os.path.join(TMP, "bad.json"))[0])
else:
    print("     (no Xray next to vpn.py: the Xray checks were skipped)")

# ---------- the whole chain, on this computer ----------
if HAVE_CORE and HAVE_XRAY:
    class Web(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"reached the web server through XHTTP"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    web = ThreadingHTTPServer(("127.0.0.1", 0), Web)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    wport = web.server_address[1]

    def free():
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            return sk.getsockname()[1]
    sport = free()
    server = {"log": {"loglevel": "warning"},
              "inbounds": [{"listen": "127.0.0.1", "port": sport, "protocol": "vless", "settings": {"clients": [{"id": U}], "decryption": "none"},
                            "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {"path": "/xh", "mode": "auto"}}}],
              "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}  # a test server on loopback: new Xray blocks private targets otherwise
    spath = os.path.join(TMP, "server.json")
    json.dump(server, open(spath, "w"))
    sproc = subprocess.Popen([vpn.XRAY, "run", "-c", spath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=vpn.NOWIN)
    procs = [sproc]
    try:
        for _ in range(40):
            try:
                socket.create_connection(("127.0.0.1", sport), 0.2).close(); break
            except OSError:
                time.sleep(0.2)
        link = f"vless://{U}@127.0.0.1:{sport}?type=xhttp&security=none&path=/xh&mode=auto#chain test"
        o = S.parse_text(link)[0]
        proc, xp, note = vpn.launch_xray([o], free(), vpn.XRAYCFG, vpn.XRAYLOG)
        procs.append(proc)
        check("launch_xray starts the companion, which answers on the port it was given", proc is not None and set(xp) == {"chain test"} and not note, (xp, note))

        def socks_get(port):
            """A minimal SOCKS5 client: CONNECT to the web server, GET, read."""
            c = socket.create_connection(("127.0.0.1", port), 5)
            c.settimeout(8)
            c.sendall(b"\x05\x01\x00")
            assert c.recv(2) == b"\x05\x00"
            c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + wport.to_bytes(2, "big"))
            assert c.recv(10)[1] == 0
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = b""
            try:
                while True:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    head, sep, body = data.partition(b"\r\n\r\n")
                    n = [int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")]
                    if sep and n and len(body) >= n[0]:  # the answer is complete: no need to wait for the connection to close
                        break
            except OSError:
                pass
            c.close()
            return data
        got = socks_get(xp["chain test"]) if proc else b""
        check("a request through the companion's SOCKS port crosses XHTTP to the web server and back", b"reached the web server through XHTTP" in got, got[:80])

        # through sing-box as well: a local mixed port whose rule sends everything to that server
        tcfg = vpn.build_test_config([o], None, (), xp)
        vpn.write_json(vpn.TESTCFG, tcfg)
        core = subprocess.Popen([vpn.CORE, "run", "-c", vpn.TESTCFG], cwd=TMP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=vpn.NOWIN)
        procs.append(core)
        mport = vpn.TEST_BASE_PORT
        for _ in range(40):
            try:
                socket.create_connection(("127.0.0.1", mport), 0.2).close(); break
            except OSError:
                time.sleep(0.2)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{mport}"}))
        try:
            body = opener.open(f"http://127.0.0.1:{wport}/", timeout=10).read()
        except Exception as e:  # noqa: BLE001
            body = str(e).encode()
        check("... and the same through the core: sing-box -> SOCKS -> Xray -> XHTTP -> Xray -> web server", b"reached the web server through XHTTP" in body, body[:120])
        procs.remove(proc)
        vpn.stop_proc(proc)
        check("stopping the companion ends its process", proc.poll() is not None)
    finally:
        for pr in procs:
            vpn.stop_proc(pr)
        web.shutdown()
else:
    print("     (the chain test needs both the core and Xray: skipped)")

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
