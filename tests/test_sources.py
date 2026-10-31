"""Everything a user may paste or a provider may send, and what comes out of it: share links of every protocol, base64
lists, sing-box / Xray / Clash / SIP008 documents, "open in the app" links. No GUI, no network.
Run: python tests/test_sources.py"""
import base64
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import sources as S  # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


U = "11111111-2222-3333-4444-555555555555"
b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
b64u = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")  # noqa: E731


def one(link):
    outs, skipped = S.parse_text_ex(link)
    return (outs[0] if outs else None), dict(skipped)


# ---------- share links ----------
o, _ = one(f"vless://{U}@h.example:443?type=tcp&security=reality&pbk=KEY&sid=ab&sni=www.m.com&fp=chrome&flow=xtls-rprx-vision#🇩🇪 Берлин 1")
check("vless reality: name with emoji and Cyrillic, key, flow",
      o and o["tag"] == "🇩🇪 Берлин 1" and o["tls"]["reality"]["public_key"] == "KEY" and o["flow"] == "xtls-rprx-vision", o)
o, _ = one(f"vless://{U}@h.example:8443?type=ws&security=tls&host=cdn.example&path=%2Fws%3Fed%3D2048#ws")
check("vless ws+tls: host header, SNI from host, early data moved out of the path",
      o and o["transport"]["headers"]["Host"] == "cdn.example" and o["tls"]["server_name"] == "cdn.example"
      and o["transport"]["path"] == "/ws" and o["transport"]["max_early_data"] == 2048, o)
o, _ = one(f"vless://{U}@h.example:443?type=grpc&serviceName=svc&security=tls&sni=a.com#g")
check("vless grpc", o and o["transport"] == {"type": "grpc", "service_name": "svc"}, o)
o, _ = one(f"vless://{U}@h.example:443?type=httpupgrade&path=/u&host=a.com&security=tls#h")
check("vless httpupgrade", o and o["transport"]["type"] == "httpupgrade" and o["transport"]["path"] == "/u", o)
o, sk = one(f"vless://{U}@h.example:443?type=xhttp&security=reality&pbk=K&sid=ab&sni=a.com&fp=chrome&path=%2Fx&host=cdn.a.com&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#x")
check("vless xhttp is an Xray server: the whole Xray outbound is kept, with reality, path, host, mode and extra",
      o and o["type"] == "xray" and o["server"] == "h.example" and sk == {}
      and o["xray"]["streamSettings"]["network"] == "xhttp" and o["xray"]["streamSettings"]["realitySettings"]["publicKey"] == "K"
      and o["xray"]["streamSettings"]["xhttpSettings"] == {"path": "/x", "mode": "packet-up", "host": "cdn.a.com", "extra": {"xPaddingBytes": "100-1000"}}
      and o["xray"]["settings"]["vnext"][0]["users"][0]["id"] == U, o)
o, sk = one(f"vless://{U}@h.example:443?type=splithttp&security=tls&sni=a.com#old-name")
check("the old name of XHTTP (splithttp) is the same thing", o and o["type"] == "xray" and o["xray"]["streamSettings"]["network"] == "xhttp", o)
o, sk = one(f"vless://{U}@h.example:443?encryption=mlkem768x25519plus.native.0rtt.KEY&security=tls#e")
check("vless with its own encryption layer is an Xray server too (the key is kept)",
      o and o["type"] == "xray" and o["xray"]["settings"]["vnext"][0]["users"][0]["encryption"].startswith("mlkem768"), o)
o, sk = one(f"vless://{U}@h.example:443?type=kcp&headerType=wechat-video&seed=s3&security=none#k")
check("mKCP is an Xray server (header and seed kept)", o and o["type"] == "xray" and o["xray"]["streamSettings"]["kcpSettings"] == {"header": {"type": "wechat-video"}, "seed": "s3"}, o)
o, sk = one("trojan://pw@t.example:443?type=xhttp&sni=a.com&path=/t#tx")
check("trojan over XHTTP is an Xray server", o and o["type"] == "xray" and o["xray"]["protocol"] == "trojan" and o["xray"]["settings"]["servers"][0]["password"] == "pw", o)
o, sk = one(f"vless://{U}@h.example:443?type=tcp&headerType=http&host=a.com&path=/p#th")
check("TCP with an HTTP header is an Xray server", o and o["type"] == "xray" and o["xray"]["streamSettings"]["tcpSettings"]["header"]["type"] == "http", o)
o, sk = one(f"vless://{U}@h.example:443?type=quic&security=tls&sni=a.com#q")
check("the core's own QUIC transport is used, not skipped", o and o["type"] == "vless" and o["transport"] == {"type": "quic"}, o)
o, _ = one(f"vless://{U}@[2001:db8::1]:443?security=tls&sni=a.com#v6")
check("an IPv6 address", o and o["server"] == "2001:db8::1" and o["server_port"] == 443, o)
o, _ = one(f"  ​vless://{U}@h.example:443?security=tls#sp​ ")
check("zero-width marks and spaces around a link do not matter", o and o["tag"] == "sp" and o["server"] == "h.example", o)
o, _ = one(f"🔥 Лучший: vless://{U}@h.example:443?security=tls#hot")
check("words before a link are ignored", o and o["tag"] == "hot", o)

vm = {"v": "2", "ps": "VM ws", "add": "vm.example", "port": "443", "id": U, "aid": "0", "scy": "auto", "net": "ws",
      "type": "none", "host": "cdn.vm.example", "path": "/p", "tls": "tls", "sni": ""}
o, _ = one("vmess://" + b64(json.dumps(vm)))
check("vmess (base64 JSON): ws, tls, host, port as text", o and o["tag"] == "VM ws" and o["server_port"] == 443
      and o["transport"]["headers"]["Host"] == "cdn.vm.example" and o["tls"]["server_name"] == "cdn.vm.example", o)
o, _ = one("vmess://" + b64u(json.dumps(vm)) + "#ignored")
check("vmess with url-safe base64 and no padding", o and o["server"] == "vm.example", o)
o, sk = one("vmess://" + b64(json.dumps(dict(vm, net="kcp", type="srtp"))))
check("vmess over mKCP is an Xray server", o and o["type"] == "xray" and o["xray"]["protocol"] == "vmess"
      and o["xray"]["streamSettings"]["network"] == "kcp", (o, sk))
o, _ = one(f"vmess://{U}@vm.example:443?type=ws&security=tls&host=a.com&path=/x&encryption=auto#url-form")
check("vmess in the newer URL form", o and o["uuid"] == U and o["transport"]["type"] == "ws", o)

o, _ = one(f"trojan://pa%24s@t.example:443?type=ws&host=a.com&path=/t&sni=a.com#tr")
check("trojan ws: TLS always on, password decoded", o and o["password"] == "pa$s" and o["tls"]["enabled"] and o["transport"]["type"] == "ws", o)
o, _ = one("trojan://pw@t.example:443?security=none#plain")
check("trojan: even 'security=none' keeps TLS (the protocol is TLS)", o and o["tls"]["enabled"], o)

cred = b64("aes-256-gcm:pass:word")
o, _ = one(f"ss://{cred}@s.example:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dbing.com#ss1")
check("shadowsocks SIP002 with '/?plugin=' (the slash used to break the port)",
      o and o["server_port"] == 8388 and o["method"] == "aes-256-gcm" and o["password"] == "pass:word"
      and o["plugin"] == "obfs-local" and "obfs=tls" in o["plugin_opts"], o)
o, _ = one("ss://" + b64("chacha20-ietf-poly1305:pw@old.example:1234") + "#legacy")
check("shadowsocks legacy (everything in base64)", o and o["server"] == "old.example" and o["server_port"] == 1234, o)
o, _ = one("ss://" + cred.replace("=", "%3D") + "@s.example:8388#pct")
check("shadowsocks with a percent-encoded base64 userinfo", o and o["method"] == "aes-256-gcm", o)
o, _ = one("ss://aes-128-gcm:p%40ss@[2001:db8::2]:9000#v6")
check("shadowsocks plain userinfo and IPv6", o and o["password"] == "p@ss" and o["server"] == "2001:db8::2", o)
o, sk = one("ssr://" + b64("h.example:1:origin:aes-256-cfb:plain:cGFzcw/?remarks=x"))
check("ShadowsocksR is left out, with the reason", o is None and sk == {"ssr": 1}, sk)

o, _ = one("hysteria2://pw@hy.example:443?sni=a.com&insecure=1&obfs=salamander&obfs-password=op&pinSHA256=AB:CD#hy2")
check("hysteria2: sni, insecure, obfs, pin", o and o["tls"]["insecure"] and o["obfs"] == {"type": "salamander", "password": "op"}
      and o["tls"]["certificate_public_key_sha256"] == ["AB:CD"], o)
o, _ = one("hy2://pw@hy.example:20000-30000?mport=40000-50000#hop")
check("hysteria2 with a port range in the address and mport (port hopping)",
      o and o["server_port"] == 20000 and o["server_ports"] == ["20000:30000", "40000:50000"], o)
o, _ = one("hysteria2://user:pw@hy.example:443?up=50 Mbps&down=200#ud")
check("hysteria2 user:password and speeds", o and o["password"] == "user:pw" and o["up_mbps"] == 50 and o["down_mbps"] == 200, o)
o, _ = one("hysteria://hy1.example:443?auth=secret&upmbps=20&downmbps=100&peer=a.com&insecure=1&alpn=h3#v1")
check("hysteria (v1)", o and o["type"] == "hysteria" and o["auth_str"] == "secret" and o["up_mbps"] == 20 and o["tls"]["server_name"] == "a.com", o)
o, _ = one(f"tuic://{U}:pw@tu.example:443?congestion_control=bbr&alpn=h3&sni=a.com&udp_relay_mode=native#tu")
check("tuic", o and o["uuid"] == U and o["password"] == "pw" and o["udp_relay_mode"] == "native", o)
o, _ = one("anytls://secret@any.example:443?sni=a.com&insecure=1#any")
check("anytls", o and o["type"] == "anytls" and o["password"] == "secret" and o["tls"]["insecure"], o)
o, _ = one("socks5://user:pw@sock.example:1080#s5")
check("socks5 with a login", o and o["type"] == "socks" and o["username"] == "user" and o["version"] == "5", o)
o, _ = one("socks://" + b64("user:pw") + "@sock.example:1080#v2rayn")
check("socks with base64 login (v2rayN)", o and o["username"] == "user" and o["password"] == "pw", o)
WGK = "mHk5Q0hcX0xx6dWjLrU2uHk3WqZ0eB0a1Jq0k3x0v1U="
o, sk = one(f"wireguard://{WGK.replace('=', '%3D')}@wg.example:51820?publickey={WGK.replace('=', '%3D')}&address=10.0.0.2/32,fd00::2/128&mtu=1280&reserved=1,2,3#wg")
check("WireGuard link: keys, addresses, reserved bytes, mtu", o and o["type"] == "wireguard" and o["private_key"] == WGK and o["local_address"] == ["10.0.0.2/32", "fd00::2/128"]
      and o["reserved"] == [1, 2, 3] and o["mtu"] == 1280 and o["server_port"] == 51820, o)
o, sk = one("wireguard://KEY@wg.example:51820?address=10.0.0.2/32#no-peer-key")
check("a WireGuard link without the server's key is not a server", o is None, o)
o, sk = one(f"wireguard://{WGK}@wg.example:51820?publickey={WGK}&address=10.0.0.2/32&jc=4&jmin=40#awg")
check("AmneziaWG is left out, with the reason (the core has no such option)", o is None and sk == {"amneziawg": 1}, (o, sk))
o, sk = one("naive+https://user:pw@nv.example:443#naive")
check("NaiveProxy", o and o["type"] == "naive" and o["username"] == "user" and o["tls"]["server_name"] == "nv.example", o)
o, sk = one("ssh://root:pw@ssh.example:2222#ssh")
check("SSH", o and o["type"] == "ssh" and o["server_port"] == 2222 and o["user"] == "root" and o["password"] == "pw", o)
o, _ = one(f"vless://{U}@h.example:0?security=tls#zero")
check("port 0 is not a server", o is None)

# ---------- lists and documents ----------
LINKS = "\n".join([f"vless://{U}@a.example:443?security=tls&sni=a.com#A", "trojan://pw@b.example:443#B",
                   "hysteria2://pw@c.example:443#C", f"vless://{U}@x.example:443?type=xhttp#X"])
outs, sk = S.parse_text_ex(LINKS)
check("a plain list: every server comes out, the XHTTP one as an Xray server", [o["tag"] for o in outs] == ["A", "B", "C", "X"] and outs[3]["type"] == "xray" and not sk, (outs, sk))
check("the same as base64", [o["tag"] for o in S.parse_text(b64(LINKS))] == ["A", "B", "C", "X"])
check("... url-safe, without padding", [o["tag"] for o in S.parse_text(b64u(LINKS))] == ["A", "B", "C", "X"])
wrapped = "\n".join(b64(LINKS)[i:i + 76] for i in range(0, len(b64(LINKS)), 76))
check("... wrapped in lines of 76 characters", [o["tag"] for o in S.parse_text(wrapped)] == ["A", "B", "C", "X"])
check("a BOM and a blank line first do not matter", len(S.parse_text("﻿\n\n" + LINKS)) == 4)

sb = {"outbounds": [{"type": "selector", "tag": "sel", "outbounds": ["A"]}, {"type": "direct", "tag": "direct"},
                    {"type": "vless", "tag": "SB", "server": "sb.example", "server_port": 443, "uuid": U, "detour": "x"}]}
outs = S.parse_text(json.dumps(sb))
check("sing-box JSON: servers only, links to other outbounds dropped", [o["tag"] for o in outs] == ["SB"] and "detour" not in outs[0], outs)

xray = {"remarks": "Xray 1", "outbounds": [
    {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "x.example", "port": 443,
                                                                    "users": [{"id": U, "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
                        "realitySettings": {"serverName": "www.m.com", "publicKey": "PK", "shortId": "ab", "fingerprint": "chrome"}}},
    {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]}
xray2 = {"remarks": "Xray 2", "outbounds": [
    {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "w.example", "port": 443, "users": [{"id": U}]}]},
     "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "w.example", "alpn": ["h2", "http/1.1"]},
                        "wsSettings": {"path": "/w", "headers": {"Host": "w.example"}}}}]}
xray3 = {"remarks": "Xray 3", "outbounds": [
    {"protocol": "vless", "settings": {"vnext": [{"address": "h.example", "port": 443, "users": [{"id": U}]}]},
     "streamSettings": {"network": "xhttp", "security": "tls"}}]}
outs, sk = S.parse_text_ex(json.dumps([xray, xray2, xray3]))
check("an array of Xray configs (Remnawave): names from 'remarks', reality and ws+tls read, xhttp kept for Xray as written",
      [o["tag"] for o in outs] == ["Xray 1", "Xray 2", "Xray 3"] and outs[0]["tls"]["reality"]["public_key"] == "PK"
      and outs[0]["flow"] == "xtls-rprx-vision" and outs[1]["transport"]["path"] == "/w" and outs[1]["tls"]["alpn"] == ["h2", "http/1.1"]
      and outs[2]["type"] == "xray" and outs[2]["xray"]["streamSettings"] == {"network": "xhttp", "security": "tls"} and not sk, (outs, sk))
check("one Xray config (not an array)", [o["tag"] for o in S.parse_text(json.dumps(xray))] == ["Xray 1"])
trojan_x = {"outbounds": [{"protocol": "trojan", "tag": "T", "settings": {"servers": [{"address": "t.example", "port": 443, "password": "pw"}]},
                           "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "t.example"}}},
                          {"protocol": "shadowsocks", "tag": "S", "settings": {"servers": [{"address": "s.example", "port": 8388, "method": "aes-128-gcm", "password": "p"}]}}]}
check("Xray trojan and shadowsocks", [o["type"] for o in S.parse_text(json.dumps(trojan_x))] == ["trojan", "shadowsocks"])

xhttp_json = {"remarks": "Provider XHTTP", "outbounds": [
    {"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "xh.example", "port": 443, "users": [{"id": U, "encryption": "none", "flow": ""}]}]},
     "streamSettings": {"network": "xhttp", "security": "reality", "realitySettings": {"serverName": "www.m.com", "publicKey": "PK", "shortId": "ab", "fingerprint": "chrome"},
                        "xhttpSettings": {"path": "/p", "mode": "stream-up", "extra": {"headers": {"X-A": "1"}, "xmux": {"maxConcurrency": "16-32"}}}},
     "mux": {"enabled": False}}]}
outs = S.parse_text(json.dumps(xhttp_json))
check("an Xray config with XHTTP is passed to Xray exactly as the provider wrote it (extra and all), without mux",
      len(outs) == 1 and outs[0]["type"] == "xray" and outs[0]["tag"] == "Provider XHTTP" and outs[0]["xray"]["streamSettings"]["xhttpSettings"]["extra"]["xmux"] == {"maxConcurrency": "16-32"}
      and "mux" not in outs[0]["xray"], outs)
wg_end = {"endpoints": [{"type": "wireguard", "tag": "WG end", "address": ["10.0.0.2/32"], "private_key": WGK, "mtu": 1280,
                         "peers": [{"address": "wg.example", "port": 51820, "public_key": WGK, "allowed_ips": ["0.0.0.0/0"], "reserved": [1, 2, 3]}]}],
          "outbounds": [{"type": "direct", "tag": "direct"}]}
outs = S.parse_text(json.dumps(wg_end))
check("a sing-box WireGuard endpoint becomes a server", len(outs) == 1 and outs[0]["type"] == "wireguard" and outs[0]["server"] == "wg.example"
      and outs[0]["reserved"] == [1, 2, 3] and outs[0]["local_address"] == ["10.0.0.2/32"], outs)
wg_x = {"outbounds": [{"protocol": "wireguard", "tag": "w", "settings": {"secretKey": WGK, "address": ["10.0.0.2/32"], "mtu": 1280,
                                                                          "peers": [{"publicKey": WGK, "endpoint": "wgx.example:51820"}]}}]}
outs = S.parse_text(json.dumps(wg_x))
check("an Xray WireGuard outbound becomes a server", len(outs) == 1 and outs[0]["server"] == "wgx.example" and outs[0]["server_port"] == 51820, outs)

sip = {"version": 1, "servers": [{"server": "ss1.example", "server_port": 8388, "password": "pw", "method": "aes-256-gcm", "remarks": "SIP 1"},
                                 {"server": "ss2.example", "server_port": 8389, "password": "pw", "method": "chacha20-ietf-poly1305"}]}
outs = S.parse_text(json.dumps(sip))
check("SIP008 (Shadowsocks JSON)", [o["tag"] for o in outs][0] == "SIP 1" and len(outs) == 2 and outs[1]["method"].startswith("chacha"), outs)

CLASH_FLOW = f"""port: 7890
proxies:
  - {{name: "SS 1", type: ss, server: ss.example, port: 8388, cipher: aes-256-gcm, password: pw, plugin: obfs, plugin-opts: {{mode: tls, host: bing.com}}}}
  - {{name: 'VM ws', type: vmess, server: vm.example, port: 443, uuid: {U}, alterId: 0, cipher: auto, tls: true, network: ws, ws-opts: {{path: /p, headers: {{Host: cdn.example}}}}}}
  - {{name: VL reality, type: vless, server: vl.example, port: 443, uuid: {U}, tls: true, flow: xtls-rprx-vision, servername: www.m.com, client-fingerprint: chrome, reality-opts: {{public-key: PK, short-id: ab}}}}
  - {{name: TR, type: trojan, server: tr.example, port: 443, password: pw, sni: a.com, skip-cert-verify: true}}
  - {{name: HY2, type: hysteria2, server: hy.example, port: 443, password: pw, sni: a.com, up: "100 Mbps", down: "200 Mbps"}}
  - {{name: TUIC, type: tuic, server: tu.example, port: 443, uuid: {U}, password: pw, alpn: [h3], congestion-controller: bbr}}
  - {{name: WG, type: wireguard, server: wg.example, port: 51820, private-key: {WGK}, public-key: {WGK}, ip: 10.0.0.2, reserved: [1, 2, 3]}}
proxy-groups:
  - {{name: auto, type: url-test, proxies: ["SS 1"]}}
"""
outs, sk = S.parse_text_ex(CLASH_FLOW)
check("Clash, one-line entries (no YAML library needed): ss+obfs, vmess ws, vless reality, trojan, hysteria2, tuic, WireGuard",
      [o["tag"] for o in outs] == ["SS 1", "VM ws", "VL reality", "TR", "HY2", "TUIC", "WG"] and not sk, ([o["tag"] for o in outs], sk))
byname = {o["tag"]: o for o in outs}
check("... the details survive: obfs plugin, ws headers, reality key, skip-cert-verify, speeds, alpn",
      byname["SS 1"]["plugin"] == "obfs-local" and "obfs-host=bing.com" in byname["SS 1"]["plugin_opts"]
      and byname["VM ws"]["transport"]["headers"]["Host"] == "cdn.example" and byname["VL reality"]["tls"]["reality"]["public_key"] == "PK"
      and byname["TR"]["tls"]["insecure"] and byname["HY2"]["up_mbps"] == 100 and byname["TUIC"]["tls"]["alpn"] == ["h3"], byname)
check("a proxy group is not a server", "auto" not in byname)
check("Clash WireGuard: keys, address from ip, reserved bytes", byname["WG"]["type"] == "wireguard" and byname["WG"]["local_address"] == ["10.0.0.2/32"]
      and byname["WG"]["reserved"] == [1, 2, 3], byname.get("WG"))
CLASH_X = f"""proxies:
  - {{name: "CX", type: vless, server: cx.example, port: 443, uuid: {U}, tls: true, network: xhttp, servername: www.m.com, client-fingerprint: chrome, reality-opts: {{public-key: PK, short-id: ab}}, xhttp-opts: {{path: /cx, mode: packet-up, host: h.a.com}}}}
  - {{name: "CE", type: vless, server: ce.example, port: 443, uuid: {U}, tls: true, encryption: "mlkem768x25519plus.native.0rtt.KEY", servername: ce.example}}
  - {{name: "SSHX", type: ssh, server: sx.example, port: 22, username: root, password: pw}}
"""
outs = S.parse_text(CLASH_X)
check("Clash: XHTTP (xhttp-opts), VLESS encryption and SSH", [o["type"] for o in outs] == ["xray", "xray", "ssh"]
      and outs[0]["xray"]["streamSettings"]["xhttpSettings"] == {"path": "/cx", "mode": "packet-up", "host": "h.a.com"}
      and outs[1]["xray"]["settings"]["vnext"][0]["users"][0]["encryption"].startswith("mlkem"), outs)

CLASH_BLOCK = f"""proxies:
  - name: "Block 1"
    type: vless
    server: b.example
    port: 443
    uuid: {U}
    tls: true
    network: grpc
    servername: b.example
    grpc-opts:
      grpc-service-name: svc
  - name: Block 2
    type: ss
    server: s.example
    port: 8388
    cipher: aes-128-gcm
    password: pw
"""
if S.yaml is not None:
    outs = S.parse_text(CLASH_BLOCK)
    check("Clash, block style (with the YAML library)", [o["tag"] for o in outs] == ["Block 1", "Block 2"]
          and outs[0]["transport"] == {"type": "grpc", "service_name": "svc"}, outs)
else:
    print("     (no PyYAML here: block-style Clash is skipped)")
check("Clash inside base64", [o["tag"] for o in S.parse_text(b64(CLASH_FLOW))][:2] == ["SS 1", "VM ws"])
check("JSON inside base64", [o["tag"] for o in S.parse_text(b64(json.dumps(sb)))] == ["SB"])
check("an HTML page is nothing, not an exception", S.parse_text("<html><body>Login</body></html>") == [])
check("an empty answer is nothing", S.parse_text("") == [] and S.parse_text("   \n") == [])
check("the note says how many and why", "Пропущено 3 сервера" in S.skipped_note({"xhttp": 2, "kcp": 1}) and "XHTTP: 2" in S.skipped_note({"xhttp": 2, "kcp": 1})
      and "Пропущено 1 сервер," in S.skipped_note({"ssr": 1}) and S.skipped_note({}) == "")

# ---------- the box ----------
SUB = "https://h.example/sub/k1"
for raw, want, name in (
        (SUB, [SUB], "an address"),
        (f'"{SUB}"', [SUB], "an address in quotes"),
        (f"<{SUB}>", [SUB], "an address in angle brackets"),
        (f"[моя подписка]({SUB})", [SUB], "an address as a Markdown link"),
        (f"Вот ссылка: {SUB}, спасибо.", [SUB], "an address inside a sentence"),
        ("h.example/sub/k1", [SUB], "an address without https://"),
        ("sing-box://import-remote-profile?url=https%3A%2F%2Fh.example%2Fsub%2Fk1#Name", [SUB], "a sing-box link"),
        ("clash://install-config?url=https%3A%2F%2Fh.example%2Fsub%2Fk1&name=x", [SUB], "a Clash link"),
        ("clashmeta://install-config?url=" + "https%3A%2F%2Fh.example%2Fsub%2Fk1", [SUB], "a Clash Meta link"),
        ("hiddify://import/https://h.example/sub/k1#x", [SUB], "a Hiddify link"),
        ("sub://" + b64u(SUB) + "#n", [SUB], "a Shadowrocket link"),
        ("v2rayn://install-sub?url=" + "https%253A%252F%252Fh.example%252Fsub%252Fk1", [SUB], "a doubly encoded link"),
        ("https://a.example/1 https://b.example/2,https://c.example/3", ["https://a.example/1", "https://b.example/2", "https://c.example/3"], "several addresses in a line"),
        (f"# my subscriptions\n{SUB}\n\n// old\n", [SUB], "comments and blank lines"),
        ("https://h.example/sub?token=a,b&x=1", ["https://h.example/sub?token=a,b&x=1"], "commas and ampersands inside an address stay"),
):
    check("the box: " + name, S.source_lines(raw) == want, S.source_lines(raw))
link = f"vless://{U}@h.example:443?security=tls#My Server (2)"
check("a share link keeps its whole name, spaces and brackets", S.source_lines(link) == [link], S.source_lines(link))
urls, rest = S.split_sources(f"{SUB}\n{link}\n{b64(LINKS)[:40]}")
check("split: addresses and the rest", urls == [SUB] and len(rest) == 2, (urls, rest))
outs, sk = S.parse_inline([link, "trojan://pw@b.example:443#B", f"vless://{U}@x.example:443?type=xhttp#X", "ssr://" + b64("h:1:o:m:p:cGFzcw")])
check("pasted share links: parsed one by one, the one nobody can run is counted", len(outs) == 3 and dict(sk) == {"ssr": 1}, (outs, sk))
chunks = [b64(LINKS)[i:i + 40] for i in range(0, len(b64(LINKS)), 40)]
check("a pasted base64 blob that spans several lines is read as one", [o["tag"] for o in S.parse_inline(chunks)[0]] == ["A", "B", "C", "X"])
check("a mix: a link line and a base64 blob together",
      len(S.parse_inline([link] + chunks)[0]) == 5, len(S.parse_inline([link] + chunks)[0]))

# ---------- never an exception, whatever comes ----------
import random  # noqa: E402
rnd = random.Random(7)
ALPH = list("abcdefghijklmnop0123456789:/?&=#%@[]{}()-_+.,; \n\t\"'\\") + ["vless://", "ss://", "vmess://", "hy2://", "proxies:", "{", "[", "https://"]
bad = 0
for _ in range(3000):
    txt = "".join(rnd.choice(ALPH) for _ in range(rnd.randint(0, 80)))
    try:
        for o in S.parse_text(txt):
            assert S.valid_outbound(o)
        S.source_lines(txt)
        S.parse_inline(S.split_sources(txt)[1])
    except Exception as e:  # noqa: BLE001
        bad += 1
        print("      raised on", repr(txt), type(e).__name__, e)
check("3000 random strings: no exception, only valid servers", bad == 0, bad)
mutants = 0
for base in (f"vless://{U}@h.example:443?type=ws&security=tls&host=a.com&path=/x#n", "ss://" + cred + "@s.example:8388/?plugin=x#n",
             "vmess://" + b64(json.dumps(vm)), "hysteria2://pw@h.example:443?sni=a.com#n", CLASH_FLOW, json.dumps(xray)):
    for _ in range(300):
        s = list(base)
        for _ in range(rnd.randint(1, 5)):
            i = rnd.randrange(len(s) + 1)
            s.insert(i, rnd.choice(ALPH)) if rnd.random() < 0.5 and s else (s.pop(min(i, len(s) - 1)) if s else None)
        try:
            for o in S.parse_text("".join(s)):
                assert S.valid_outbound(o)
        except Exception as e:  # noqa: BLE001
            mutants += 1
            print("      raised on", repr("".join(s))[:120], type(e).__name__, e)
check("1800 damaged real-looking inputs: no exception", mutants == 0, mutants)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
