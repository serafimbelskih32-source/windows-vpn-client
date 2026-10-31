"""Everything that turns what a user pastes or a provider sends into sing-box servers: share links, base64 lists,
sing-box / Xray / Clash / SIP008 files, and the "open in the app" links that wrap a subscription address.
No GUI, no network: it runs the same everywhere and is tested on its own (tests/test_sources.py)."""
import base64
import json
import re
from collections import Counter
from urllib.parse import parse_qs, unquote, urlparse

try:
    import yaml  # block-style Clash files; flow-style ones (what most converters write) are read without it
except Exception:  # noqa: BLE001
    yaml = None


class Unsupported(Exception):
    """A server the program understands but the core cannot run: the reason is a key of WHY."""


# What the user reads when servers had to be left out.
WHY = {"xhttp": "транспорт XHTTP", "kcp": "транспорт mKCP", "quic": "старый транспорт QUIC", "ssr": "ShadowsocksR",
       "wireguard": "WireGuard", "vless-enc": "шифрование VLESS (encryption)", "tcp-http": "TCP с подменой заголовка HTTP",
       "naive": "NaiveProxy", "ssh": "SSH", "snell": "Snell", "mieru": "Mieru", "amneziawg": "AmneziaWG",
       "other": "неизвестный протокол"}
# The core (sing-box) cannot run these, Xray can: such a server is kept as an "xray" server that a companion Xray
# process serves on a local port (see engines.py).
XRAY_REASONS = ("xhttp", "kcp", "tcp-http", "vless-enc")

LINK_SCHEMES = ("vless", "vmess", "trojan", "ss", "ssr", "ssh", "hysteria2", "hy2", "hysteria", "hy", "tuic", "anytls", "socks",
                "socks4", "socks5", "wireguard", "wg", "naive+https", "naive+quic")
LINK_RE = re.compile(r"(?i)(?<![A-Za-z0-9+.-])(" + "|".join(re.escape(s) for s in LINK_SCHEMES) + r")://")
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e"), None)


def clean_blob(text):
    """A pasted or downloaded text without what hides in it: BOM, zero-width and direction marks, non-breaking spaces."""
    return str(text or "").translate(_INVISIBLE).replace("\u00a0", " ").strip()


def b64d(s: str) -> str:
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def _flag(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _first(q, *names, default=""):
    for n in names:
        v = q.get(n)
        if v and v[0] != "":
            return v[0]
    return default


# ---------- TLS and transport from a link's parameters (q = parse_qs-style dict of lists) ----------
def _tls(q, host, default_sec="none"):
    sec = (_first(q, "security", default=default_sec) or default_sec).lower()
    if sec not in ("tls", "reality", "xtls"):
        return None
    typ = _first(q, "type", default="tcp").lower()
    sni = _first(q, "sni", "peer", "servername")
    if not sni and typ in ("ws", "http", "h2", "httpupgrade", "grpc"):
        sni = _first(q, "host")  # what v2rayN does: no SNI given, the Host header stands in
    t = {"enabled": True, "server_name": sni or host}
    if _flag(_first(q, "allowInsecure", "insecure", "allow_insecure", default="0")):
        t["insecure"] = True
    if _first(q, "alpn"):
        t["alpn"] = [a for a in _first(q, "alpn").split(",") if a]
    fp = _first(q, "fp", "fingerprint")
    if fp or sec == "reality":
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    if sec == "reality":
        t["reality"] = {"enabled": True, "public_key": _first(q, "pbk", "publicKey"), "short_id": _first(q, "sid", "shortId")}
    return t


def _transport(q):
    typ = (_first(q, "type", default="tcp") or "tcp").lower()
    if typ in ("xhttp", "splithttp"):
        raise Unsupported("xhttp")
    if typ in ("kcp", "mkcp"):
        raise Unsupported("kcp")
    path = unquote(_first(q, "path", default="/")) or "/"
    host = _first(q, "host")
    if typ == "ws":
        t = {"type": "ws", "path": path}
        m = re.search(r"[?&]ed=(\d+)", path)
        if m:  # early data: the path carries it, the core wants it as settings
            t["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            t["headers"] = {"Host": host}
        return t
    if typ == "grpc":
        return {"type": "grpc", "service_name": unquote(_first(q, "serviceName", "service_name", default=""))}
    if typ in ("http", "h2"):
        return {"type": "http", "path": path, "host": [host] if host else []}
    if typ == "httpupgrade":
        return {"type": "httpupgrade", "path": path, "host": host}
    if typ == "quic":
        return {"type": "quic"}
    if typ == "tcp" and _first(q, "headerType") == "http":
        raise Unsupported("tcp-http")
    return None


def _secure(o, q, host, default_sec="none"):
    """Add the TLS and transport parts of a link's parameters to the server `o`. What the core cannot run but Xray can
    (XHTTP, mKCP, an HTTP header on TCP) turns the server into an "xray" one."""
    try:
        t = _tls(q, host, default_sec)
        tr = _transport(q)
    except Unsupported as e:
        if str(e) in XRAY_REASONS:
            return _to_xray(o, q, host, default_sec)
        raise
    if t:
        o["tls"] = t
    if tr:
        o["transport"] = tr
    return o


def _xray_stream(q, host, default_sec="none"):
    """Xray's `streamSettings` from the link-parameter dict."""
    net = (_first(q, "type", default="tcp") or "tcp").lower()
    net = {"splithttp": "xhttp", "mkcp": "kcp", "h2": "http", "raw": "tcp"}.get(net, net)
    sec = (_first(q, "security", default=default_sec) or default_sec).lower()
    sec = "tls" if sec == "xtls" else sec
    ss = {"network": net, "security": sec if sec in ("tls", "reality") else "none"}
    sni = _first(q, "sni", "peer", "servername") or (_first(q, "host") if net in ("ws", "http", "httpupgrade", "xhttp", "grpc") else "")
    alpn = [a for a in _first(q, "alpn").split(",") if a]
    if ss["security"] == "tls":
        ss["tlsSettings"] = {"serverName": sni or host, "fingerprint": _first(q, "fp", "fingerprint") or "chrome",
                             "allowInsecure": _flag(_first(q, "allowInsecure", "insecure", "allow_insecure", default="0"))}
        if alpn:
            ss["tlsSettings"]["alpn"] = alpn
    elif ss["security"] == "reality":
        ss["realitySettings"] = {"serverName": sni or host, "fingerprint": _first(q, "fp", "fingerprint") or "chrome",
                                 "publicKey": _first(q, "pbk", "publicKey"), "shortId": _first(q, "sid", "shortId"),
                                 "spiderX": unquote(_first(q, "spx", "spiderX"))}
    path, hosth = unquote(_first(q, "path", default="/")) or "/", _first(q, "host")
    if net == "xhttp":
        x = {"path": path, "mode": _first(q, "mode", default="auto") or "auto"}
        if hosth:
            x["host"] = hosth
        extra = _first(q, "extra")
        if extra:
            try:
                x["extra"] = json.loads(unquote(extra))
            except ValueError:
                pass
        ss["xhttpSettings"] = x
    elif net == "kcp":
        ss["kcpSettings"] = {"header": {"type": _first(q, "headerType", default="none") or "none"}}
        if _first(q, "seed"):
            ss["kcpSettings"]["seed"] = _first(q, "seed")
    elif net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": hosth} if hosth else {}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": unquote(_first(q, "serviceName", "service_name")), "multiMode": _first(q, "mode") == "multi"}
    elif net == "http":
        ss["httpSettings"] = {"path": path, "host": [hosth] if hosth else []}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": hosth}
    elif net == "tcp" and _first(q, "headerType") == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {"path": [path], "headers": {"Host": [hosth] if hosth else []}}}}
    return ss


def _to_xray(o, q, host, default_sec="none", enc="none"):
    """A server the core cannot run, as an "xray" server: the sing-box-style fields stay (name, address, for lists and
    ping) and `xray` holds the complete Xray outbound."""
    proto = o["type"]
    if proto == "vless":
        settings = {"vnext": [{"address": o["server"], "port": o["server_port"],
                               "users": [dict({"id": o.get("uuid", ""), "encryption": enc or "none"},
                                              **({"flow": o["flow"]} if o.get("flow") else {}))]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": o["server"], "port": o["server_port"],
                               "users": [{"id": o.get("uuid", ""), "security": o.get("security") or "auto", "alterId": int(o.get("alter_id") or 0)}]}]}
    elif proto == "trojan":
        settings = {"servers": [{"address": o["server"], "port": o["server_port"], "password": o.get("password", "")}]}
    else:
        raise Unsupported("other")
    return {"type": "xray", "tag": o.get("tag", ""), "server": o["server"], "server_port": o["server_port"],
            "xray": {"protocol": proto, "settings": settings, "streamSettings": _xray_stream(q, host, default_sec)}}


def _mbps(v, default):
    m = re.match(r"\s*(\d+)", str(v or ""))
    return int(m.group(1)) if m else default


def _split_ports(netloc):
    """'host:443' or 'host:1234,5000-6000' (port hopping) -> (host, first port, [ranges 'a:b'])."""
    hostport = netloc.rsplit("@", 1)[-1]
    host, _, ports = hostport.rpartition(":")
    if not host:
        raise ValueError("no port")
    host = host.strip("[]")
    first, ranges = None, []
    for part in re.split(r"[,;]", ports):
        a, _, b = part.partition("-")
        if not a.isdigit():
            raise ValueError("bad port")
        if first is None:
            first = int(a)
        if b:
            ranges.append(f"{a}:{b}")
    return host, first, ranges


def _name(link):
    return re.sub(r"[\x00-\x1f]", "", unquote(link.split("#", 1)[1])).strip() if "#" in link else ""


# ---------- one share link ----------
def parse_link(link: str, skipped=None):
    """A sing-box outbound from one share link, or None. `skipped` (a list), if given, gets the key of the reason when a
    link is understood but cannot be run (see WHY)."""
    link = clean_blob(link)
    m = LINK_RE.search(link)
    if not m:
        return None
    link = link[m.start():]
    scheme = m.group(1).lower()
    name = _name(link)
    try:
        return _parse(link, scheme, name)
    except Unsupported as e:
        if skipped is not None:
            skipped.append(str(e))
        return None
    except Exception:  # noqa: BLE001
        return None


def _parse(link, scheme, name):
    if scheme == "vmess":
        body = link[8:].split("#")[0]
        if "@" in body:  # the newer form: vmess://uuid@host:port?...
            u = urlparse("vmess://" + body)
            q = parse_qs(u.query)
            host, port = _split_ports(u.netloc)[:2]
            o = {"type": "vmess", "tag": name, "server": host, "server_port": port, "uuid": unquote(u.username or ""),
                 "security": _first(q, "encryption", "scy", default="auto"), "alter_id": 0}
            return _secure(o, q, host)
        j = json.loads(b64d(unquote(body)))
        o = {"type": "vmess", "tag": j.get("ps") or name, "server": str(j["add"]).strip(), "server_port": int(j["port"]),
             "uuid": str(j["id"]).strip(), "security": j.get("scy") or "auto", "alter_id": int(j.get("aid", 0) or 0)}
        net = str(j.get("net") or "tcp").lower()
        q = {"security": ["tls" if str(j.get("tls", "")).lower() == "tls" else "none"],
             "sni": [j.get("sni") or ""], "type": [net], "path": [j.get("path") or "/"], "host": [j.get("host") or ""],
             "serviceName": [j.get("path") or ""], "fp": [j.get("fp") or ""], "alpn": [j.get("alpn") or ""],
             "headerType": [j.get("type") or ""] if net == "tcp" else [""]}
        if net in ("h2", "http") and not q["host"][0]:
            q["host"] = [j.get("sni") or ""]
        return _secure(o, q, o["server"])
    if scheme == "ss":
        body = link[5:].split("#")[0]
        plugin = None
        if "?" in body:
            body, qs = body.split("?", 1)
            plugin = parse_qs(qs).get("plugin", [None])[0]
        body = body.rstrip("/")  # SIP002 writes host:port/?plugin=...
        if "@" not in body:
            body = b64d(unquote(body))
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = b64d(unquote(userinfo))
        method, pw = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        o = {"type": "shadowsocks", "tag": name, "server": host.strip("[]"), "server_port": int(port),
             "method": unquote(method), "password": unquote(pw)}
        if plugin:
            p = unquote(plugin).split(";")
            o["plugin"] = {"obfs": "obfs-local"}.get(p[0], p[0])
            o["plugin_opts"] = ";".join(p[1:])
        return o
    if scheme == "ssr":
        raise Unsupported("ssr")
    u = urlparse(link)
    q = parse_qs(u.query)
    host, port, ranges = _split_ports(u.netloc) if re.search(r":\d+[,;-]", u.netloc) else (u.hostname, u.port, [])
    if port is None:
        port = 443
    user, pw = unquote(u.username or ""), unquote(u.password or "")
    if scheme == "vless":
        enc = _first(q, "encryption", default="none")
        o = {"type": "vless", "tag": name, "server": host, "server_port": port, "uuid": user, "packet_encoding": "xudp"}
        if _first(q, "flow"):
            o["flow"] = _first(q, "flow")
        if enc not in ("none", ""):  # VLESS with its own encryption layer: Xray only
            return _to_xray(o, q, host, "none", enc)
        return _secure(o, q, host)
    if scheme == "trojan":
        o = {"type": "trojan", "tag": name, "server": host, "server_port": port, "password": user}
        try:
            o["tls"] = _tls(q, host, "tls") or {"enabled": True, "server_name": host}
            tr = _transport(q)
        except Unsupported as e:
            if str(e) in XRAY_REASONS:
                return _to_xray(o, q, host, "tls")
            raise
        if tr:
            o["transport"] = tr
        return o
    if scheme in ("wireguard", "wg"):
        pk = unquote(u.username or "")
        pub = _first(q, "publickey", "public_key", "peer_public_key", "pubkey")
        addr = [a for a in re.split(r"[,\s]+", _first(q, "address", "ip", "local_address")) if a]
        if _first(q, "amnezia", "jc", "junk"):
            raise Unsupported("amneziawg")
        o = {"type": "wireguard", "tag": name, "server": host, "server_port": port, "local_address": addr or ["10.0.0.2/32"],
             "private_key": pk, "peer_public_key": pub}
        if _first(q, "presharedkey", "psk", "pre_shared_key"):
            o["pre_shared_key"] = _first(q, "presharedkey", "psk", "pre_shared_key")
        if _first(q, "reserved"):
            try:
                o["reserved"] = [int(x) for x in re.split(r"[,\s]+", _first(q, "reserved")) if x][:3]
            except ValueError:
                pass
        if _first(q, "mtu").isdigit():
            o["mtu"] = int(_first(q, "mtu"))
        return o
    if scheme.startswith("naive"):
        o = {"type": "naive", "tag": name, "server": host, "server_port": port, "username": user, "password": pw,
             "tls": {"enabled": True, "server_name": _first(q, "sni", default=host)}}
        if scheme.endswith("quic"):
            o["quic"] = True
        return o
    if scheme == "ssh":
        o = {"type": "ssh", "tag": name, "server": host, "server_port": port if u.port else 22, "user": user}
        if pw:
            o["password"] = pw
        return o
    if scheme in ("hysteria2", "hy2"):
        o = {"type": "hysteria2", "tag": name, "server": host, "server_port": port, "password": user + (":" + pw if pw else ""),
             "tls": {"enabled": True, "server_name": _first(q, "sni", "peer", default=host),
                     "insecure": _flag(_first(q, "insecure", "allowInsecure", default="0"))}}
        if _first(q, "alpn"):
            o["tls"]["alpn"] = _first(q, "alpn").split(",")
        if _first(q, "pinSHA256"):
            o["tls"]["certificate_public_key_sha256"] = [_first(q, "pinSHA256")]
        if _first(q, "obfs") and _first(q, "obfs") != "none":
            o["obfs"] = {"type": _first(q, "obfs"), "password": _first(q, "obfs-password", "obfsPassword")}
        mp = _first(q, "mport", "ports")
        if mp:
            ranges = ranges + [r.replace("-", ":") for r in re.split(r"[,;]", mp) if r]
        if ranges:
            o["server_ports"] = ranges
        for k_in, k_out in (("up", "up_mbps"), ("down", "down_mbps"), ("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
            v = re.match(r"\d+", _first(q, k_in))
            if v:
                o[k_out] = int(v.group(0))
        return o
    if scheme in ("hysteria", "hy"):
        o = {"type": "hysteria", "tag": name, "server": host, "server_port": port,
             "up_mbps": _mbps(_first(q, "upmbps", "up"), 100), "down_mbps": _mbps(_first(q, "downmbps", "down"), 100),
             "tls": {"enabled": True, "server_name": _first(q, "peer", "sni", default=host),
                     "insecure": _flag(_first(q, "insecure", "allowInsecure", default="0"))}}
        if _first(q, "auth", "auth_str"):
            o["auth_str"] = _first(q, "auth", "auth_str")
        if _first(q, "alpn"):
            o["tls"]["alpn"] = _first(q, "alpn").split(",")
        if _first(q, "obfsParam", "obfs"):
            o["obfs"] = _first(q, "obfsParam", "obfs")
        if ranges:
            o["server_ports"] = ranges
        return o
    if scheme == "tuic":
        o = {"type": "tuic", "tag": name, "server": host, "server_port": port, "uuid": user, "password": pw,
             "congestion_control": _first(q, "congestion_control", "congestion-controller", default="bbr"),
             "tls": {"enabled": True, "server_name": _first(q, "sni", default=host),
                     "insecure": _flag(_first(q, "allow_insecure", "allowInsecure", "insecure", default="0")),
                     "alpn": _first(q, "alpn", default="h3").split(",")}}
        if _first(q, "udp_relay_mode"):
            o["udp_relay_mode"] = _first(q, "udp_relay_mode")
        return o
    if scheme == "anytls":
        o = {"type": "anytls", "tag": name, "server": host, "server_port": port, "password": user + (":" + pw if pw else ""),
             "tls": {"enabled": True, "server_name": _first(q, "sni", "peer", default=host),
                     "insecure": _flag(_first(q, "insecure", "allowInsecure", default="0"))}}
        if _first(q, "alpn"):
            o["tls"]["alpn"] = _first(q, "alpn").split(",")
        return o
    if scheme in ("socks", "socks4", "socks5"):
        if user and not pw and ":" not in user:  # socks://base64(user:pass)@host:port (v2rayN)
            try:
                dec = b64d(user)
                if ":" in dec:
                    user, pw = dec.split(":", 1)
            except Exception:  # noqa: BLE001
                pass
        o = {"type": "socks", "tag": name, "server": host, "server_port": port, "version": "4" if scheme == "socks4" else "5"}
        if user:
            o["username"] = user
            o["password"] = pw
        return o
    return None


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NEEDS = {"vless": ("uuid",), "vmess": ("uuid",), "tuic": ("uuid",), "trojan": ("password",),
          "shadowsocks": ("method", "password"), "hysteria2": ("password",), "anytls": ("password",),
          "wireguard": ("private_key", "peer_public_key"), "naive": ("password",), "ssh": ("user",)}
_NOT_SERVERS = ("direct", "block", "dns", "selector", "urltest")


def valid_outbound(o):
    """Can this entry be a server at all? One broken line of a subscription (no host, port 0, a UUID that is not
    one) used to make the whole config fail its check, so nobody could connect. Anything dubious is dropped here;
    what only the core can judge is dealt with by salvage_outs."""
    try:
        if not isinstance(o, dict) or not isinstance(o.get("type"), str) or o["type"] in _NOT_SERVERS or not o["type"]:
            return False
        srv, port = o.get("server"), o.get("server_port")
        if not isinstance(srv, str) or not srv.strip() or len(srv) > 253 or re.search(r"[\s/@#?\\]", srv):
            return False
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return False
        for k in _NEEDS.get(o["type"], ()):
            if not isinstance(o.get(k), str) or not o[k].strip():
                return False
        if "uuid" in _NEEDS.get(o["type"], ()) and not _UUID.match(o["uuid"]):
            return False
        for k in ("tls", "transport"):
            if k in o and not isinstance(o[k], dict):
                return False
        tls = o.get("tls") or {}
        if "alpn" in tls and (not isinstance(tls["alpn"], list) or not all(isinstance(a, str) and a for a in tls["alpn"])):
            return False
        if o["type"] == "xray":
            x = o.get("xray")
            return isinstance(x, dict) and x.get("protocol") in ("vless", "vmess", "trojan") and isinstance(x.get("settings"), dict)
        if o["type"] == "wireguard":
            la = o.get("local_address")
            return isinstance(la, list) and bool(la) and all(isinstance(a, str) and "/" in a for a in la)
        return True
    except Exception:  # noqa: BLE001
        return False


def clean_outbound(o):
    """What a core must never take from a subscription: links to other outbounds (a server that is 'behind' a tag that
    is not in our list makes the config invalid) and anything that is not plain data."""
    o = dict(o)
    for k in ("detour", "outbounds", "default", "interrupt_exist_connections", "domain_resolver"):
        o.pop(k, None)
    if not isinstance(o.get("tag"), str):
        o["tag"] = ""
    return o


# ---------- Xray / v2ray JSON ----------
def _xray_q(ss, host):
    """Stream settings of an Xray outbound as the link-parameter dict _tls and _transport read."""
    ss = ss if isinstance(ss, dict) else {}
    net = str(ss.get("network") or "tcp").lower()
    net = "tcp" if net == "raw" else net
    sec = str(ss.get("security") or "none").lower()
    q = {"security": [sec], "type": [net]}
    t = ss.get("tlsSettings") or {}
    r = ss.get("realitySettings") or {}
    src = r if sec == "reality" else t
    q["sni"] = [src.get("serverName") or ""]
    q["fp"] = [src.get("fingerprint") or ""]
    q["alpn"] = [",".join(t.get("alpn") or [])]
    q["allowInsecure"] = ["1" if (t.get("allowInsecure") or r.get("allowInsecure")) else "0"]
    q["pbk"], q["sid"] = [r.get("publicKey") or ""], [r.get("shortId") or ""]
    ws, grpc, ht, hu = (ss.get(k) or {} for k in ("wsSettings", "grpcSettings", "httpSettings", "httpupgradeSettings"))
    if net == "ws":
        q["path"] = [ws.get("path") or "/"]
        q["host"] = [(ws.get("headers") or {}).get("Host") or ws.get("host") or ""]
    elif net == "grpc":
        q["serviceName"] = [grpc.get("serviceName") or ""]
    elif net in ("h2", "http"):
        q["path"] = [ht.get("path") or "/"]
        h = ht.get("host") or []
        q["host"] = [h[0] if isinstance(h, list) and h else (h if isinstance(h, str) else "")]
    elif net == "httpupgrade":
        q["path"] = [hu.get("path") or "/"]
        q["host"] = [hu.get("host") or ""]
    elif net == "tcp" and (((ss.get("tcpSettings") or {}).get("header") or {}).get("type") == "http"):
        q["headerType"] = ["http"]
    return q


def xray_outbound(o, remarks=""):
    """One Xray/v2ray `outbounds` entry -> sing-box outbound (None if it is not a server; Unsupported if it cannot run)."""
    proto = str(o.get("protocol") or "").lower()
    st = o.get("settings") or {}
    tag = remarks or o.get("tag") or ""
    if proto in ("freedom", "blackhole", "dns", "loopback", "direct", "block"):
        return None
    ss = o.get("streamSettings") if isinstance(o.get("streamSettings"), dict) else {}
    net = str(ss.get("network") or "tcp").lower()
    needs_xray = (net in ("xhttp", "splithttp", "kcp", "mkcp") or ((ss.get("tcpSettings") or {}).get("header") or {}).get("type") == "http")
    if proto in ("vless", "vmess") or proto == "trojan":
        v0 = ((st.get("vnext") or st.get("servers") or [{}])[0]) if (st.get("vnext") or st.get("servers")) else st
        u0 = ((v0.get("users") or [{}])[0]) if v0.get("users") else v0
        if proto == "vless" and str(u0.get("encryption") or "none") not in ("none", ""):
            needs_xray = True
        if needs_xray:  # as the provider wrote it: Xray runs it
            return {"type": "xray", "tag": tag, "server": v0.get("address"), "server_port": int(v0.get("port") or 0),
                    "xray": {"protocol": proto, "settings": st, "streamSettings": ss}}
    if proto in ("vless", "vmess"):
        v = (st.get("vnext") or [{}])[0] if st.get("vnext") else st
        user = (v.get("users") or [{}])[0] if v.get("users") else v
        host, port = v.get("address"), int(v.get("port") or 0)
        ob = {"type": proto, "tag": tag, "server": host, "server_port": port, "uuid": user.get("id")}
        if proto == "vless":
            ob["packet_encoding"] = "xudp"
            if user.get("flow"):
                ob["flow"] = user["flow"]
        else:
            ob["security"] = user.get("security") or "auto"
            ob["alter_id"] = int(user.get("alterId") or 0)
        return _secure(ob, _xray_q(o.get("streamSettings"), host), host)
    if proto == "trojan":
        s = (st.get("servers") or [{}])[0] if st.get("servers") else st
        host = s.get("address")
        ob = {"type": "trojan", "tag": tag, "server": host, "server_port": int(s.get("port") or 0), "password": s.get("password")}
        return _secure(ob, _xray_q(o.get("streamSettings"), host), host, "tls")
    if proto == "shadowsocks":
        s = (st.get("servers") or [{}])[0] if st.get("servers") else st
        return {"type": "shadowsocks", "tag": tag, "server": s.get("address"), "server_port": int(s.get("port") or 0),
                "method": s.get("method"), "password": s.get("password")}
    if proto == "socks":
        s = (st.get("servers") or [{}])[0] if st.get("servers") else st
        ob = {"type": "socks", "tag": tag, "server": s.get("address"), "server_port": int(s.get("port") or 0), "version": "5"}
        u = (s.get("users") or [{}])[0] if s.get("users") else {}
        if u.get("user"):
            ob["username"], ob["password"] = u["user"], u.get("pass", "")
        return ob
    if proto == "wireguard":
        peers = st.get("peers") or [{}]
        pr = peers[0] if isinstance(peers[0], dict) else {}
        host, _, port = str(pr.get("endpoint") or "").rpartition(":")
        ob = {"type": "wireguard", "tag": tag, "server": host.strip("[]"), "server_port": int(port or 0),
              "local_address": [st["address"]] if isinstance(st.get("address"), str) else list(st.get("address") or []),
              "private_key": st.get("secretKey"), "peer_public_key": pr.get("publicKey")}
        if pr.get("preSharedKey"):
            ob["pre_shared_key"] = pr["preSharedKey"]
        if isinstance(st.get("reserved"), list):
            ob["reserved"] = [int(x) for x in st["reserved"]][:3]
        if st.get("mtu"):
            ob["mtu"] = int(st["mtu"])
        return ob
    return None


def wg_from_endpoint(e):
    """A sing-box WireGuard `endpoint` as the outbound-style server this program keeps."""
    peers = e.get("peers") if isinstance(e.get("peers"), list) and e.get("peers") else [{}]
    pr = peers[0] if isinstance(peers[0], dict) else {}
    addr = e.get("address")
    o = {"type": "wireguard", "tag": str(e.get("tag") or ""), "server": pr.get("address"), "server_port": int(pr.get("port") or 0),
         "local_address": [addr] if isinstance(addr, str) else list(addr or []), "private_key": e.get("private_key"),
         "peer_public_key": pr.get("public_key")}
    if pr.get("pre_shared_key"):
        o["pre_shared_key"] = pr["pre_shared_key"]
    if isinstance(pr.get("reserved"), list):
        o["reserved"] = pr["reserved"]
    if e.get("mtu"):
        o["mtu"] = e["mtu"]
    return o


# ---------- Clash / Mihomo ----------
def _flow_value(s, i):
    """Value of a YAML flow collection starting at s[i]: (python value, next index)."""
    while i < len(s) and s[i] in " \t":
        i += 1
    if i >= len(s):
        return None, i
    c = s[i]
    if c == "{":
        out, i = {}, i + 1
        while True:
            while i < len(s) and s[i] in " \t,\n":
                i += 1
            if i >= len(s) or s[i] == "}":
                return out, i + 1
            start = i
            k, i = _flow_key(s, i)
            while i < len(s) and s[i] in " \t":
                i += 1
            if i < len(s) and s[i] == ":":
                i += 1
            v, i = _flow_value(s, i)
            out[k] = v
            if i <= start:  # a stray character that nothing consumes: skip it, never loop
                i = start + 1
    if c == "[":
        out, i = [], i + 1
        while True:
            while i < len(s) and s[i] in " \t,\n":
                i += 1
            if i >= len(s) or s[i] == "]":
                return out, i + 1
            start = i
            v, i = _flow_value(s, i)
            out.append(v)
            if i <= start:
                i = start + 1
    if c in "\"'":
        j, buf = i + 1, []
        while j < len(s):
            if s[j] == "\\" and c == '"' and j + 1 < len(s):
                buf.append({"n": "\n", "t": "\t"}.get(s[j + 1], s[j + 1]))
                j += 2
                continue
            if s[j] == c:
                if c == "'" and s[j + 1:j + 2] == "'":
                    buf.append("'")
                    j += 2
                    continue
                break
            buf.append(s[j])
            j += 1
        return "".join(buf), j + 1
    j = i
    while j < len(s) and s[j] not in ",}]":
        j += 1
    return _scalar(s[i:j].strip()), j


def _flow_key(s, i):
    if s[i] in "\"'":
        return _flow_value(s, i)
    j = i
    while j < len(s) and s[j] not in ":,}":
        j += 1
    return s[i:j].strip(), j


def _scalar(t):
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


def clash_proxies(text):
    """The `proxies` of a Clash file as a list of dicts. Without PyYAML only one-line `- {...}` entries are read."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                return [p for p in data["proxies"] if isinstance(p, dict)]
        except Exception:  # noqa: BLE001
            pass
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*-\s*(\{.*\})\s*(#.*)?$", line)
        if m:
            try:
                v, _ = _flow_value(m.group(1), 0)
                if isinstance(v, dict):
                    out.append(v)
            except Exception:  # noqa: BLE001
                continue
    return out


def clash_outbound(p):
    """One Clash proxy dict -> sing-box outbound (None if it is not a server; Unsupported if it cannot run)."""
    typ = str(p.get("type") or "").lower()
    host, port = str(p.get("server") or "").strip(), int(p.get("port") or 0)
    tag = str(p.get("name") or "")
    base = {"tag": tag, "server": host, "server_port": port}
    net = str(p.get("network") or "tcp").lower()
    ws, grpc, h2, ro = (p.get(k) or {} for k in ("ws-opts", "grpc-opts", "h2-opts", "reality-opts"))
    alpn = p.get("alpn") or []
    alpn = [alpn] if isinstance(alpn, str) else [str(a) for a in alpn]
    q = {"type": ["tcp" if net == "raw" else net], "sni": [str(p.get("servername") or p.get("sni") or "")],
         "fp": [str(p.get("client-fingerprint") or "")], "alpn": [",".join(alpn)],
         "allowInsecure": ["1" if p.get("skip-cert-verify") else "0"],
         "security": ["reality" if ro else "tls" if p.get("tls") else "none"]}
    if ro:
        q["pbk"], q["sid"] = [str(ro.get("public-key") or "")], [str(ro.get("short-id") or "")]
    if net == "ws":
        q["path"] = [ws.get("path") or "/"]
        q["host"] = [(ws.get("headers") or {}).get("Host") or (ws.get("headers") or {}).get("host") or ""]
        if ws.get("max-early-data"):
            q["path"] = [f"{q['path'][0]}{'&' if '?' in q['path'][0] else '?'}ed={ws['max-early-data']}"]
    elif net == "grpc":
        q["serviceName"] = [grpc.get("grpc-service-name") or ""]
    elif net in ("h2", "http"):
        h = h2.get("host") or (p.get("http-opts") or {}).get("headers", {}).get("Host") or []
        q["host"] = [h[0] if isinstance(h, list) and h else (h if isinstance(h, str) else "")]
        q["path"] = [h2.get("path") or "/"]
    if typ == "ss":
        o = dict(base, type="shadowsocks", method=str(p.get("cipher") or ""), password=str(p.get("password") or ""))
        plug, opts = str(p.get("plugin") or ""), p.get("plugin-opts") or {}
        if plug == "obfs":
            o["plugin"] = "obfs-local"
            o["plugin_opts"] = f"obfs={opts.get('mode', 'http')};obfs-host={opts.get('host', '')}"
        elif plug == "v2ray-plugin":
            o["plugin"] = "v2ray-plugin"
            parts = [f"mode={opts.get('mode', 'websocket')}"] + ([f"host={opts['host']}"] if opts.get("host") else []) \
                + ([f"path={opts['path']}"] if opts.get("path") else []) + (["tls"] if opts.get("tls") else [])
            o["plugin_opts"] = ";".join(parts)
        elif plug:
            raise Unsupported("other")
        return o
    if typ == "vmess":
        o = dict(base, type="vmess", uuid=str(p.get("uuid") or ""), security=str(p.get("cipher") or "auto"),
                 alter_id=int(p.get("alterId") or 0))
        return _secure(o, q, host)
    if typ == "vless":
        o = dict(base, type="vless", uuid=str(p.get("uuid") or ""), packet_encoding="xudp")
        if p.get("flow"):
            o["flow"] = str(p["flow"])
        enc = str(p.get("encryption") or "")
        if enc not in ("", "none"):
            return _to_xray(o, q, host, q["security"][0], enc)
        if net in ("xhttp", "splithttp"):  # Mihomo's own XHTTP options
            xo = p.get("xhttp-opts") or {}
            q["path"] = [xo.get("path") or "/"]
            q["host"] = [xo.get("host") or ""]
            q["mode"] = [xo.get("mode") or "auto"]
        return _secure(o, q, host)
    if typ == "trojan":
        o = dict(base, type="trojan", password=str(p.get("password") or ""))
        q["security"] = ["reality" if ro else "tls"]
        return _secure(o, q, host, "tls")
    if typ in ("hysteria2", "hy2"):
        o = dict(base, type="hysteria2", password=str(p.get("password") or ""),
                 tls={"enabled": True, "server_name": str(p.get("sni") or host), "insecure": bool(p.get("skip-cert-verify"))})
        if p.get("alpn"):
            o["tls"]["alpn"] = list(p["alpn"])
        if p.get("obfs"):
            o["obfs"] = {"type": str(p["obfs"]), "password": str(p.get("obfs-password") or "")}
        if p.get("ports"):
            o["server_ports"] = [r.replace("-", ":") for r in re.split(r"[,;]", str(p["ports"])) if r]
        for k_in, k_out in (("up", "up_mbps"), ("down", "down_mbps")):
            m = re.match(r"\d+", str(p.get(k_in) or ""))
            if m:
                o[k_out] = int(m.group(0))
        return o
    if typ == "hysteria":
        m1, m2 = re.match(r"\d+", str(p.get("up") or "")), re.match(r"\d+", str(p.get("down") or ""))
        o = dict(base, type="hysteria", up_mbps=int(m1.group(0)) if m1 else 100, down_mbps=int(m2.group(0)) if m2 else 100,
                 tls={"enabled": True, "server_name": str(p.get("sni") or host), "insecure": bool(p.get("skip-cert-verify"))})
        if p.get("auth-str") or p.get("auth_str"):
            o["auth_str"] = str(p.get("auth-str") or p.get("auth_str"))
        if p.get("alpn"):
            o["tls"]["alpn"] = list(p["alpn"])
        if p.get("obfs"):
            o["obfs"] = str(p["obfs"])
        return o
    if typ == "tuic":
        o = dict(base, type="tuic", uuid=str(p.get("uuid") or ""), password=str(p.get("password") or ""),
                 congestion_control=str(p.get("congestion-controller") or "bbr"),
                 tls={"enabled": True, "server_name": str(p.get("sni") or host), "insecure": bool(p.get("skip-cert-verify")),
                      "alpn": list(p.get("alpn") or ["h3"])})
        if p.get("udp-relay-mode"):
            o["udp_relay_mode"] = str(p["udp-relay-mode"])
        return o
    if typ == "anytls":
        return dict(base, type="anytls", password=str(p.get("password") or ""),
                    tls={"enabled": True, "server_name": str(p.get("sni") or host), "insecure": bool(p.get("skip-cert-verify"))})
    if typ in ("socks5", "socks"):
        o = dict(base, type="socks", version="5")
        if p.get("username"):
            o["username"], o["password"] = str(p["username"]), str(p.get("password") or "")
        return o
    if typ == "wireguard":
        if p.get("amnezia-wg-option"):
            raise Unsupported("amneziawg")
        addr = [str(a) if "/" in str(a) else str(a) + ("/128" if ":" in str(a) else "/32")
                for a in (p.get("ip"), p.get("ipv6")) if a]
        o = dict(base, type="wireguard", local_address=addr or ["10.0.0.2/32"], private_key=str(p.get("private-key") or ""),
                 peer_public_key=str(p.get("public-key") or ""))
        if p.get("pre-shared-key"):
            o["pre_shared_key"] = str(p["pre-shared-key"])
        if isinstance(p.get("reserved"), list):
            o["reserved"] = [int(x) for x in p["reserved"]][:3]
        if p.get("mtu"):
            o["mtu"] = int(p["mtu"])
        return o
    if typ == "ssr":
        raise Unsupported("ssr")
    if typ == "ssh":
        o = dict(base, type="ssh", user=str(p.get("username") or ""))
        if p.get("password"):
            o["password"] = str(p["password"])
        return o
    if typ in ("snell", "mieru"):
        raise Unsupported(typ)
    if typ in ("http", "direct", "reject", "dns", ""):
        return None
    raise Unsupported("other")


# ---------- SIP008 (Shadowsocks) ----------
def sip008_outbound(s):
    return {"type": "shadowsocks", "tag": str(s.get("remarks") or s.get("name") or ""), "server": str(s.get("server") or ""),
            "server_port": int(s.get("server_port") or s.get("port") or 0), "method": str(s.get("method") or ""),
            "password": str(s.get("password") or "")}


_XRAY_PLUMBING = ("freedom", "blackhole", "dns", "loopback", "direct", "block")


def _from_json(data, skipped, remarks=""):
    """Servers out of a decoded JSON document of any of the shapes providers use."""
    outs = []

    def add(fn, *a):
        try:
            o = fn(*a)
        except Unsupported as e:
            skipped[str(e)] += 1
            return
        except Exception:  # noqa: BLE001
            return
        if o:
            outs.append(o)

    if isinstance(data, list):
        for el in data:
            if isinstance(el, dict):
                outs += _from_json(el, skipped)
            elif isinstance(el, str):
                sk = []
                o = parse_link(el, sk)
                skipped.update(sk)
                if o:
                    outs.append(o)
        return outs
    if not isinstance(data, dict):
        return outs
    remarks = str(data.get("remarks") or data.get("name") or remarks or "")
    ob = data.get("outbounds")
    if isinstance(ob, list):
        proxies = [x for x in ob if isinstance(x, dict) and x.get("protocol") and not x.get("type")
                   and str(x["protocol"]).lower() not in _XRAY_PLUMBING]
        for x in ob:
            if isinstance(x, dict) and x.get("type"):
                outs.append(clean_outbound(x))
        for x in proxies:
            add(xray_outbound, x, remarks if len(proxies) == 1 else "")
    if isinstance(data.get("endpoints"), list):
        for e in data["endpoints"]:
            if isinstance(e, dict) and e.get("type") == "wireguard":
                add(wg_from_endpoint, e)
    if isinstance(data.get("servers"), list):
        for s in data["servers"]:
            if isinstance(s, dict) and (s.get("server") or s.get("password")):
                add(sip008_outbound, s)
    if isinstance(data.get("proxies"), list):
        for p in data["proxies"]:
            if isinstance(p, dict):
                add(clash_outbound, p)
    for k in ("data", "nodes", "configs"):  # some panels wrap the document
        if isinstance(data.get(k), (list, dict)):
            outs += _from_json(data[k], skipped)
    return outs


def parse_text_ex(text, _depth=0):
    """(servers, Counter of reasons for the ones left out) from any blob a subscription may come as: share links one
    per line, base64 of that (or of a file), a sing-box / Xray / SIP008 / Clash document. Only entries that pass
    valid_outbound come back; a bad one costs that one server, never the list."""
    text = clean_blob(text)
    skipped = Counter()
    outs = []
    if text[:1] in ("{", "["):
        try:
            outs = _from_json(json.loads(text), skipped)
        except Exception:  # noqa: BLE001
            outs = []
    elif re.search(r"(?m)^\s*proxies\s*:", text) or re.search(r"(?m)^\s*-\s*\{.*\btype\s*:", text):
        for p in clash_proxies(text):
            try:
                o = clash_outbound(p)
            except Unsupported as e:
                skipped[str(e)] += 1
                continue
            except Exception:  # noqa: BLE001
                continue
            if o:
                outs.append(o)
    elif "://" not in text and _depth < 2 and text:  # base64 never contains "://"
        try:
            decoded = b64d(text)
        except Exception:  # noqa: BLE001
            decoded = ""
        if decoded and decoded.strip():
            return parse_text_ex(decoded, _depth + 1)
    else:
        for line in re.split(r"[\r\n]+", text):
            sk = []
            o = parse_link(line, sk)
            skipped.update(sk)
            if o:
                outs.append(o)
    outs = [o for o in outs if valid_outbound(o)]
    return _unique_tags(outs), skipped


def parse_text(text: str):
    return parse_text_ex(text)[0]


def skipped_note(skipped):
    """'пропущено 3 сервера: транспорт XHTTP (3)' for the status line, '' if nothing was left out."""
    skipped = Counter(skipped or {})
    if not skipped:
        return ""
    n = sum(skipped.values())
    parts = ", ".join(f"{WHY.get(k, k)}: {v}" for k, v in skipped.most_common())
    word = "сервер" if n % 10 == 1 and n % 100 != 11 else "сервера" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else "серверов"
    return f"Пропущено {n} {word}, которые программа не умеет запускать ({parts})."


def _unique_tags(outs):
    """Every server gets a non-empty tag of its own that does not collide with the config's reserved ones."""
    seen = {}
    for o in outs:
        t = o.get("tag") or f"{o['type']}-{o.get('server', '?')}:{o.get('server_port', '')}"
        t = t.strip()[:120] or f"{o['type']}-{o.get('server', '?')}"
        if t in ("proxy", "direct", "AUTO"):
            t += " (node)"
        if t in seen:
            seen[t] += 1
            t = f"{t} ({seen[t]})"
        else:
            seen[t] = 1
        o["tag"] = t
    return outs


# ---------- what the user pastes into the box ----------
# Apps open a subscription from a link of their own kind: sing-box://import-remote-profile?url=..., clash://install-config?url=...
DEEP_SCHEMES = ("sing-box", "singbox", "clash", "clashmeta", "clash-verge", "stash", "surge", "hiddify", "v2rayn", "v2rayng",
                "happ", "streisand", "shadowrocket", "karing", "flclash", "nekobox", "husi", "sub", "quantumult", "loon",
                "v2box", "foxray", "anxray", "exclave", "mihomo", "throne", "nekoray", "sagernet", "karing")
_DEEP_RE = re.compile(r"(?i)^(" + "|".join(re.escape(s) for s in DEEP_SCHEMES) + r"):/{0,3}")
_URL_IN = re.compile(r"(?i)https?(?::|%3A)(?://|%2F%2F)[^\s<>\"']+")
_URL_TOKEN = re.compile(r"(?i)https?://[^\s<>\"'`]+")
_BARE = re.compile(r"(?i)^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(:\d+)?(/\S*)?$")


def unwrap_deeplink(line):
    """The subscription address inside an "open in the app" link, '' if the line is not one."""
    m = _DEEP_RE.match(line)
    if not m:
        return ""
    scheme, rest = m.group(1).lower(), line[m.end():]
    if scheme == "sub":  # Shadowrocket: sub://base64(address)#name
        try:
            inner = b64d(rest.split("#")[0])
            if inner.lower().startswith(("http://", "https://")):
                return inner.strip()
        except Exception:  # noqa: BLE001
            return ""
    for cand in (rest, unquote(rest), unquote(unquote(rest))):
        q = parse_qs(urlparse("x://h/?" + cand.split("?", 1)[-1].split("#")[0]).query)
        for key in ("url", "link", "sub", "remote-resource", "config"):
            v = (q.get(key) or [""])[0]
            if v:
                v = unquote(v) if v.lower().startswith(("https%3a", "http%3a")) else v
                if v.lower().startswith(("http://", "https://")):
                    return v.strip()
        m2 = _URL_IN.search(cand)
        if m2:
            u = unquote(m2.group(0)) if "%3A" in m2.group(0).upper()[:8] else m2.group(0)
            return u.split("#")[0].strip().rstrip(".,;)")
    return ""


def source_lines(text):
    """The lines of the "subscriptions" box in the form the program works with: each is a subscription address
    (https://...) or a share link or a piece of a pasted blob. Deep links are unwrapped, several addresses in one
    line are separated, a bare "sub.example.com/key" gets https://, quotes and brackets around an address go."""
    out = []
    pairs = {'"': '"', "'": "'", "`": "`", "<": ">", "(": ")", "[": "]"}
    for raw in re.split(r"[\r\n]+", clean_blob(text)):
        line = raw.strip()
        md = re.search(r"\[[^\]]*\]\((https?://[^)\s]+)\)", line)  # [text](address) from a chat or a page
        if md:
            line = md.group(1)
        while len(line) > 1 and pairs.get(line[0]) == line[-1]:
            line = line[1:-1].strip()
        if not line or line.startswith(("#", "//")):
            continue
        inner = unwrap_deeplink(line)
        if inner:
            out.append(inner)
            continue
        if LINK_RE.search(line):
            out.append(line)  # a share link: its name may hold spaces, so the line stays whole
            continue
        urls = [u for tok in _URL_TOKEN.findall(line) for u in re.split(r"[,;](?=(?i:https?://))", tok)]  # one, several, or inside a sentence
        if urls:
            out += [u.rstrip(".,;)") for u in urls]
            continue
        if _BARE.match(line):
            out.append("https://" + line)
            continue
        out.append(line)
    return out


def split_sources(text):
    """(subscription addresses, everything else) of the box."""
    urls, rest = [], []
    for line in source_lines(text):
        (urls if line.lower().startswith(("http://", "https://")) else rest).append(line)
    return urls, rest


def parse_inline(lines):
    """Servers from the non-address lines of the box: share links one by one, the rest (a pasted base64 blob, JSON, YAML)
    together as one text. Returns (servers, Counter of reasons for the ones left out)."""
    skipped, outs = Counter(), []
    blob = []
    for line in lines:
        if LINK_RE.search(line):
            sk = []
            o = parse_link(line, sk)
            skipped.update(sk)
            if o and valid_outbound(o):
                outs.append(o)
        else:
            blob.append(line)
    if blob:
        o2, s2 = parse_text_ex("\n".join(blob))
        outs += o2
        skipped.update(s2)
    return _unique_tags(outs), skipped
