"""How the servers the core (sing-box) cannot run on its own are served.

* An "xray" server (XHTTP, mKCP, VLESS with its own encryption, an HTTP header on TCP) is run by a companion Xray process:
  it listens on a local port, and the core sees that port as an ordinary SOCKS server with the server's name.
* A WireGuard server is a sing-box "endpoint", not an outbound; it is moved there when the config is made.
No GUI, no network: tested on its own (tests/test_engines.py)."""
import copy
import json
import re

XRAY_BASE_PORT = 21400  # first local port tried for the companion's SOCKS inbounds


def is_xray(o):
    return isinstance(o, dict) and o.get("type") == "xray"


def has_xray(outs):
    return any(is_xray(o) for o in outs)


def proto_label(o):
    """The short name in the protocol column for a server that is not a plain outbound, else None."""
    if is_xray(o):
        x = o.get("xray") or {}
        net = (x.get("streamSettings") or {}).get("network", "tcp")
        return {"xhttp": "XHTTP", "kcp": "MKCP"}.get(net, (x.get("protocol") or "xray").upper() + "+")
    return None


def xray_with_address(o, ip):
    """The Xray outbound of server `o` with the address replaced by `ip` (so Xray needs no DNS), keeping the name that
    TLS and REALITY check: it is made explicit first, because it defaults to the address."""
    x = copy.deepcopy(o["xray"])
    host = o["server"]
    ss = x.get("streamSettings") or {}
    for key in ("tlsSettings", "realitySettings"):
        if isinstance(ss.get(key), dict) and not ss[key].get("serverName"):
            ss[key]["serverName"] = host
    xs = ss.get("xhttpSettings")
    if isinstance(xs, dict) and not xs.get("host") and ss.get("security") == "none":
        xs["host"] = host
    for block in (x.get("settings") or {}).get("vnext", []) + (x.get("settings") or {}).get("servers", []):
        if isinstance(block, dict):
            block["address"] = ip
    x["streamSettings"] = ss
    return x


def xray_config(outs, ports, log_path=None, nic=None, loglevel="warning"):
    """The companion Xray's config: one local SOCKS inbound per "xray" server in `outs`, wired to that server's outbound.
    `ports` = {tag: local port}. `nic` = name of the real network adapter to bind outgoing sockets to (so a test goes
    around any VPN that is up)."""
    inbounds, outbounds, rules = [], [], []
    for i, o in enumerate(x for x in outs if is_xray(x)):
        ob = copy.deepcopy(o["xray"])
        ob.pop("mux", None)
        ob.pop("proxySettings", None)
        ob["tag"] = f"out{i}"
        if nic:
            ss = ob.setdefault("streamSettings", {})
            ss["sockopt"] = dict(ss.get("sockopt") or {}, interface=nic)
        inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": ports[o["tag"]], "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": True}})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    log = {"loglevel": loglevel}
    if log_path:
        log["error"] = log_path
    return {"log": log, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def wg_endpoint(o):
    """A WireGuard server as a sing-box endpoint (the outbound form of it is gone from the core)."""
    peer = {"address": o["server"], "port": o["server_port"], "public_key": o["peer_public_key"],
            "allowed_ips": ["0.0.0.0/0", "::/0"]}
    if o.get("pre_shared_key"):
        peer["pre_shared_key"] = o["pre_shared_key"]
    if isinstance(o.get("reserved"), list) and len(o["reserved"]) == 3:
        peer["reserved"] = o["reserved"]
    ep = {"type": "wireguard", "tag": o["tag"], "address": list(o["local_address"]), "private_key": o["private_key"],
          "peers": [peer]}
    if o.get("mtu"):
        ep["mtu"] = o["mtu"]
    return ep


def to_singbox(outs, ports=None):
    """(outbounds, endpoints) for the core's config. An "xray" server becomes a SOCKS outbound to its local port (one
    without a port is left out: nothing serves it)."""
    outbounds, endpoints = [], []
    for o in outs:
        if is_xray(o):
            port = (ports or {}).get(o["tag"])
            if port:
                outbounds.append({"type": "socks", "tag": o["tag"], "server": "127.0.0.1", "server_port": port, "version": "5"})
        elif o.get("type") == "wireguard":
            endpoints.append(wg_endpoint(o))
        else:
            outbounds.append(o)
    return outbounds, endpoints


def usable(outs, xray_ok):
    """The servers that can be run at all: without a working Xray the "xray" ones cannot."""
    return [o for o in outs if xray_ok or not is_xray(o)]
