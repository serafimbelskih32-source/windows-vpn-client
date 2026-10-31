"""Flat flags in the app's style: hard-edged rectangles, solid colours, an ink outline, no gradients.

Windows has no colour flag emoji (it shows letters like "FI"), so the flag is drawn here from simple geometry and
handed to Tk as pixel rows. No GUI imports: everything below is plain Python and testable anywhere.
A flag is a list of paint operations in unit coordinates (u right, v down, both 0..1); later operations paint over
earlier ones. Circles and stars use the height as the unit, so they stay round on a 3:2 rectangle.
"""
import math
import re

INK = "#12151B"

# stripes: ("H"|"V", [(colour, weight), ...])   rect: ("R", colour, x0, y0, x1, y1)   circle: ("C", colour, cx, cy, r)
# star: ("S", colour, cx, cy, r)   triangle: ("T", colour, ax, ay, bx, by, cx, cy)   line: ("L", colour, ax, ay, bx, by, w)
W, K = "#FFFFFF", "#000000"


def _eq(*cols):
    return [(c, 1) for c in cols]


def _cross(bg, fg, vx0, vx1, hy0, hy1):
    return [("R", bg, 0, 0, 1, 1), ("R", fg, vx0, 0, vx1, 1), ("R", fg, 0, hy0, 1, hy1)]


def _nordic(bg, outer, inner):
    ops = [("R", bg, 0, 0, 1, 1), ("R", outer, 0.25, 0, 0.45, 1), ("R", outer, 0, 0.34, 1, 0.66)]
    return ops + [("R", inner, 0.30, 0, 0.40, 1), ("R", inner, 0, 0.42, 1, 0.58)]


def _us():
    ops = [("H", [("#B22234" if i % 2 == 0 else W, 1) for i in range(13)]), ("R", "#3C3B6E", 0, 0, 0.42, 0.54)]
    for cx in (0.1, 0.21, 0.32):
        for cy in (0.12, 0.27, 0.42):
            ops.append(("C", W, cx, cy, 0.035))
    return ops


FLAGS = {
    "RU": [("H", _eq(W, "#0039A6", "#D52B1E"))],
    "NL": [("H", _eq("#AE1C28", W, "#21468B"))],
    "DE": [("H", _eq(K, "#DD0000", "#FFCE00"))],
    "LU": [("H", _eq("#ED2939", W, "#00A1DE"))],
    "AT": [("H", _eq("#ED2939", W, "#ED2939"))],
    "HU": [("H", _eq("#CD2A3E", W, "#436F4D"))],
    "BG": [("H", _eq(W, "#00966E", "#D62612"))],
    "EE": [("H", _eq("#0072CE", K, W))],
    "LT": [("H", _eq("#FDB913", "#006A44", "#C1272D"))],
    "LV": [("H", [("#9E3039", 2), (W, 1), ("#9E3039", 2)])],
    "PL": [("H", _eq(W, "#DC143C"))],
    "UA": [("H", _eq("#0057B8", "#FFD700"))],
    "ID": [("H", _eq("#FF0000", W))],
    "MC": [("H", _eq("#CE1126", W))],
    "SK": [("H", _eq(W, "#0B4EA2", "#EE1C25")), ("R", "#EE1C25", 0.1, 0.2, 0.36, 0.8), ("R", W, 0.21, 0.3, 0.25, 0.7),
           ("R", W, 0.15, 0.42, 0.31, 0.48)],
    "SI": [("H", _eq(W, "#005DA4", "#ED1C24")), ("R", "#005DA4", 0.1, 0.12, 0.34, 0.62), ("T", W, 0.22, 0.28, 0.16, 0.5, 0.28, 0.5)],
    "RS": [("H", _eq("#C6363C", "#0C4076", W))],
    "HR": [("H", _eq("#FF0000", W, "#171796")), ("R", "#FF0000", 0.36, 0.22, 0.64, 0.78), ("R", W, 0.36, 0.22, 0.43, 0.36),
           ("R", W, 0.5, 0.22, 0.57, 0.36), ("R", W, 0.43, 0.36, 0.5, 0.5), ("R", W, 0.57, 0.36, 0.64, 0.5),
           ("R", W, 0.36, 0.5, 0.43, 0.64), ("R", W, 0.5, 0.5, 0.57, 0.64), ("R", W, 0.43, 0.64, 0.5, 0.78),
           ("R", W, 0.57, 0.64, 0.64, 0.78)],
    "AM": [("H", _eq("#D90012", "#0033A0", "#F2A800"))],
    "BY": [("H", [("#C8313E", 2), ("#4AA657", 1)]), ("R", W, 0, 0, 0.13, 1)] +
          [("R", "#C8313E", 0.03, y, 0.1, y + 0.1) for y in (0.08, 0.31, 0.54, 0.77)],
    "CZ": [("H", _eq(W, "#D7141A")), ("T", "#11457E", 0, 0, 0.5, 0.5, 0, 1)],
    "IE": [("V", _eq("#169B62", W, "#FF883E"))],
    "FR": [("V", _eq("#0055A4", W, "#EF4135"))],
    "IT": [("V", _eq("#009246", W, "#CE2B37"))],
    "BE": [("V", _eq(K, "#FDDA24", "#EF3340"))],
    "RO": [("V", _eq("#002B7F", "#FCD116", "#CE1126"))],
    "MD": [("V", _eq("#0046AE", "#FFD200", "#CC092F"))],
    "MX": [("V", _eq("#006847", W, "#CE1126")), ("C", "#8C5A2B", 0.5, 0.5, 0.1)],
    "ES": [("H", [("#AA151B", 1), ("#F1BF00", 2), ("#AA151B", 1)])],
    "PT": [("V", [("#006600", 2), ("#FF0000", 3)]), ("C", "#FFE000", 0.4, 0.5, 0.16)],
    "TH": [("H", [("#A51931", 1), (W, 1), ("#2D2A4A", 2), (W, 1), ("#A51931", 1)])],
    "AR": [("H", _eq("#74ACDF", W, "#74ACDF")), ("C", "#F6B40E", 0.5, 0.5, 0.08)],
    "IN": [("H", _eq("#FF9933", W, "#138808")), ("C", "#000080", 0.5, 0.5, 0.1)],
    "AE": [("H", _eq("#00732F", W, K)), ("R", "#FF0000", 0, 0, 0.25, 1)],
    "AZ": [("H", _eq("#00B5E2", "#EF3340", "#509E2F")), ("C", W, 0.46, 0.5, 0.14), ("C", "#EF3340", 0.51, 0.5, 0.12),
           ("S", W, 0.62, 0.5, 0.07)],
    "CL": [("H", _eq(W, "#D52B1E")), ("R", "#0039A6", 0, 0, 0.33, 0.5), ("S", W, 0.165, 0.25, 0.14)],
    "CH": _cross("#DA291C", W, 0.43, 0.57, 0.38, 0.62)[:1] + [("R", W, 0.43, 0.2, 0.57, 0.8), ("R", W, 0.28, 0.38, 0.72, 0.62)],
    "FI": _cross(W, "#003580", 0.28, 0.42, 0.38, 0.62),
    "SE": _cross("#006AA7", "#FECC02", 0.28, 0.42, 0.4, 0.6),
    "DK": _cross("#C8102E", W, 0.27, 0.40, 0.42, 0.58),
    "NO": _nordic("#BA0C2F", W, "#00205B"),
    "IS": _nordic("#02529C", W, "#DC1E35"),
    "GE": [("R", W, 0, 0, 1, 1), ("R", "#FF0000", 0.44, 0, 0.56, 1), ("R", "#FF0000", 0, 0.42, 1, 0.58)] +
          [op for cx, cy in ((0.22, 0.22), (0.78, 0.22), (0.22, 0.76), (0.78, 0.76))
           for op in (("R", "#FF0000", cx - 0.03, cy - 0.11, cx + 0.03, cy + 0.11),
                      ("R", "#FF0000", cx - 0.09, cy - 0.04, cx + 0.09, cy + 0.04))],
    "JP": [("R", W, 0, 0, 1, 1), ("C", "#BC002D", 0.5, 0.5, 0.3)],
    "KR": [("R", W, 0, 0, 1, 1), ("C", "#CD2E3A", 0.5, 0.5, 0.28), ("B", "#0047A0", 0.5, 0.5, 0.28),
           ("C", "#CD2E3A", 0.5, 0.64, 0.14), ("C", "#0047A0", 0.5, 0.36, 0.14)],
    "CN": [("R", "#DE2910", 0, 0, 1, 1), ("S", "#FFDE00", 0.2, 0.32, 0.22)] +
          [("C", "#FFDE00", x, y, 0.04) for x, y in ((0.38, 0.14), (0.44, 0.26), (0.44, 0.4), (0.38, 0.52))],
    "HK": [("R", "#DE2910", 0, 0, 1, 1), ("S", W, 0.5, 0.5, 0.26)],
    "VN": [("R", "#DA251D", 0, 0, 1, 1), ("S", "#FFFF00", 0.5, 0.52, 0.3)],
    "TR": [("R", "#E30A17", 0, 0, 1, 1), ("C", W, 0.38, 0.5, 0.26), ("C", "#E30A17", 0.45, 0.5, 0.21),
           ("S", W, 0.62, 0.5, 0.12)],
    "SG": [("H", _eq("#EF3340", W)), ("C", W, 0.2, 0.25, 0.16), ("C", "#EF3340", 0.26, 0.25, 0.16),
           ("C", W, 0.36, 0.14, 0.03), ("C", W, 0.4, 0.26, 0.03), ("C", W, 0.34, 0.38, 0.03)],
    "KZ": [("R", "#00AFCA", 0, 0, 1, 1), ("C", "#FEC50C", 0.5, 0.5, 0.2)],
    "IL": [("R", W, 0, 0, 1, 1), ("R", "#0038B8", 0, 0.1, 1, 0.22), ("R", "#0038B8", 0, 0.78, 1, 0.9),
           ("T", "#0038B8", 0.5, 0.3, 0.36, 0.62, 0.64, 0.62), ("T", "#0038B8", 0.5, 0.72, 0.36, 0.38, 0.64, 0.38)],
    "BR": [("R", "#009C3B", 0, 0, 1, 1), ("T", "#FFDF00", 0.5, 0.1, 0.1, 0.5, 0.9, 0.5),
           ("T", "#FFDF00", 0.1, 0.5, 0.9, 0.5, 0.5, 0.9), ("C", "#002776", 0.5, 0.5, 0.2)],
    "CA": [("V", [("#D80621", 1), (W, 2), ("#D80621", 1)]), ("T", "#D80621", 0.5, 0.18, 0.4, 0.62, 0.6, 0.62),
           ("C", "#D80621", 0.5, 0.48, 0.15)],
    "GB": [("R", "#012169", 0, 0, 1, 1), ("L", W, 0, 0, 1, 1, 0.22), ("L", W, 0, 1, 1, 0, 0.22),
           ("L", "#C8102E", 0, 0, 1, 1, 0.08), ("L", "#C8102E", 0, 1, 1, 0, 0.08),
           ("R", W, 0.4, 0, 0.6, 1), ("R", W, 0, 0.34, 1, 0.66), ("R", "#C8102E", 0.44, 0, 0.56, 1),
           ("R", "#C8102E", 0, 0.42, 1, 0.58)],
    "US": _us(),
    "AU": [("R", "#00247D", 0, 0, 1, 1), ("R", "#00247D", 0, 0, 0.5, 0.5), ("R", W, 0.2, 0, 0.3, 0.5),
           ("R", W, 0, 0.2, 0.5, 0.3), ("R", "#CF142B", 0.23, 0, 0.27, 0.5), ("R", "#CF142B", 0, 0.23, 0.5, 0.27),
           ("S", W, 0.25, 0.78, 0.15), ("C", W, 0.74, 0.2, 0.04), ("C", W, 0.86, 0.42, 0.04), ("C", W, 0.74, 0.74, 0.04),
           ("C", W, 0.62, 0.45, 0.04)],
    "GR": [("H", [("#0D5EAF" if i % 2 == 0 else W, 1) for i in range(9)]), ("R", "#0D5EAF", 0, 0, 0.42, 0.56),
           ("R", W, 0.17, 0, 0.25, 0.56), ("R", W, 0, 0.24, 0.42, 0.32)],
    "EU": [("R", "#003399", 0, 0, 1, 1)] +
          [("C", "#FFCC00", 0.5 + 0.3 * math.cos(math.radians(a)) / 1.5, 0.5 + 0.3 * math.sin(math.radians(a)), 0.055)
           for a in range(0, 360, 30)],
    # the "Auto" row of the server list: not a country, a blue tile with a bolt
    "AUTO": [("R", "#1E3CFF", 0, 0, 1, 1), ("T", W, 0.58, 0.08, 0.28, 0.56, 0.52, 0.56), ("T", W, 0.48, 0.44, 0.72, 0.44, 0.42, 0.92)],
    # unknown country: neutral tile with a diagonal, so rows still line up
    "??": [("R", "#C7CBD1", 0, 0, 1, 1), ("L", "#555C67", 0.15, 0.85, 0.85, 0.15, 0.1)],
}

# country names (Russian and English) -> code, for server names without a flag emoji
NAMES = {
    "RU": "россия russia", "US": "сша usa америка united states", "DE": "германия germany", "NL": "нидерланды netherlands holland",
    "FI": "финляндия finland", "SE": "швеция sweden", "PL": "польша poland", "LT": "литва lithuania", "LV": "латвия latvia",
    "EE": "эстония estonia", "FR": "франция france", "GB": "великобритания англия britain england united kingdom uk",
    "TR": "турция turkey turkiye", "IN": "индия india", "JP": "япония japan", "KR": "корея korea", "SG": "сингапур singapore",
    "HK": "гонконг hong kong hongkong", "CN": "китай china", "UA": "украина ukraine", "KZ": "казахстан kazakhstan",
    "BY": "беларусь belarus", "AM": "армения armenia", "GE": "грузия georgia", "AZ": "азербайджан azerbaijan",
    "IL": "израиль israel", "AE": "оаэ эмираты uae emirates", "CA": "канада canada", "BR": "бразилия brazil",
    "AR": "аргентина argentina", "MX": "мексика mexico", "AU": "австралия australia", "CH": "швейцария switzerland",
    "AT": "австрия austria", "IT": "италия italy", "ES": "испания spain", "PT": "португалия portugal",
    "LU": "люксембург luxembourg", "BE": "бельгия belgium", "DK": "дания denmark", "NO": "норвегия norway",
    "CZ": "чехия czechia czech", "SK": "словакия slovakia", "HU": "венгрия hungary", "RO": "румыния romania",
    "BG": "болгария bulgaria", "RS": "сербия serbia", "HR": "хорватия croatia", "SI": "словения slovenia",
    "GR": "греция greece", "IE": "ирландия ireland", "IS": "исландия iceland", "MD": "молдова moldova",
    "VN": "вьетнам vietnam", "TH": "таиланд thailand", "ID": "индонезия indonesia", "CL": "чили chile", "MC": "монако monaco",
}
_WORDS = sorted(((w, c) for c, ws in NAMES.items() for w in ws.split(" ") if w), key=lambda wc: -len(wc[0]))
_NAME_RE = [(re.compile(r"(?<![a-zа-яё])" + re.escape(w) + r"(?![a-zа-яё])", re.I), c) for w, c in _WORDS]
_FLAG_EMOJI = re.compile("^[\\s‍️]*([\U0001F1E6-\U0001F1FF])([\U0001F1E6-\U0001F1FF])[\\s‍️]*")


def code_for(tag):
    """Country code of a server name: from its flag emoji, else from a country name in it, else '??'."""
    m = _FLAG_EMOJI.match(tag or "")
    if m:
        code = "".join(chr(ord(ch) - 0x1F1E6 + 65) for ch in m.groups())
        if code in FLAGS:
            return code
    low = (tag or "").lower()
    for rx, code in _NAME_RE:
        if rx.search(low):
            return code
    return "??"


def strip_flag(tag):
    """The server name without its leading flag emoji (the app draws its own flag next to it)."""
    return _FLAG_EMOJI.sub("", tag or "", count=1).strip() or tag


# ----- rendering -----
def _hex(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


def _band(stripes, t):
    total = sum(w for _, w in stripes)
    acc = 0.0
    for colour, w in stripes:
        acc += w / total
        if t < acc:
            return colour
    return stripes[-1][0]


def _in_poly(px, py, pts):
    inside = False
    j = len(pts) - 1
    for i in range(len(pts)):
        (xi, yi), (xj, yj) = pts[i], pts[j]
        if (yi > py) != (yj > py) and px < (xj - xi) * (py - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _star(cx, cy, r):
    pts = []
    for k in range(10):
        a = math.radians(-90 + 36 * k)
        rad = r if k % 2 == 0 else r * 0.382
        pts.append((cx + rad * math.cos(a), cy + rad * math.sin(a)))
    return pts


def _seg_dist(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy or 1)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def pixel(ops, u, v, aspect):
    """Colour at (u, v), or None when no operation paints there. x is stretched by `aspect` for round shapes."""
    x, y, out = u * aspect, v, None
    for op in ops:
        kind = op[0]
        if kind == "H":
            out = _band(op[1], v)
        elif kind == "V":
            out = _band(op[1], u)
        elif kind == "R":
            if op[2] <= u < op[4] and op[3] <= v < op[5]:
                out = op[1]
        elif kind == "C":
            if (x - op[2] * aspect) ** 2 + (y - op[3]) ** 2 <= op[4] ** 2:
                out = op[1]
        elif kind == "B":  # lower half of a circle: ("B", colour, cx, cy, r)
            if (x - op[2] * aspect) ** 2 + (y - op[3]) ** 2 <= op[4] ** 2 and v >= op[3]:
                out = op[1]
        elif kind == "S":
            if _in_poly(x, y, _star(op[2] * aspect, op[3], op[4])):
                out = op[1]
        elif kind == "T":
            if _in_poly(x, y, [(op[2] * aspect, op[3]), (op[4] * aspect, op[5]), (op[6] * aspect, op[7])]):
                out = op[1]
        elif kind == "L":
            if _seg_dist(x, y, op[2] * aspect, op[3], op[4] * aspect, op[5]) <= op[6] / 2:
                out = op[1]
    return out


def render(code, w, h, border=1, accent=None, ink=None):
    """Pixel rows (lists of '#rrggbb') for a w x h flag with an outline of `border` pixels in `ink` (default: dark).
    `accent` recolours the blue of the "fastest of the list" badge."""
    ops = FLAGS.get(code) or FLAGS["??"]
    if accent and code == "AUTO":
        ops = [(op[0], accent) + tuple(op[2:]) if op[1] == "#1E3CFF" else op for op in ops]
    edge = ink or INK
    aspect = w / h
    rows = []
    for yy in range(h):
        row = []
        for xx in range(w):
            if xx < border or yy < border or xx >= w - border or yy >= h - border:
                row.append(edge)
                continue
            iu, iv = (xx - border + 0.5) / (w - 2 * border), (yy - border + 0.5) / (h - 2 * border)
            row.append(pixel(ops, iu, iv, aspect) or "#C7CBD1")
        rows.append(row)
    return rows


def to_tk_data(rows):
    """The `data` string of Tk's PhotoImage.put: '{#fff #000} {#000 #fff}' (one braced group per row)."""
    return " ".join("{" + " ".join(r) + "}" for r in rows)
