"""Which server is the best one: the response time (ping) and the speed weighed together. No window, no network.

Ping and speed matter for different things. A short exchange (a page, a message, a call, a game) is mostly waiting, and
waiting is the ping: past 5-10 Mbit/s more speed changes nothing there. A long transfer (a video, a download) is mostly
bytes, and bytes are the speed: 30 ms more ping changes nothing there. A server with the lowest ping but 5 Mbit/s is bad
for the second, one with 150 Mbit/s and a ping a little higher is good for both. So each of the two becomes a factor from
0 to 1 that saturates (a better ping or more speed helps less and less), and the score is their product, each raised to
a power that says how much the user cares about it ("focus")."""

LATENCY_HALF = 120.0   # ms: at this response time the factor is a half
SPEED_HALF = 25.0      # Mbit/s: at this speed the factor is a half
MARGIN = 1.25          # another server must score this much better than the current one to be worth a switch
FOCUS = {              # (power of the ping factor, power of the speed factor)
    "balanced": (1.0, 1.0),  # calls, pages, video: the default
    "latency": (2.0, 0.5),   # messengers, calls, games, browsing: the response time first
    "speed": (0.5, 2.0),     # video, downloads: the speed first
}


def latency_factor(ms):
    return 1.0 / (1.0 + (ms / LATENCY_HALF) ** 2)


def speed_factor(mbit):
    return mbit / (mbit + SPEED_HALF)


def usable(value):
    """A measurement that is a number and not a failure (the program writes a negative one for 'tried, no answer')."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def assumed_speed(results):
    """What to take for a server whose speed was not measured: the lower quarter of those that were (a guess a bit on
    the careful side, so a measured good server is not beaten by an unknown one). None when nothing was measured."""
    speeds = sorted(sp for ms, sp in results.values() if usable(ms) and usable(sp))
    return speeds[len(speeds) // 4] if speeds else None


def score(ms, mbit, focus="balanced", assumed=None):
    """0 for a server that does not answer, else 0..1 (higher is better). Without a speed the ping decides alone."""
    if not usable(ms):
        return 0.0
    a, b = FOCUS.get(focus, FOCUS["balanced"])
    speed = mbit if usable(mbit) else assumed
    s = latency_factor(ms) ** a
    if speed is not None:
        s *= speed_factor(speed) ** b
    return s


def rank(results, focus="balanced"):
    """[(tag, score)] best first. `results` = {tag: (ping ms or None, speed Mbit/s or None)}; dead servers are left out."""
    assumed = assumed_speed(results)
    rows = [(tag, score(ms, sp, focus, assumed)) for tag, (ms, sp) in results.items()]
    return sorted(((t, s) for t, s in rows if s > 0), key=lambda r: (-r[1], r[0]))


def best(results, focus="balanced", current=None, margin=MARGIN):
    """The tag to be on. A server already in use is kept unless another scores `margin` times better (or it stopped
    answering): switching costs a hiccup in every open connection, a small gain does not pay for it. None when no
    server answers."""
    ranked = rank(results, focus)
    if not ranked:
        return None
    top_tag, top = ranked[0]
    if current is not None:
        cur = dict(ranked).get(current)
        if cur is not None and cur * margin >= top:
            return current
    return top_tag
