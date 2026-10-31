"""Choosing the best server without a window: ping and speed weighed together.
Run: python tests/test_choice.py"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import choice  # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def top(results, focus="balanced"):
    r = choice.rank(results, focus)
    return r[0][0] if r else None


# the case the user described: the lowest ping with 5 Mbit/s against a slightly higher ping with 150 Mbit/s
two = {"low ping": (25, 5), "fast": (60, 150)}
check("5 Mbit/s at the lowest ping loses to 150 Mbit/s at a ping a little higher", top(two) == "fast", choice.rank(two))
check("... also when the response time matters most (the gap in ping is small)", top(two, "latency") == "fast", choice.rank(two, "latency"))
check("... and when the speed matters most", top(two, "speed") == "fast")
check("a slow line is not worth a ping that is only a little lower", top({"a": (40, 3), "b": (45, 40)}) == "b")

# what each focus is for
trade = {"near": (20, 12), "far": (180, 300)}
check("for calls and games the near server wins, even with a thin pipe", top(trade, "latency") == "near", choice.rank(trade, "latency"))
check("for video and downloads the far server with the thick pipe wins", top(trade, "speed") == "far", choice.rank(trade, "speed"))
check("the balanced focus does not send everything over an ocean for speed it does not need",
      top({"near": (30, 60), "far": (250, 200)}) == "near")
check("... and does not stay on a thin pipe for the sake of 10 ms", top({"near": (30, 4), "mid": (60, 80)}) == "mid")

# the factors
check("a better ping never scores worse", all(choice.latency_factor(a) >= choice.latency_factor(b) for a, b in ((10, 50), (50, 200), (200, 900))))
check("more speed never scores worse", all(choice.speed_factor(a) <= choice.speed_factor(b) for a, b in ((1, 5), (5, 50), (50, 500))))
check("the factors are between 0 and 1 and half at their midpoints",
      0 < choice.latency_factor(1) <= 1 and 0 < choice.speed_factor(1000) < 1
      and abs(choice.latency_factor(choice.LATENCY_HALF) - 0.5) < 1e-9 and abs(choice.speed_factor(choice.SPEED_HALF) - 0.5) < 1e-9)
check("speed saturates: 150 vs 300 Mbit/s is a far smaller gain than 5 vs 10",
      choice.speed_factor(300) / choice.speed_factor(150) < choice.speed_factor(10) / choice.speed_factor(5))

# missing and failed measurements
check("a server that does not answer is never chosen", top({"dead": (None, 500), "neg": (-1, 500), "ok": (300, 2)}) == "ok")
check("nobody answers: nothing to choose", choice.rank({"a": (None, None), "b": (-1, -1)}) == [] and choice.best({"a": (None, None)}) is None)
check("without any speed the ping decides alone", top({"a": (80, None), "b": (30, None), "c": (50, None)}) == "b")
check("a speed that failed (-1) counts as not measured", choice.score(40, -1, assumed=50) == choice.score(40, None, assumed=50))
check("an unmeasured server does not beat a measured good one with a similar ping",
      top({"measured": (50, 120), "unknown": (45, None), "slow": (60, 4)}) == "measured", choice.rank({"measured": (50, 120), "unknown": (45, None), "slow": (60, 4)}))
check("what is assumed for the unknown is the lower quarter of what was measured",
      choice.assumed_speed({"a": (10, 4), "b": (10, 40), "c": (10, 80), "d": (10, 160), "e": (10, None)}) == 40
      and choice.assumed_speed({"a": (10, None)}) is None and choice.assumed_speed({"a": (None, 99)}) is None)
check("nonsense is no measurement", not choice.usable(None) and not choice.usable(-3) and not choice.usable("5") and not choice.usable(True) and choice.usable(0))
check("an unknown focus is the balanced one", choice.score(50, 50, "whatever") == choice.score(50, 50, "balanced"))

# staying put
res = {"cur": (60, 100), "best": (50, 120)}
check("a slightly better server is not worth a switch", choice.best(res, current="cur") == "cur", choice.rank(res))
check("... a much better one is", choice.best({"cur": (200, 6), "best": (50, 120)}, current="cur") == "best")
check("a current server that stopped answering is left at once", choice.best({"cur": (None, 100), "best": (300, 3)}, current="cur") == "best")
check("a current server that is not in the list is no reason to stay", choice.best({"best": (50, 100)}, current="gone") == "best")
check("no current server: simply the best", choice.best(res) == "best")
check("the margin is what makes it stay", choice.best(res, current="cur", margin=1.0) == "best" and choice.MARGIN > 1)
check("the ranking is stable for equal scores (by name)", [t for t, _ in choice.rank({"b": (50, 50), "a": (50, 50)})] == ["a", "b"])

# the focus keys are the ones the program offers
check("the three focuses exist", set(choice.FOCUS) == {"balanced", "latency", "speed"})

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
