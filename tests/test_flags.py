"""Tests for flags.py (no GUI). Run: python tests/test_flags.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import flags  # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


# ---------- finding the country ----------
check("flag emoji -> code", flags.code_for("🇫🇮 Финляндия") == "FI" and flags.code_for("🇪🇺 Лучший @ Белые списки") == "EU")
check("flag emoji with variation selectors / spaces", flags.code_for("  🇩🇪️ №1 @ 2 октября 17:11") == "DE")
check("Russian country name", flags.code_for("Россия") == "RU" and flags.code_for("Нидерланды 3") == "NL")
check("English country name", flags.code_for("netherlands #4") == "NL" and flags.code_for("Germany-2") == "DE")
check("name beats nothing, emoji beats name", flags.code_for("🇸🇪 Обход глушилок [WS 5]") == "SE" and flags.code_for("🇫🇮 germany") == "FI")
check("whole words only", flags.code_for("Russian roulette") == "??" and flags.code_for("Ukraine") == "UA")
check("unknown -> placeholder", flags.code_for("⚡️ Лучший") == "??" and flags.code_for("") == "??" and flags.code_for(None) == "??")
check("emoji flag of a country without a drawing falls back to its name or placeholder", flags.code_for("🇿🇼 zzz") == "??")
check("strip_flag removes only the leading flag", flags.strip_flag("🇫🇮 Финляндия ⚡") == "Финляндия ⚡"
      and flags.strip_flag("Россия") == "Россия" and flags.strip_flag("🇫🇮") == "🇫🇮")

# ---------- drawing ----------
W, H = 24, 16


def mid(rows, y):
    return rows[y][W // 2]


ru = flags.render("RU", W, H)
check("size is w x h", len(ru) == H and all(len(r) == W for r in ru))
check("1 px ink outline", all(c == flags.INK for c in ru[0]) and all(r[0] == flags.INK and r[-1] == flags.INK for r in ru))
check("RU is white / blue / red from top to bottom", (mid(ru, 3), mid(ru, 8), mid(ru, 13)) == ("#FFFFFF", "#0039A6", "#D52B1E"),
      (mid(ru, 3), mid(ru, 8), mid(ru, 13)))
fr = flags.render("FR", W, H)
check("FR is blue / white / red from left to right", (fr[8][4], fr[8][12], fr[8][20]) == ("#0055A4", "#FFFFFF", "#EF4135"))
jp = flags.render("JP", W, H)
check("JP: red disc on white", jp[8][12] == "#BC002D" and jp[3][3] == "#FFFFFF")
fi = flags.render("FI", W, H)
check("FI: blue cross on white", fi[8][3] == "#003580" and fi[3][3] == "#FFFFFF" and fi[2][8] == "#003580")
de = flags.render("DE", W, H)
check("DE: black / red / gold", (mid(de, 3), mid(de, 8), mid(de, 13)) == ("#000000", "#DD0000", "#FFCE00"))
check("all different flags differ", len({flags.to_tk_data(flags.render(c, W, H)) for c in flags.FLAGS}) == len(flags.FLAGS))
check("every flag renders without gaps at several sizes",
      all(c.startswith("#") and len(c) == 7 for code in flags.FLAGS for size in ((24, 16), (36, 24), (48, 32))
          for row in flags.render(code, *size, border=max(1, size[0] // 24)) for c in row))
check("unknown code draws the placeholder", flags.render("XX", W, H) == flags.render("??", W, H))
d = flags.to_tk_data([["#000000", "#ffffff"], ["#ff0000", "#00ff00"]])
check("Tk data format", d == "{#000000 #ffffff} {#ff0000 #00ff00}", d)
check("every name in the table has a drawing", all(c in flags.FLAGS for c in flags.NAMES), [c for c in flags.NAMES if c not in flags.FLAGS])

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
