"""Languages and countries without a window: every Russian text of the program has an English one (and nothing is left
untranslated in the code), the templates format, the language and the country are picked right, the country data is sound.
Run: python tests/test_i18n.py"""
import ast
import json
import os
import re
import string
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
import i18n  # noqa: E402
import i18n_en  # noqa: E402
import regions  # noqa: E402

fails = []
CYR = re.compile(r"[А-Яа-яЁё]")


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


# ---------- the code: no Russian text outside T(...) ----------
FILES = ("vpn.py", "sources.py", "updater.py", "tray.py")
keys, loose = {}, []
for f in FILES:
    tree = ast.parse(open(os.path.join(ROOT, f), encoding="utf-8").read())
    docs, parents = set(), {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node):
            parents[id(ch)] = node
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body \
                and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
            docs.add(id(node.body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "T" and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            keys[node.args[0].value] = f
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and CYR.search(node.value) and id(node) not in docs:
            p = parents.get(id(node))
            if not (isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id == "T" and p.args and p.args[0] is node):
                loose.append((f, node.lineno, node.value[:50]))
check("every Russian text in the program goes through T(...)", not loose, loose[:5])
check("T() is only ever given a plain text (a variable could not be found in the catalog)", len(keys) > 250, len(keys))

# ---------- the English catalog ----------
EN = i18n_en.EN
missing = [k for k in keys if k not in EN]
stale = [k for k in EN if k not in keys]
check("every text of the program has an English one", not missing, missing[:3])
check("... and the catalog has no texts the program no longer uses", not stale, stale[:3])
ph = lambda s: sorted(f for _, f, _, _ in string.Formatter().parse(s) if f is not None) + sorted(re.findall(r"%[a-zA-Z]", s))  # noqa: E731
check("the English text has the same placeholders as the Russian one", all(ph(k) == ph(v) for k, v in EN.items()),
      [(k[:40], v[:40]) for k, v in EN.items() if ph(k) != ph(v)][:3])
check("no Russian is left in an English text", not [v for v in EN.values() if CYR.search(v)], [v for v in EN.values() if CYR.search(v)][:3])
same = [k for k, v in EN.items() if k == v and len(re.sub(r"[^A-Za-zА-Яа-я]", "", k)) > 3]
check("an English text differs from the Russian one", not same, same[:3])
bad_fmt = []
for k, v in EN.items():
    for text in (k, v):
        fields = [f for _, f, _, _ in string.Formatter().parse(text) if f is not None]
        args = [1.5] * 6
        kwargs = {f: "x" for f in fields if f and not f[0].isdigit()}
        try:
            text.format(*args, **kwargs) if fields else None
        except Exception as e:  # noqa: BLE001
            bad_fmt.append((text[:40], repr(e)))
check("every template formats with its placeholders", not bad_fmt, bad_fmt[:3])
check("the strftime patterns keep their codes", EN["обновлено %d.%m"].count("%") == 2 and EN["обновлено в %H:%M"].count("%") == 2)

# ---------- the language ----------
old_lang = i18n.LANG
try:
    i18n.set_language("en")
    check("T gives the English text", i18n.T("Подключить") == "Connect" and i18n.T("нет такого текста в каталоге") == "нет такого текста в каталоге")
    i18n.set_language("ru")
    check("... and Russian is the source text itself", i18n.T("Подключить") == "Подключить")
    i18n.set_language("xx")
    check("an unknown language falls back to English", i18n.LANG == "en")
finally:
    i18n.set_language(old_lang)

tmp = tempfile.mkdtemp(prefix="fimai18n_")
env_before = os.environ.pop("FIMA_LANG", None)
real_sys = i18n.system_language
try:
    i18n.system_language = lambda: "en"
    check("a new installation takes the system's language", i18n.initial_language(os.path.join(tmp, "none.json")) == "en")
    i18n.system_language = lambda: "ru"
    check("... Russian system: Russian", i18n.initial_language(os.path.join(tmp, "none.json")) == "ru")
    i18n.system_language = lambda: "en"
    legacy = os.path.join(tmp, "legacy.json")
    json.dump({"sources": "https://x"}, open(legacy, "w"))
    check("an installation from the Russian-only days stays Russian, whatever the system says", i18n.initial_language(legacy) == "ru")
    chosen = os.path.join(tmp, "chosen.json")
    json.dump({"sources": "", "lang": "en"}, open(chosen, "w"))
    check("a chosen language wins", i18n.initial_language(chosen) == "en")
    json.dump({"lang": "klingon"}, open(chosen, "w"))
    check("an unknown chosen language is ignored (an existing installation: Russian)", i18n.initial_language(chosen) == "ru")
    broken = os.path.join(tmp, "broken.json")
    open(broken, "w").write("{not json")
    check("a damaged settings file does not break the start", i18n.initial_language(broken) == "en")
    os.environ["FIMA_LANG"] = "ru"
    check("FIMA_LANG overrides everything (tests, support)", i18n.initial_language(chosen) == "ru" and i18n.initial_language(os.path.join(tmp, "none.json")) == "ru")
finally:
    i18n.system_language = real_sys
    os.environ.pop("FIMA_LANG", None)
    if env_before is not None:
        os.environ["FIMA_LANG"] = env_before
real_loc = i18n.system_locale
try:
    for loc, want in (("ru-RU", "ru"), ("be-BY", "ru"), ("uk-UA", "ru"), ("kk-KZ", "ru"), ("en-US", "en"), ("de-DE", "en"), ("zh-CN", "en"), ("", "en")):
        i18n.system_locale = lambda loc=loc: loc
        check(f"system locale {loc or '(unknown)'} -> {want}", i18n.system_language() == want, i18n.system_language())
    i18n.system_locale = lambda: "de-DE"
    check("the country of the system settings", regions.system_country() == "DE")
    i18n.system_locale = lambda: "en-001"
    check("... nothing when the locale names no country", regions.system_country() == "")
    i18n.system_locale = lambda: "ru-XX"
    check("... or one that is not on the list", regions.system_country() == "")
finally:
    i18n.system_locale = real_loc

# ---------- countries ----------
codes = [c for c, _, _ in regions.COUNTRIES]
check("country codes are two capital letters and unique", all(re.fullmatch(r"[A-Z]{2}", c) for c in codes) and len(codes) == len(set(codes)))
check("every country has a name in both languages", all(ru.strip() and en.strip() and CYR.search(ru) and not CYR.search(en) for _, ru, en in regions.COUNTRIES))
check("enough countries to be a list for the world", len(codes) >= 80 and {"RU", "UA", "BY", "KZ", "CN", "IR", "TR", "DE", "FR", "GB", "US", "BR", "IN", "JP", "AU"} <= set(codes))
check("names follow the language", regions.name("DE", "en") == "Germany" and regions.name("DE", "ru") == "Германия" and regions.name("XX") == "")
check("the list is sorted by name in the language asked", [n for _, n in regions.listing("en")] == sorted((n for _, n in regions.listing("en")), key=str.lower)
      and [n for _, n in regions.listing("ru")] == sorted((n for _, n in regions.listing("ru")), key=str.lower))
check("search finds a country by a part of its name in either language, and by its code",
      ("DE", "Germany") in regions.search("germ", "en") and ("DE", "Германия") in regions.search("герм", "ru") and ("DE", "Germany") in regions.search("de", "en")
      and len(regions.search("", "en")) == len(codes) and regions.search("zzzz", "en") == [])
check("a country's sites: its own domain ending, or the ones that need more than that",
      regions.suffixes("DE") == ["de"] and regions.suffixes("GB") == ["uk"] and "ru" in regions.suffixes("RU") and "yandex.net" in regions.suffixes("RU")
      and "cn" in regions.suffixes("CN") and regions.suffixes("XX") == [] and regions.suffixes(regions.NONE) == [])
rs = regions.rule_sets("DE")
check("every country has an address list; where a list of sites exists, too",
      list(rs) == ["geoip-de"] and all(u.startswith("https://") and u.endswith(".srs") for urls in rs.values() for u in urls)
      and list(regions.rule_sets("RU")) == ["geosite-ru", "geoip-ru"] and list(regions.rule_sets("CN")) == ["geosite-cn", "geoip-cn"]
      and list(regions.rule_sets("IR")) == ["geosite-ir", "geoip-ir"] and regions.rule_sets(regions.NONE) == {})
check("the Russian lists are where the program always took them from",
      regions.rule_sets("RU")["geoip-ru"][0] == "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
      and regions.rule_sets("RU")["geosite-ru"][1] == "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs")
check("DNS: where there is a country's own resolver it is used, elsewhere the system's", regions.local_dns("RU") == "77.88.8.8" and regions.local_dns("DE") == "")
check("where blocking is the reason for a VPN, servers of the same country are no use",
      all(regions.blocks(c) for c in ("RU", "CN", "IR", "BY")) and not any(regions.blocks(c) for c in ("DE", "US", "FR", "BR")))
check("a country is valid, 'no country' is valid, nonsense is not", regions.valid("DE") and regions.valid(regions.NONE) and not regions.valid("XX") and not regions.valid(None))

# ---------- the packaged program ----------
# catalog() finds a language's module by name, which PyInstaller cannot see: each catalog must also be imported plainly
src = open(os.path.join(ROOT, "i18n.py"), encoding="utf-8").read()
check("every catalog module is imported plainly in i18n.py, so that the packaged program bundles it",
      all(re.search(rf"^import i18n_{c}\b", src, re.M) for c in i18n.LANGS if c != "ru"),
      [c for c in i18n.LANGS if c != "ru" and not re.search(rf"^import i18n_{c}\b", src, re.M)])
check("every language of the list has a catalog with the texts of the program", all(len(i18n.catalog(c)) >= 250 for c in i18n.LANGS if c != "ru"))

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
