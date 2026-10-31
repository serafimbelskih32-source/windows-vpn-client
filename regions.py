"""Countries, and what "my country's sites go without the VPN" means for each: the domain endings, the rule sets (lists of
addresses and sites) and the DNS that resolves them. Also where blocking is a reason not to use servers of one's own country.
No GUI, no network."""
import locale
import re

import i18n

# (code, name in Russian, name in English)
COUNTRIES = (
    ("RU", "Россия", "Russia"), ("UA", "Украина", "Ukraine"), ("BY", "Беларусь", "Belarus"), ("KZ", "Казахстан", "Kazakhstan"),
    ("UZ", "Узбекистан", "Uzbekistan"), ("KG", "Киргизия", "Kyrgyzstan"), ("TJ", "Таджикистан", "Tajikistan"),
    ("TM", "Туркменистан", "Turkmenistan"), ("AZ", "Азербайджан", "Azerbaijan"), ("AM", "Армения", "Armenia"),
    ("GE", "Грузия", "Georgia"), ("MD", "Молдова", "Moldova"),
    ("DE", "Германия", "Germany"), ("FR", "Франция", "France"), ("GB", "Великобритания", "United Kingdom"), ("IT", "Италия", "Italy"),
    ("ES", "Испания", "Spain"), ("PT", "Португалия", "Portugal"), ("NL", "Нидерланды", "Netherlands"), ("BE", "Бельгия", "Belgium"),
    ("CH", "Швейцария", "Switzerland"), ("AT", "Австрия", "Austria"), ("SE", "Швеция", "Sweden"), ("NO", "Норвегия", "Norway"),
    ("FI", "Финляндия", "Finland"), ("DK", "Дания", "Denmark"), ("IE", "Ирландия", "Ireland"), ("PL", "Польша", "Poland"),
    ("CZ", "Чехия", "Czechia"), ("SK", "Словакия", "Slovakia"), ("HU", "Венгрия", "Hungary"), ("RO", "Румыния", "Romania"),
    ("BG", "Болгария", "Bulgaria"), ("GR", "Греция", "Greece"), ("RS", "Сербия", "Serbia"), ("HR", "Хорватия", "Croatia"),
    ("LT", "Литва", "Lithuania"), ("LV", "Латвия", "Latvia"), ("EE", "Эстония", "Estonia"), ("TR", "Турция", "Turkey"),
    ("IR", "Иран", "Iran"), ("IL", "Израиль", "Israel"), ("AE", "ОАЭ", "United Arab Emirates"), ("SA", "Саудовская Аравия", "Saudi Arabia"),
    ("QA", "Катар", "Qatar"), ("KW", "Кувейт", "Kuwait"), ("IQ", "Ирак", "Iraq"), ("JO", "Иордания", "Jordan"),
    ("EG", "Египет", "Egypt"), ("MA", "Марокко", "Morocco"), ("DZ", "Алжир", "Algeria"), ("TN", "Тунис", "Tunisia"),
    ("NG", "Нигерия", "Nigeria"), ("ZA", "ЮАР", "South Africa"), ("KE", "Кения", "Kenya"), ("ET", "Эфиопия", "Ethiopia"),
    ("CN", "Китай", "China"), ("HK", "Гонконг", "Hong Kong"), ("TW", "Тайвань", "Taiwan"), ("JP", "Япония", "Japan"),
    ("KR", "Южная Корея", "South Korea"), ("IN", "Индия", "India"), ("PK", "Пакистан", "Pakistan"), ("BD", "Бангладеш", "Bangladesh"),
    ("LK", "Шри-Ланка", "Sri Lanka"), ("TH", "Таиланд", "Thailand"), ("VN", "Вьетнам", "Vietnam"), ("ID", "Индонезия", "Indonesia"),
    ("MY", "Малайзия", "Malaysia"), ("SG", "Сингапур", "Singapore"), ("PH", "Филиппины", "Philippines"), ("MM", "Мьянма", "Myanmar"),
    ("KH", "Камбоджа", "Cambodia"), ("MN", "Монголия", "Mongolia"),
    ("US", "США", "United States"), ("CA", "Канада", "Canada"), ("MX", "Мексика", "Mexico"), ("BR", "Бразилия", "Brazil"),
    ("AR", "Аргентина", "Argentina"), ("CL", "Чили", "Chile"), ("CO", "Колумбия", "Colombia"), ("PE", "Перу", "Peru"),
    ("VE", "Венесуэла", "Venezuela"), ("CU", "Куба", "Cuba"),
    ("AU", "Австралия", "Australia"), ("NZ", "Новая Зеландия", "New Zealand"),
)
NAMES = {c: (ru, en) for c, ru, en in COUNTRIES}
NONE = "NONE"  # "do not let any site bypass the VPN"

# What is known about particular countries; every other one gets its own domain ending and the address list of its country.
_SUFFIXES = {
    "RU": ["ru", "su", "xn--p1ai", "yandex.net", "yastatic.net", "vk.com", "userapi.com", "vkuser.net", "mail.ru", "ok.ru",
           "sberbank.ru", "tinkoff.ru", "gosuslugi.ru"],
    "BY": ["by", "xn--90ais"], "UA": ["ua", "xn--j1amh"], "KZ": ["kz", "xn--80ao21a"], "IR": ["ir", "xn--mgba3a4f16a"],
    "CN": ["cn", "xn--fiqs8s", "baidu.com", "qq.com", "taobao.com", "tmall.com", "alipay.com", "weibo.com", "bilibili.com",
           "zhihu.com", "163.com", "jd.com", "douyin.com", "weixin.qq.com"],
    "GB": ["uk"], "HK": ["hk", "xn--j6w193g"], "TW": ["tw", "xn--kpry57d"],
}
# Lists of sites per country that sing-geosite publishes (checked); the address lists (sing-geoip) exist for every country.
_GEOSITE = {"RU": "category-ru", "CN": "geolocation-cn", "IR": "category-ir"}
_DNS = {"RU": "77.88.8.8", "CN": "223.5.5.5", "IR": "178.22.122.100"}  # a resolver of that country; others: the system's own
# Where blocking makes servers of one's own country useless for getting around it.
_BLOCKING = ("RU", "BY", "CN", "IR", "TM", "MM", "KP", "CU")
_RAW = "https://raw.githubusercontent.com/SagerNet/{repo}/rule-set/{name}.srs"
_CDN = "https://cdn.jsdelivr.net/gh/SagerNet/{repo}@rule-set/{name}.srs"


def valid(code):
    return code == NONE or code in NAMES


def name(code, lang=None):
    """The country's name in `lang` (the current language by default); '' for no country."""
    if code not in NAMES:
        return ""
    ru, en = NAMES[code]
    return ru if (lang or i18n.LANG) == "ru" else en


def listing(lang=None):
    """[(code, name)] sorted by name in `lang`."""
    return sorted(((c, name(c, lang)) for c in NAMES), key=lambda x: x[1].lower())


def search(query, lang=None):
    q = (query or "").strip().lower()
    return [(c, n) for c, n in listing(lang) if not q or q in n.lower() or q == c.lower() or q in (NAMES[c][0].lower(), NAMES[c][1].lower())
            or any(x.lower().startswith(q) for x in NAMES[c])]


def suffixes(code):
    """Domain endings and domains whose sites are this country's."""
    if code not in NAMES:
        return []
    return list(_SUFFIXES.get(code, [code.lower()]))


def rule_sets(code):
    """{tag: (urls)} of the rule sets of this country: its address list and, where there is one, its list of sites."""
    if code not in NAMES:
        return {}
    cc = code.lower()
    out = {}
    if code in _GEOSITE:
        n = "geosite-" + _GEOSITE[code]
        out["geosite-" + cc] = (_RAW.format(repo="sing-geosite", name=n), _CDN.format(repo="sing-geosite", name=n))
    n = "geoip-" + cc
    out["geoip-" + cc] = (_RAW.format(repo="sing-geoip", name=n), _CDN.format(repo="sing-geoip", name=n))
    return out


def local_dns(code):
    """The DNS server (address) that resolves this country's sites, '' = the system's own resolver."""
    return _DNS.get(code, "")


def blocks(code):
    """Is this a country where blocking is the reason for a VPN (so its own servers cannot help)?"""
    return code in _BLOCKING


def system_country():
    """The country of the user's system settings ('RU' for ru-RU), '' when unknown or not in the list."""
    m = re.search(r"-([A-Za-z]{2})\b", i18n.system_locale())
    cc = m.group(1).upper() if m else ""
    return cc if cc in NAMES else ""
