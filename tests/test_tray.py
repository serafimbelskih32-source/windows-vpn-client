"""Tests for tray.py with a stand-in for pystray (no real icon is created). Run: python tests/test_tray.py"""
import os
import sys
import types

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import tray  # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


class FakeIcon:
    instances = []
    boom = False

    def __init__(self, name, image, title, menu):
        if FakeIcon.boom:
            raise RuntimeError("no tray on this desktop")
        self.name, self.icon, self.title, self.menu = name, image, title, menu
        self.started = self.stopped = False
        self.menu_updates = 0
        self.notes = []
        FakeIcon.instances.append(self)

    def run_detached(self):
        self.started = True

    def update_menu(self):
        self.menu_updates += 1

    def notify(self, message, title=None):
        self.notes.append((title, message))

    def stop(self):
        self.stopped = True


class FakeItem:
    def __init__(self, text, action, default=False):
        self.text, self.action, self.default = text, action, default

    def label(self):
        return self.text(self) if callable(self.text) else self.text


class FakeMenu:
    SEPARATOR = object()

    def __init__(self, *items):
        self.items = items


fake = types.SimpleNamespace(Icon=FakeIcon, Menu=FakeMenu, MenuItem=FakeItem)
posted = []
mark = {"show": lambda: None, "toggle": lambda: None, "quit": lambda: None}
t = tray.Tray(os.path.join(ROOT, "icon.png"), posted.append, mark["show"], mark["toggle"], mark["quit"], pystray_module=fake)

check("start() reports success", t.start() is True and t.icon is FakeIcon.instances[-1] and t.icon.started)
items = t.icon.menu.items
check("menu: show (default), connect/disconnect, separator, quit",
      [i.label() if isinstance(i, FakeItem) else "---" for i in items] == ["Показать окно", "Подключить", "---", "Выход"],
      [i.label() if isinstance(i, FakeItem) else "---" for i in items])
check("the first item is the default action (a click on the icon)", items[0].default is True)
items[0].action(t.icon, items[0])
items[1].action(t.icon, items[1])
items[3].action(t.icon, items[3])
check("clicks are handed to the UI thread, never run on the tray thread",
      posted == [mark["show"], mark["toggle"], mark["quit"]])

t.update(True, "VPN: подключено, Германия")
check("update: connected changes the icon, the title and the menu label",
      t.icon.title == "VPN: подключено, Германия" and t.icon.menu_updates == 1 and items[1].label() == "Отключить")
before = (t.icon.icon, t.icon.menu_updates)
t.update(True, "VPN: подключено, Германия")
check("update with the same values touches nothing", (t.icon.icon, t.icon.menu_updates) == before)
t.update(False, "VPN: выключено")
check("update: back to off", items[1].label() == "Подключить" and t.icon.menu_updates == 2)

on, off = t.image(True), t.image(False)
px_on, px_off = on.getpixel((on.width // 6, on.height // 2)), off.getpixel((off.width // 6, off.height // 2))
check("on = the blue slab", px_on[:3] == (30, 60, 255), px_on)
check("off = the same slab in grey (R=G=B)", px_off[0] == px_off[1] == px_off[2] and px_off[:3] != px_on[:3], px_off)
check("images are cached", t.image(True) is on and t.image(False) is off)

t.notify("hello")
check("notify goes to the icon", t.icon.notes == [("VPN", "hello")])
icon = t.icon
t.stop()
check("stop() stops the icon and forgets it", icon.stopped and t.icon is None)
t.update(True, "x")
t.notify("x")
t.stop()
check("calls after stop are harmless", True)

FakeIcon.boom = True
t2 = tray.Tray(os.path.join(ROOT, "icon.png"), posted.append, None, None, None, pystray_module=fake)
check("no tray available: start() returns False instead of raising", t2.start() is False and t2.icon is None)
t2.update(True, "x")
t2.notify("x")
check("... and every later call is a no-op", True)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
