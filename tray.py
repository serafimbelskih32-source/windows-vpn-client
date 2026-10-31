"""Tray icon: the Windows notification area (the icons under the "^" arrow), the macOS menu bar, the Linux system tray.
Built on pystray; everything is optional: if it cannot start, the app simply works without a tray icon.

The menu callbacks run on pystray's own thread, so they never touch the window directly: they hand a function to
`post`, which the app runs on the Tk thread. No Tk imports here.
"""
import sys

from i18n import T


def _sharp_icon_class():
    """Windows only. pystray loads its icon at Windows' 'default' size (32 px) and lets the shell shrink it to the
    notification area's 16 px, which smears it. This subclass loads it at the small-icon size of this display scaling
    (16 / 20 / 24 / 32 px) from the .ico pystray writes, which holds every size."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        from pystray import _win32 as backend
        from pystray._util import serialized_image, win32
    except Exception:  # noqa: BLE001
        return None

    class SharpIcon(backend.Icon):
        def _assert_icon_handle(self):
            if self._icon_handle:
                return
            try:
                dpi = ctypes.windll.user32.GetDpiForSystem()
            except Exception:  # noqa: BLE001
                dpi = 96
            size = round(16 * dpi / 96)
            with serialized_image(self.icon, "ICO") as icon_path:
                self._icon_handle = win32.LoadImage(None, icon_path, win32.IMAGE_ICON, size, size, win32.LR_LOADFROMFILE)

    return SharpIcon


class Tray:
    def __init__(self, icon_path, post, on_show, on_toggle, on_quit, pystray_module=None):
        self.icon_path, self.post = icon_path, post
        self.on_show, self.on_toggle, self.on_quit = on_show, on_toggle, on_quit
        self._pystray = pystray_module  # tests pass a stand-in
        self.icon = None
        self.connected = False
        self.title = T("VPN: выключено")
        self._images = {}

    def image(self, connected):
        """Blue slab while connected, the same slab in grey while off: the state is readable from across the screen."""
        key = bool(connected)
        if key not in self._images:
            from PIL import Image
            img = Image.open(self.icon_path).convert("RGBA")
            if not key:
                img = img.convert("LA").convert("RGBA")  # grey, transparency kept
            self._images[key] = img
        return self._images[key]

    def start(self):
        """True if the icon is up. Any failure (no tray on this desktop, a missing backend) just returns False."""
        try:
            pystray = self._pystray or __import__("pystray")
            menu = pystray.Menu(
                pystray.MenuItem(T("Показать окно"), lambda icon, item: self.post(self.on_show), default=True),
                pystray.MenuItem(lambda item: T("Отключить") if self.connected else T("Подключить"),
                                 lambda icon, item: self.post(self.on_toggle)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(T("Выход"), lambda icon, item: self.post(self.on_quit)))
            icon_class = (_sharp_icon_class() if self._pystray is None else None) or pystray.Icon
            self.icon = icon_class("FimaVPN", self.image(False), self.title, menu)
            self.icon.run_detached()
            return True
        except Exception:  # noqa: BLE001
            self.icon = None
            return False

    def update(self, connected, title):
        """Cheap to call often: touches the icon only when something changed."""
        if self.icon is None:
            return
        try:
            if bool(connected) != self.connected:
                self.connected = bool(connected)
                self.icon.icon = self.image(connected)
                self.icon.update_menu()  # the Connect / Disconnect label
            if title != self.title:
                self.title = title
                self.icon.title = title
        except Exception:  # noqa: BLE001
            pass

    def notify(self, message, title="VPN"):
        try:
            self.icon.notify(message, title)
        except Exception:  # noqa: BLE001
            pass

    def stop(self):
        icon, self.icon = self.icon, None
        try:
            if icon is not None:
                icon.stop()
        except Exception:  # noqa: BLE001
            pass


def selftest():
    """For `--tray-selftest` in a packaged build: is the tray backend bundled and importable?"""
    try:
        import pystray
        from PIL import Image
        icon = pystray.Icon("selftest", Image.new("RGBA", (16, 16), (30, 60, 255, 255)), "selftest")
        return f"ok: backend {type(icon).__module__}"
    except Exception as e:  # noqa: BLE001
        return f"unavailable: {type(e).__name__}: {e}"
