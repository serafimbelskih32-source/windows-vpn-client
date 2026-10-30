"""Open the real window for a moment: catches fonts/icon/layout errors on every OS. Run: python tests/gui_smoke.py"""
import os
import sys
import traceback

os.environ["FIMA_NO_TRAY"] = "1"  # the real tray is checked separately; a CI desktop has none

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    import vpn

    vpn.detect_home = lambda *a, **k: None  # no throw-away core asking which country the CI machine is in
    vpn.kill_stale_cores = lambda *a, **k: 0  # starting the window closes our leftover cores: never a developer's live VPN

    app = vpn.App()
    app.update()
    assert app.power.winfo_width() > 100, "main button has no size"
    assert app.tree.winfo_height() > 50, "server list has no size"
    if vpn.IS_WIN:  # the window carries its own title-bar and taskbar icons, not ones Windows stretches
        import ctypes
        user = ctypes.windll.user32
        user.GetParent.restype = ctypes.c_void_p
        user.GetParent.argtypes = [ctypes.c_void_p]
        user.SendMessageW.restype = ctypes.c_void_p
        user.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p]
        hwnd = user.GetParent(app.winfo_id()) or app.winfo_id()
        assert user.SendMessageW(hwnd, 0x7F, 0, 0) and user.SendMessageW(hwnd, 0x7F, 1, 0), "window has no icons"  # WM_GETICON
    print(f"window ok: {app.winfo_width()}x{app.winfo_height()} font={app.fam!r} "
          f"nic={vpn.posix_nic() if not vpn.IS_WIN else vpn.physical_nic()!r} platform={sys.platform}")
    app.destroy()
except Exception:  # noqa: BLE001
    traceback.print_exc()
    sys.exit(1)
