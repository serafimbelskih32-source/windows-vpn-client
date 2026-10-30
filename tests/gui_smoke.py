"""Open the real window for a moment: catches fonts/icon/layout errors on every OS. Run: python tests/gui_smoke.py"""
import os
import sys
import traceback

os.environ["FIMA_NO_TRAY"] = "1"  # the real tray is checked separately; a CI desktop has none

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    import vpn

    app = vpn.App()
    app.update()
    assert app.power.winfo_width() > 100, "main button has no size"
    assert app.tree.winfo_height() > 50, "server list has no size"
    print(f"window ok: {app.winfo_width()}x{app.winfo_height()} font={app.fam!r} "
          f"nic={vpn.posix_nic() if not vpn.IS_WIN else vpn.physical_nic()!r} platform={sys.platform}")
    app.destroy()
except Exception:  # noqa: BLE001
    traceback.print_exc()
    sys.exit(1)
