"""Tests for updater.py: pure logic plus a fake GitHub on localhost. Runs on every system, needs no GUI.
Run: python tests/test_updater.py"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import updater  # noqa: E402

updater.ALLOW_ANY_HOST = True
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


# ---------- versions, asset names, checksums ----------
check("parse_version", updater.parse_version("v1.2.3") == (1, 2, 3) and updater.parse_version("1.10") == (1, 10, 0))
check("1.10.0 is newer than 1.9.0", updater.parse_version("1.10.0") > updater.parse_version("1.9.0"))
check("asset: windows", updater.asset_name("win32", "AMD64") == "FimaVPN.exe")
check("asset: linux x86_64 / arm64", updater.asset_name("linux", "x86_64") == "FimaVPN-linux-x86_64"
      and updater.asset_name("linux", "aarch64") == "FimaVPN-linux-arm64")
check("asset: macOS Intel / Apple Silicon", updater.asset_name("darwin", "x86_64") == "FimaVPN-macos-x86_64.zip"
      and updater.asset_name("darwin", "arm64") == "FimaVPN-macos-arm64.zip")
good = "a" * 64
sums = f"{good}  FimaVPN.exe\n{'b' * 64} *FimaVPN-linux-x86_64\nnot a hash  junk\n"
check("parse_sums", updater.parse_sums(sums) == {"FimaVPN.exe": good, "FimaVPN-linux-x86_64": "b" * 64})

info = {"version": "1.2.0", "assets": {"FimaVPN.exe": "u1", updater.SUMS_NAME: "u2"}}
check("find_update: newer release", updater.find_update("1.1.0", info, "FimaVPN.exe") ==
      {"version": "1.2.0", "name": "FimaVPN.exe", "url": "u1", "sums": "u2"})
check("find_update: same version", updater.find_update("1.2.0", info, "FimaVPN.exe") is None)
check("find_update: older release", updater.find_update("1.3.0", info, "FimaVPN.exe") is None)
check("find_update: no asset for this system", updater.find_update("1.1.0", info, "FimaVPN-linux-x86_64") is None)
check("find_update: no checksums file = incomplete release",
      updater.find_update("1.1.0", {"version": "1.2.0", "assets": {"FimaVPN.exe": "u1"}}, "FimaVPN.exe") is None)

# ---------- a fake GitHub ----------
PAYLOAD = os.urandom(300_000)
STATE = {"bad_sum": False, "redirect": False}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path == "/api":
            body = json.dumps({"tag_name": "v1.2.0", "assets": [
                {"name": "FimaVPN.exe", "browser_download_url": base + "/dl/FimaVPN.exe"},
                {"name": updater.SUMS_NAME, "browser_download_url": base + "/dl/sums"}]}).encode()
        elif self.path == "/dl/FimaVPN.exe":
            body = PAYLOAD
        elif self.path == "/dl/sums":
            h = hashlib.sha256(PAYLOAD).hexdigest() if not STATE["bad_sum"] else "0" * 64
            body = f"{h}  FimaVPN.exe\n".encode()
        else:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_address[1]}"
lat = updater.latest(base + "/api")
check("latest() reads tag and assets", lat["version"] == "1.2.0" and set(lat["assets"]) == {"FimaVPN.exe", updater.SUMS_NAME})
upd = updater.find_update("1.1.0", lat, "FimaVPN.exe")
tmp = tempfile.mkdtemp(prefix="fimaupd_")
seen = []
st = updater.stage(upd, tmp, progress=seen.append)
check("stage downloads and verifies", os.path.getsize(st["path"]) == len(PAYLOAD) and st["version"] == "1.2.0" and seen)
check("staged() finds it", updater.staged(tmp, "1.1.0") is not None and updater.staged(tmp, "1.2.0") is None)
open(st["path"], "ab").write(b"x")
check("staged() rejects a file changed on disk", updater.staged(tmp, "1.1.0") is None)

STATE["bad_sum"] = True
tmp2 = tempfile.mkdtemp(prefix="fimaupd_")
try:
    updater.stage(upd, tmp2)
    bad = False
except ValueError:
    bad = True
check("stage refuses a wrong checksum and leaves nothing behind",
      bad and not os.path.exists(os.path.join(tmp2, "staged.json")) and not any(f.endswith(".part") for f in os.listdir(tmp2)),
      os.listdir(tmp2))
STATE["bad_sum"] = False

updater.ALLOW_ANY_HOST = False
try:
    updater._open("http://evil.example/x")
    refused = False
except ValueError:
    refused = True
check("plain http / foreign hosts are refused", refused)
updater.ALLOW_ANY_HOST = True

# ---------- tries limit ----------
tmp3 = tempfile.mkdtemp(prefix="fimaupd_")
st3 = updater.stage(upd, tmp3)
j = os.path.join(tmp3, "staged.json")
d = json.load(open(j))
d["tries"] = updater.MAX_TRIES
json.dump(d, open(j, "w"))
check("a staged update that failed to install too often is dropped", updater.staged(tmp3, "1.1.0") is None)

# ---------- the swap itself ----------
if sys.platform == "win32":
    work = tempfile.mkdtemp(prefix="fimaswap_")
    dst, src = os.path.join(work, "FimaVPN.exe"), os.path.join(work, "new.exe")
    open(dst, "wb").write(b"OLD")
    open(src, "wb").write(b"NEW")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
    updater.apply_windows(src, dst, [holder.pid], relaunch=False)
    time.sleep(0.5)
    check("windows: old file stays until the program has exited", open(dst, "rb").read() == b"OLD")
    end = time.time() + 20
    while time.time() < end and open(dst, "rb").read() != b"NEW":
        time.sleep(0.3)
    check("windows: new file swapped in after the program exited", open(dst, "rb").read() == b"NEW")
    check("windows: staged copy removed", not os.path.exists(src))
else:
    work = tempfile.mkdtemp(prefix="fimaswap_")
    dst, src = os.path.join(work, "FimaVPN"), os.path.join(work, "new")
    open(dst, "wb").write(b"OLD")
    open(src, "wb").write(b"NEW")
    updater.apply_linux(src, dst, relaunch=False)
    check("posix: binary replaced and executable", open(dst, "rb").read() == b"NEW" and os.access(dst, os.X_OK))
    check("posix: staged copy removed", not os.path.exists(src))

# apply_staged does nothing when not packaged
check("apply_staged is a no-op from source", updater.apply_staged({"path": "x"}, False) is False)

# The new copy is started from the old one: it must not inherit the old copy's unpacked folder (a PyInstaller one-file
# program deletes it on exit, and the new copy died with "Failed to load Python DLL").
os.environ["_MEIPASS2"] = os.environ["_PYI_APPLICATION_HOME_DIR"] = os.path.join(tempfile.gettempdir(), "_MEI_gone")
env = updater.fresh_env()
check("fresh_env drops the old copy's unpacked-folder variables", not any(k in env for k in updater._PYI_VARS), sorted(env))
check("... asks the bootloader for a fresh start", env.get("PYINSTALLER_RESET_ENVIRONMENT") == "1")
check("... and keeps the rest of the environment", env.get("PATH") == os.environ.get("PATH"))
seen = {}
real_popen = subprocess.Popen
subprocess.Popen = lambda *a, **k: seen.update(k)
try:
    updater.apply_windows("new.exe", "app.exe", [1], True)
finally:
    subprocess.Popen = real_popen
check("the Windows swap helper starts with that environment", seen.get("env") == env, seen.get("env", {}).keys())
for k in updater._PYI_VARS:
    os.environ.pop(k, None)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
