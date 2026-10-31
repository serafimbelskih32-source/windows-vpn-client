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

# ---------- several copies of the program, one install at a time, damaged files ----------
dd = tempfile.mkdtemp(prefix="fimadata_")
a1, a2 = updater.update_dir(dd, os.path.join(dd, "Downloads", "FimaVPN.exe")), updater.update_dir(dd, os.path.join(dd, "release", "FimaVPN.exe"))
check("two copies of the program stage their updates in different folders", a1 != a2 and os.path.dirname(a1) == os.path.dirname(a2))
check("one copy always gets the same folder", a1 == updater.update_dir(dd, os.path.join(dd, "Downloads", "FimaVPN.exe")))
check("... whatever the case of its path on Windows' case-insensitive disks",
      sys.platform != "win32" or a1 == updater.update_dir(dd, os.path.join(dd, "DOWNLOADS", "fimavpn.exe")))

claim_dir = tempfile.mkdtemp(prefix="fimaclaim_")
check("the first install may start", updater._claim(claim_dir) is True)
check("a second one while it is on its way may not", updater._claim(claim_dir) is False)
old = time.time() - updater.LOCK_TTL - 5
os.utime(updater._lock_path(claim_dir), (old, old))
check("an install that never finished does not block forever", updater._claim(claim_dir) is True)

cl = tempfile.mkdtemp(prefix="fimaclean_")
json.dump({"version": "1.2.2"}, open(os.path.join(cl, "staged.json"), "w"))
updater.cleanup(cl, "1.2.2")
check("cleanup removes an update that is installed already", not os.path.exists(cl))
cl = tempfile.mkdtemp(prefix="fimaclean_")
json.dump({"version": "1.2.3"}, open(os.path.join(cl, "staged.json"), "w"))
updater.cleanup(cl, "1.2.2")
check("... and keeps one that is newer than the running program", os.path.exists(cl))
cl2 = tempfile.mkdtemp(prefix="fimaclean_")
json.dump({"version": "1.0.0"}, open(os.path.join(cl2, "staged.json"), "w"))
updater._claim(cl2)
updater.cleanup(cl2, "1.2.2")
check("... and leaves an install under way alone", os.path.exists(cl2))

if sys.platform == "win32":
    work = tempfile.mkdtemp(prefix="fimaswap_")
    dst, src = os.path.join(work, "FimaVPN.exe"), os.path.join(work, "new.exe")
    open(dst, "wb").write(b"OLD")
    open(src, "wb").write(b"NEW")
    updater.apply_windows(src, dst, [], relaunch=False, sha256=hashlib.sha256(b"WRONG").hexdigest(), attempts=3)
    time.sleep(5)
    check("windows: a file that does not match its hash never replaces the program", open(dst, "rb").read() == b"OLD")
    check("windows: ... and no half-copied file is left next to it", not os.path.exists(dst + ".new"))
    updater.apply_windows(src, dst, [], relaunch=False, sha256=hashlib.sha256(b"NEW").hexdigest().upper(), attempts=10)
    end = time.time() + 20
    while time.time() < end and open(dst, "rb").read() != b"NEW":
        time.sleep(0.3)
    check("windows: a file with the right hash replaces it", open(dst, "rb").read() == b"NEW")
    check("windows: ... and the work file is gone", not os.path.exists(dst + ".new") and not os.path.exists(src))

    # two installs for the same update: only the first starts a swap
    folder = tempfile.mkdtemp(prefix="fimatwice_")
    dst2, src2 = os.path.join(folder, "FimaVPN.exe"), os.path.join(folder, "new.exe")
    open(dst2, "wb").write(b"OLD")
    open(src2, "wb").write(b"NEW")
    inf = {"version": "9.9.9", "name": "FimaVPN.exe", "path": src2, "sha256": hashlib.sha256(b"NEW").hexdigest()}
    first = updater.apply_staged(dict(inf), relaunch=False, exe=dst2, pids=[])
    second = updater.apply_staged(dict(inf), relaunch=False, exe=dst2, pids=[])
    check("a second install of the same update is refused", first is True and second is False, (first, second))
    end = time.time() + 20
    while time.time() < end and open(dst2, "rb").read() != b"NEW":
        time.sleep(0.3)
    check("... and the first one still completes", open(dst2, "rb").read() == b"NEW")

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
