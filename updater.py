"""Self-update from GitHub releases. No GUI imports, so it can be tested on any system.

Flow: ask the GitHub API for the latest release -> pick the asset for this system -> download it next to the
release's SHA256SUMS.txt and verify the hash -> keep it staged in the data folder -> swap it in when the app is
closed or started again (the running program cannot overwrite itself, so a tiny helper does the swap).
"""
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

VERSION = "1.2.0"  # the release workflow rewrites this line from the git tag
REPO = "serafimbelskih32-source/windows-vpn-client"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
ALLOWED_HOSTS = ("api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
SUMS_NAME = "SHA256SUMS.txt"
UA = "FimaVPN-updater"
MAX_SIZE = 300 * 1024 * 1024
MAX_TRIES = 3  # give up on a staged update that failed to install this many times
ALLOW_ANY_HOST = False  # tests only


def parse_version(s):
    """'v1.2.3' -> (1, 2, 3); missing parts count as 0."""
    nums = [int(n) for n in re.findall(r"\d+", str(s))[:3]]
    return tuple(nums) + (0,) * (3 - len(nums))


def asset_name(system=None, machine=None):
    """Release asset that matches this system (the names are fixed by the release workflow)."""
    system = system or sys.platform
    arm = (machine or platform.machine()).lower() in ("arm64", "aarch64")
    if system == "win32":
        return "FimaVPN.exe"
    if system == "darwin":
        return f"FimaVPN-macos-{'arm64' if arm else 'x86_64'}.zip"
    return f"FimaVPN-linux-{'arm64' if arm else 'x86_64'}"


def _check_url(url):
    u = urlsplit(url)
    if not ALLOW_ANY_HOST and (u.scheme != "https" or u.hostname not in ALLOWED_HOSTS):
        raise ValueError(f"адрес не из списка разрешённых: {u.hostname}")


def usable_proxies():
    """The system's proxy settings minus a proxy on this very computer that nobody listens on. A VPN client that was
    closed (or the computer restarted) often leaves its proxy switched on in Windows; every request that obeys it then
    fails, including ours, with "connection refused"."""
    out = {}
    for scheme, url in urllib.request.getproxies().items():
        u = urlsplit(url if "://" in url else "http://" + url)
        if u.hostname in ("127.0.0.1", "localhost", "::1") and u.port:
            try:
                socket.create_connection((u.hostname, u.port), 0.7).close()
            except OSError:
                continue
        out[scheme] = url
    return out


def urlopen(req, timeout=30):
    """urllib's urlopen with usable_proxies() instead of whatever the system says."""
    return urllib.request.build_opener(urllib.request.ProxyHandler(usable_proxies())).open(req, timeout=timeout)


def _open(url, timeout=30):
    _check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json, */*"})
    r = urlopen(req, timeout=timeout)
    try:
        _check_url(r.geturl())  # a redirect must not lead away from GitHub either
    except ValueError:
        r.close()
        raise
    return r


def latest(api=None):
    """{'version': '1.2.0', 'assets': {name: url}} for the newest published release."""
    with _open(api or API) as r:
        j = json.load(r)
    return {"version": str(j["tag_name"]).lstrip("v"),
            "assets": {a["name"]: a["browser_download_url"] for a in j.get("assets", [])}}


def find_update(current=VERSION, info=None, name=None):
    """None if up to date or the release is not complete yet, else {'version','name','url','sums'}."""
    info = info or latest()
    if parse_version(info["version"]) <= parse_version(current):
        return None
    name = name or asset_name()
    if name not in info["assets"] or SUMS_NAME not in info["assets"]:
        return None
    return {"version": info["version"], "name": name, "url": info["assets"][name], "sums": info["assets"][SUMS_NAME]}


def parse_sums(text):
    """'<sha256>  <file>' lines (sha256sum format, '*' marks binary mode) -> {file: sha256}."""
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            out[parts[1].strip().lstrip("*")] = parts[0].lower()
    return out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def update_dir(data_dir, exe=None):
    """Where this copy of the program keeps its downloaded update. One folder per program file: two copies of the
    program (say one in Downloads and one on the desktop) share the settings folder, and with a single shared update
    folder the first to install took the file and the second restarted itself without being updated."""
    exe = os.path.abspath(exe or sys.executable)
    return os.path.join(data_dir, "update", hashlib.sha1(exe.lower().encode("utf-8", "replace")).hexdigest()[:10])


def stage(upd, dest_dir, progress=None):
    """Download the asset, verify it against SHA256SUMS.txt and remember it for the next start.
    Raises ValueError on any mismatch; nothing is left staged in that case."""
    os.makedirs(dest_dir, exist_ok=True)
    with _open(upd["sums"]) as r:
        expected = parse_sums(r.read(1_000_000).decode("utf-8", "replace")).get(upd["name"])
    if not expected:
        raise ValueError("в релизе нет контрольной суммы для этого файла")
    final = os.path.join(dest_dir, upd["name"])
    part = final + ".part"
    h, size = hashlib.sha256(), 0
    try:
        with _open(upd["url"], timeout=60) as r, open(part, "wb") as f:
            for chunk in iter(lambda: r.read(1 << 20), b""):
                size += len(chunk)
                if size > MAX_SIZE:
                    raise ValueError("файл обновления слишком большой")
                h.update(chunk)
                f.write(chunk)
                if progress:
                    progress(size)
        if h.hexdigest() != expected:
            raise ValueError("контрольная сумма скачанного файла не совпала")
        os.replace(part, final)
    finally:
        if os.path.exists(part):
            os.remove(part)
    info = {"version": upd["version"], "name": upd["name"], "path": final, "sha256": expected, "tries": 0}
    _write_json(os.path.join(dest_dir, "staged.json"), info)
    return info


def staged(dest_dir, current=VERSION):
    """The staged update if it is newer than `current`, intact, and has not failed too often; else None."""
    path = os.path.join(dest_dir, "staged.json")
    try:
        with open(path, encoding="utf-8") as f:
            info = json.load(f)
        if parse_version(info["version"]) <= parse_version(current) or info.get("tries", 0) >= MAX_TRIES:
            return None
        if not os.path.isfile(info["path"]) or sha256_file(info["path"]) != info["sha256"]:
            return None
        info["_json"] = path
        return info
    except Exception:
        return None


def discard(dest_dir):
    shutil.rmtree(dest_dir, ignore_errors=True)


LOCK_TTL = 120  # seconds a started install counts as still running


def _lock_path(folder):
    return os.path.join(folder, "applying.lock")


def _claim(folder):
    """True if this call may start the install. A second click or a second start while the first install is still
    on its way must not start a second swap (that is how one update used to open two programs)."""
    lock = _lock_path(folder)
    try:
        if time.time() - os.path.getmtime(lock) < LOCK_TTL:
            return False
        os.remove(lock)  # an earlier install that never finished
    except OSError:
        pass
    try:
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        return True
    except OSError:
        return False


def cleanup(dest_dir, current=VERSION):
    """Remove what an installed (or no longer newer) update leaves behind. Never while an install is under way."""
    try:
        if time.time() - os.path.getmtime(_lock_path(dest_dir)) < LOCK_TTL:
            return
    except OSError:
        pass
    try:
        with open(os.path.join(dest_dir, "staged.json"), encoding="utf-8") as f:
            newer = parse_version(json.load(f)["version"]) > parse_version(current)
    except Exception:  # noqa: BLE001
        newer = False
    if not newer:
        discard(dest_dir)


# ----- swapping the new program in -----
# A PyInstaller one-file program passes its unpacked folder to everything it starts through these variables.
_PYI_VARS = ("_MEIPASS2", "_PYI_APPLICATION_HOME_DIR", "_PYI_ARCHIVE_FILE", "_PYI_PARENT_PROCESS_LEVEL", "_PYI_SPLASH_IPC")


def fresh_env():
    """Environment for starting the new copy of this program from the running one. Without this the new copy
    inherits the old one's unpacked folder, which the old one deletes when it exits, and dies at once with
    "Failed to load Python DLL". With the variables dropped and a fresh start requested it unpacks itself."""
    env = {k: v for k, v in os.environ.items() if k not in _PYI_VARS}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def _ps_quote(p):
    return "'" + p.replace("'", "''") + "'"


def apply_windows(src, dst, pids, relaunch, sha256=None, attempts=60):
    """Detached PowerShell: wait until the old program exits (its exe is locked until then), put the new file next to
    the old one, check it against the expected hash, replace the old one in a single move, restart.
    A damaged copy never replaces a working program; if nothing could be replaced the old program is started again."""
    wait = f"Wait-Process -Id {','.join(str(p) for p in pids)} -ErrorAction SilentlyContinue; " if pids else ""
    tmp = dst + ".new"
    verify = (f"if ((Get-FileHash -LiteralPath {_ps_quote(tmp)} -Algorithm SHA256).Hash -ne {_ps_quote(sha256)}) "
              "{ throw 'hash' }; " if sha256 else "")
    script = (wait +
              f"for ($i = 0; $i -lt {int(attempts)}; $i++) {{ try {{ "
              f"Copy-Item -LiteralPath {_ps_quote(src)} -Destination {_ps_quote(tmp)} -Force -ErrorAction Stop; " + verify +
              f"Move-Item -LiteralPath {_ps_quote(tmp)} -Destination {_ps_quote(dst)} -Force -ErrorAction Stop; "
              f"Remove-Item -LiteralPath {_ps_quote(src)} -Force -ErrorAction SilentlyContinue; break "
              "} catch { Start-Sleep -Milliseconds 500 } }; "
              f"Remove-Item -LiteralPath {_ps_quote(tmp)} -Force -ErrorAction SilentlyContinue; " +
              (f"Start-Process -FilePath {_ps_quote(dst)}" if relaunch else ""))
    # CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW. (DETACHED_PROCESS would make powershell exit silently.)
    flags = 0x00000200 | 0x08000000
    subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                      "-Command", script], creationflags=flags, close_fds=True, env=fresh_env())


def apply_linux(src, dst, relaunch):
    """A running binary can be replaced by renaming over it; the copy goes next to it first (same filesystem)."""
    tmp = dst + ".new"
    shutil.copyfile(src, tmp)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dst)
    os.remove(src)
    if relaunch:
        os.execve(dst, [dst], fresh_env())


def apply_macos(src_zip, bundle, relaunch, pids):
    """Unpack the .app from the zip, then a detached shell swaps the bundle after this process exits."""
    work = os.path.join(os.path.dirname(src_zip), "extract")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    subprocess.run(["ditto", "-x", "-k", src_zip, work], check=True)
    apps = [n for n in os.listdir(work) if n.endswith(".app")]
    if not apps:
        raise ValueError("в архиве нет приложения")
    new = os.path.join(work, apps[0])
    q = lambda p: "'" + p.replace("'", "'\\''") + "'"  # noqa: E731
    wait = "".join(f"while kill -0 {p} 2>/dev/null; do sleep 0.5; done; " for p in pids)
    script = f"{wait}rm -rf {q(bundle)} && mv {q(new)} {q(bundle)} && rm -f {q(src_zip)}" + (f"; open {q(bundle)}" if relaunch else "")
    subprocess.Popen(["/bin/sh", "-c", script], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=fresh_env())


def apply_staged(info, relaunch, exe=None, pids=None):
    """Hand the staged update over to the swap helper. Returns True when the caller should exit now.
    Only a frozen (packaged) program can be replaced; from source this does nothing."""
    if not getattr(sys, "frozen", False) and exe is None:
        return False
    exe = exe or sys.executable
    if pids is None:
        pids = [os.getpid()] + ([os.getppid()] if sys.platform == "win32" else [])  # onefile: bootloader holds the exe
    folder = os.path.dirname(info["path"])
    if not _claim(folder):
        return False  # another install of this update is already on its way
    try:
        info["tries"] = info.get("tries", 0) + 1
        if info.get("_json"):
            _write_json(info["_json"], {k: v for k, v in info.items() if k != "_json"})
        if sys.platform == "win32":
            apply_windows(info["path"], exe, pids, relaunch, info.get("sha256"))
        elif sys.platform == "darwin":
            bundle = os.path.abspath(os.path.join(os.path.dirname(exe), "..", ".."))
            apply_macos(info["path"], bundle, relaunch, pids)
        else:
            apply_linux(info["path"], exe, relaunch)
        return True
    except Exception:
        try:
            os.remove(_lock_path(folder))  # nothing was started: the next try may go ahead
        except OSError:
            pass
        return False
