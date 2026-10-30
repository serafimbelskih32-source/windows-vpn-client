"""Linux/macOS: the root supervisor must stop the core when the stop file appears, when the window is gone, and
report a crashing core. Uses a fake core, no root needed. Run: python tests/test_supervisor.py"""
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vpn  # noqa: E402

if sys.platform == "win32":
    print("skipped on Windows (the core runs directly there)")
    sys.exit(0)

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))
    if not cond:
        fails.append(name)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


tmp = tempfile.mkdtemp(prefix="fimasup_")
pidfile, stop, cfg = os.path.join(tmp, "core.pid"), os.path.join(tmp, "stop"), os.path.join(tmp, "run.json")
core = os.path.join(tmp, "fakecore")
open(core, "w").write(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 300\n")
os.chmod(core, 0o755)


def run_supervisor(gui_pid):
    return subprocess.Popen(["/bin/sh", "-c", vpn.supervisor_script(core, cfg, stop, gui_pid)])


def wait_exit(p, secs):
    end = time.time() + secs
    while time.time() < end:
        if p.poll() is not None:
            return True
        time.sleep(0.1)
    return False


# 1. stop file
sup = run_supervisor(os.getpid())
time.sleep(1.5)
core_pid = int(open(pidfile).read())
check("core is running under the supervisor", alive(core_pid) and sup.poll() is None)
open(stop, "w").close()
check("stop file stops the supervisor within 3 s", wait_exit(sup, 3))
time.sleep(0.3)
check("... and the core is gone", not alive(core_pid))
os.remove(stop)

# 2. window process gone
dead = subprocess.Popen([sys.executable, "-c", "pass"])
dead.wait()
sup = run_supervisor(dead.pid)
check("a vanished window stops the supervisor (and the core)", wait_exit(sup, 4))
time.sleep(0.3)
check("... core is gone too", not alive(int(open(pidfile).read())))

# 3. core crashes by itself
open(core, "w").write("#!/bin/sh\nexit 3\n")
sup = run_supervisor(os.getpid())
check("a crashing core ends the supervisor with the core's status", wait_exit(sup, 4) and sup.returncode == 3, sup.returncode)

# 4. quoting survives spaces and quotes in paths
weird = os.path.join(tmp, "dir with 'quote' and space")
os.makedirs(weird)
wcore = os.path.join(weird, "core")
open(wcore, "w").write("#!/bin/sh\nexit 0\n")
os.chmod(wcore, 0o755)
p = subprocess.Popen(["/bin/sh", "-c", vpn.supervisor_script(wcore, cfg, stop, os.getpid())])
check("paths with spaces and quotes work", wait_exit(p, 4) and p.returncode == 0, p.returncode)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
