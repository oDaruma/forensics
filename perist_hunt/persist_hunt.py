#!/usr/bin/env python3
"""
persist_hunt.py - list the contents of common malware persistence locations
on Windows 10/11 and flag the entries worth a closer look.

Read-only: it never changes the registry, tasks, services or files.
Pure standard library (Python 3.8+). PowerShell (built in to Windows) is used
for Authenticode checks, WMI subscriptions and .lnk targets.

USAGE  (run from an elevated prompt for full coverage)
  python persist_hunt.py                         # everything, console table
  python persist_hunt.py --min-severity medium   # only flagged entries
  python persist_hunt.py --hide-microsoft        # drop entries signed by Microsoft
  python persist_hunt.py --html report.html --csv report.csv --json baseline.json
  python persist_hunt.py --baseline baseline.json --only-new   # what changed since last run
  python persist_hunt.py --only runkeys,tasks,services
  python persist_hunt.py --list-collectors

LOCATIONS COVERED  (MITRE ATT&CK technique in brackets)
  runkeys      Run / RunOnce / RunOnceEx / Policies\\Explorer\\Run / Windows\\Load,Run,
               Terminal Server Run, StartupApproved state     [T1547.001]
  startup      Startup folders for every profile + All Users  [T1547.001]
  winlogon     Shell, Userinit, Notify, Taskman, AppSetup,
               UserInitMprLogonScript                          [T1547.004, T1037.001]
  ifeo         Image File Execution Options Debugger,
               SilentProcessExit, accessibility binary swaps  [T1546.012, T1546.008]
  appinit      AppInit_DLLs, AppCertDlls                       [T1546.010, T1546.009]
  bootexec     Session Manager BootExecute/SetupExecute/Execute [T1547.012-ish]
  lsa          Authentication/Security/Notification packages  [T1547.002, .005, T1556.002]
  print        Print monitors and print processors            [T1547.010, .012]
  services     Services and drivers (auto/boot/system start, ServiceDll,
               FailureCommand)                                 [T1543.003]
  tasks        Scheduled tasks (XML + hidden tasks with no SD) [T1053.005]
  wmi          WMI event filters / consumers / bindings       [T1546.003]
  com          Per-user COM overrides (HKCU CLSID)            [T1546.015]
  explorer     BHOs, ShellServiceObjectDelayLoad, SharedTaskScheduler,
               ShellExecuteHooks                               [T1176, T1546]
  activesetup  Active Setup StubPath                           [T1547.014]
  netsh        Netsh helper DLLs                               [T1546.007]
  cmdautorun   Command Processor AutoRun                       [T1546]
  office       "Office test" DLL, Office add-ins, Word/Excel startup files [T1137]
  screensaver  SCRNSAVE.EXE                                    [T1546.002]
  psprofile    PowerShell profiles                             [T1546.013]
  timeprov     W32Time time providers                          [T1547.003]
  shims        Installed/custom application shims              [T1546.011]
  debuggers    AeDebug / WER ReflectDebugger                   [T1546]
  bits         BITS jobs (notify command lines)                [T1197]
  gposcripts   Local Group Policy logon/startup scripts        [T1037]

LIMITATIONS
  * Run as Administrator: without it, other users' hives, many scheduled
    tasks, BITS jobs for all users and some service keys are unreadable.
    The run summary lists what could not be read.
  * Only loaded user hives (HKEY_USERS) are covered; users who are not
    logged on are covered through their Startup folders and PS profiles only.
  * Flags are heuristics. Legitimate software lives in AppData, uses
    PowerShell and ships unsigned files; malware can be signed and live in
    System32. Treat every flag as a lead, and an unflagged entry as unverified.
  * This is a triage list in the spirit of Sysinternals Autoruns, not a full
    replacement (no codec, Winsock LSP, KnownDLLs or driver-signing checks).
"""
from __future__ import annotations

import argparse
import configparser
import csv
import ctypes
import datetime as dt
import glob
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict

try:
    import winreg  # type: ignore
except ImportError:  # allows import (and testing) off Windows
    winreg = None

IS_WIN = os.name == "nt"
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
SYS32 = os.path.join(WINDIR, "System32")
SYSWOW = os.path.join(WINDIR, "SysWOW64")
PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
USERS_DIR = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Entry:
    category: str
    location: str
    name: str
    command: str = ""
    path: str = ""
    user: str = ""
    enabled: bool = True
    exists: bool | None = None
    sig_status: str = ""
    signer: str = ""
    sha256: str = ""
    modified: str = ""
    flags: list = field(default_factory=list)
    severity: str = "info"
    note: str = ""
    no_file: bool = False   # entry is a name/ID, not something that maps to a file

    def key(self) -> str:
        return "|".join([self.category, self.location.lower(), self.name.lower(), self.command.lower()])

    def flag(self, sev: str, text: str):
        if text not in self.flags:
            self.flags.append(text)
        if SEV_ORDER[sev] > SEV_ORDER[self.severity]:
            self.severity = sev


class Ctx:
    """Shared state: errors encountered, user hive list, options."""

    def __init__(self, args):
        self.args = args
        self.errors: list[str] = []
        self.users = user_roots(self)

    def err(self, where: str, e: Exception | str):
        msg = f"{where}: {e}"
        if msg not in self.errors:
            self.errors.append(msg)


# ---------------------------------------------------------------------------
# Registry helpers (always read the native 64-bit view; WOW6432Node is read
# explicitly where it matters)
# ---------------------------------------------------------------------------

if winreg:
    HKLM, HKCU, HKU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER, winreg.HKEY_USERS
    HIVE_NAME = {HKLM: "HKLM", HKCU: "HKCU", HKU: "HKU"}
    ACCESS = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
else:  # pragma: no cover
    HKLM, HKCU, HKU, HIVE_NAME, ACCESS = "HKLM", "HKCU", "HKU", {}, 0


def _open(hive, path):
    return winreg.OpenKey(hive, path, 0, ACCESS)


def reg_values(hive, path):
    """Yield (name, data, type) for every value of a key; nothing if missing."""
    try:
        k = _open(hive, path)
    except OSError:
        return
    with k:
        i = 0
        while True:
            try:
                yield winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1


def reg_subkeys(hive, path):
    try:
        k = _open(hive, path)
    except OSError:
        return
    with k:
        i = 0
        while True:
            try:
                yield winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1


def reg_get(hive, path, name=""):
    try:
        with _open(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def reg_exists(hive, path):
    try:
        _open(hive, path).Close()
        return True
    except OSError:
        return False


def loc(hive, path, name=None):
    s = f"{HIVE_NAME.get(hive, hive)}\\{path}"
    return s if name is None else f"{s}\\{name or '(Default)'}"


def as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return " ; ".join(str(x) for x in v if x)
    if isinstance(v, bytes):
        return v.hex()
    return str(v)


def user_roots(ctx) -> list[tuple]:
    """[(label, hive, prefix)] for HKCU plus every other loaded user hive."""
    roots = [("current user", HKCU, "")]
    if not winreg:
        return roots
    names = {}
    for sid in reg_subkeys(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"):
        p = reg_get(HKLM, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "ProfileImagePath")
        if p:
            names[sid] = os.path.basename(p)
    cur = current_sid()
    for sid in reg_subkeys(HKU, ""):
        if sid.endswith("_Classes") or sid == cur or not sid.startswith("S-1-5-21-"):
            continue
        roots.append((names.get(sid, sid), HKU, sid + "\\"))
    return roots


def current_sid() -> str:
    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15)
        return out.stdout.strip().split(",")[-1].strip('"')
    except Exception:
        return ""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Command line -> file path
# ---------------------------------------------------------------------------

def expand(s: str) -> str:
    s = os.path.expandvars(s.strip().strip("\x00"))
    low = s.lower()
    if low.startswith("\\??\\"):
        s = s[4:]
    elif low.startswith("\\systemroot\\"):
        s = WINDIR + s[11:]
    elif low.startswith("system32\\"):
        s = os.path.join(WINDIR, s)
    elif low.startswith("%systemroot%"):
        s = WINDIR + s[12:]
    return s


def _resolve_bare(name: str) -> str:
    if os.path.isabs(name) or "\\" in name:
        return name
    for d in (SYS32, WINDIR, SYSWOW):
        for cand in (name, name + ".exe", name + ".dll"):
            p = os.path.join(d, cand)
            if os.path.exists(p):
                return p
    w = shutil.which(name)
    return w or name


def extract_path(cmd: str) -> str:
    """Best-effort: the file a command line actually loads (the DLL for rundll32/regsvr32)."""
    if not cmd:
        return ""
    c = expand(cmd)
    if c.startswith('"'):
        end = c.find('"', 1)
        exe, rest = (c[1:end], c[end + 1:]) if end > 0 else (c[1:], "")
    else:
        parts = c.split(" ")
        exe, rest = parts[0], " ".join(parts[1:])
        # unquoted paths with spaces: grow until something exists
        for i in range(1, len(parts) + 1):
            cand = " ".join(parts[:i])
            if os.path.isfile(cand) or os.path.isfile(cand + ".exe"):
                exe, rest = cand, " ".join(parts[i:])
                break
            m = re.match(r"([a-z]:\\[^/\"]+?\.(exe|dll|sys|com|scr|cpl|ocx|bat|cmd|ps1|vbs|js))\b", cand, re.I)
            if m and i == len(parts):
                exe, rest = m.group(1), c[len(m.group(1)):]
    exe = _resolve_bare(exe.strip())
    if os.path.splitext(os.path.basename(exe).lower())[0] in ("rundll32", "regsvr32"):
        args = [a for a in re.split(r"\s+", rest.strip()) if a and not a.startswith(("/", "-"))]
        if args:
            dll = args[0].strip('"').split(",")[0]
            return _resolve_bare(expand(dll))
    return exe


def dll_path(name: str) -> str:
    if not name:
        return ""
    p = expand(name)
    if not os.path.splitext(p)[1]:
        p += ".dll"
    return _resolve_bare(p)


def clsid_path(clsid: str, users=None) -> tuple[str, str]:
    """Server path for a CLSID, checking per-user classes first. Returns (path, where)."""
    roots = [(h, pre + r"Software\Classes\CLSID") for _, h, pre in (users or [])]
    roots += [(HKLM, r"SOFTWARE\Classes\CLSID"), (HKLM, r"SOFTWARE\WOW6432Node\Classes\CLSID")]
    for h, base in roots:
        for srv in ("InprocServer32", "LocalServer32"):
            v = reg_get(h, rf"{base}\{clsid}\{srv}")
            if v:
                return as_text(v), loc(h, rf"{base}\{clsid}\{srv}")
    return "", ""


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

COLLECTORS: dict = {}


def collector(name):
    def deco(fn):
        COLLECTORS[name] = fn
        return fn
    return deco


def startup_approved(hive, prefix) -> dict:
    """Disabled state from Task Manager's Startup tab: name -> enabled?"""
    out = {}
    for sub in ("Run", "Run32", "StartupFolder"):
        for n, data, _ in reg_values(hive, prefix + rf"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"):
            if isinstance(data, bytes) and data:
                out[n.lower()] = data[0] in (0x02, 0x06)
    return out


@collector("runkeys")
def c_runkeys(ctx):
    res = []
    cv = r"Software\Microsoft\Windows\CurrentVersion"
    machine = [rf"SOFTWARE\Microsoft\Windows\CurrentVersion\{k}" for k in ("Run", "RunOnce", "RunServices", "RunServicesOnce")]
    machine += [rf"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\{k}" for k in ("Run", "RunOnce")]
    machine += [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce"]
    user = [rf"{cv}\Run", rf"{cv}\RunOnce", rf"{cv}\RunServices", rf"{cv}\Policies\Explorer\Run",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"]
    approved_m = {}
    for n, data, _ in reg_values(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"):
        if isinstance(data, bytes) and data:
            approved_m[n.lower()] = data[0] in (0x02, 0x06)

    def add(hive, path, user_label, approved):
        for n, data, _ in reg_values(hive, path):
            cmd = as_text(data)
            if not cmd:
                continue
            e = Entry("Run keys", loc(hive, path), n or "(Default)", cmd, user=user_label)
            if approved.get((n or "").lower()) is False:
                e.enabled = False
                e.note = "disabled in Startup Apps"
            res.append(e)
        # RunOnceEx-style subkeys
        for sk in reg_subkeys(hive, path):
            for n, data, _ in reg_values(hive, rf"{path}\{sk}"):
                if as_text(data):
                    res.append(Entry("Run keys", loc(hive, rf"{path}\{sk}"), n or "(Default)", as_text(data), user=user_label))

    for p in machine:
        add(HKLM, p, "all users", approved_m)
    add(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", "all users", {})
    for label, hive, pre in ctx.users:
        appr = startup_approved(hive, pre)
        for p in user:
            add(hive, pre + p, label, appr)
        for v in ("Load", "Run"):
            data = reg_get(hive, pre + r"Software\Microsoft\Windows NT\CurrentVersion\Windows", v)
            if as_text(data).strip():
                e = Entry("Run keys", loc(hive, pre + r"Software\Microsoft\Windows NT\CurrentVersion\Windows", v), v, as_text(data), user=label)
                e.flag("high", f"Legacy Windows\\{v} value is set (rarely used by legitimate software)")
                res.append(e)
    return res


@collector("startup")
def c_startup(ctx):
    res = []
    folders = [(os.path.join(PROGRAMDATA, r"Microsoft\Windows\Start Menu\Programs\StartUp"), "all users")]
    for prof in glob.glob(os.path.join(USERS_DIR, "*")):
        folders.append((os.path.join(prof, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), os.path.basename(prof)))
    lnks = []
    for folder, user in folders:
        try:
            names = os.listdir(folder)
        except FileNotFoundError:
            continue
        except OSError as e:
            ctx.err(f"startup folder {folder}", e)
            continue
        for n in names:
            if n.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, n)
            e = Entry("Startup folder", folder, n, full, path=full, user=user)
            if n.lower().endswith(".lnk"):
                lnks.append(e)
            res.append(e)
    if lnks:
        targets = ps_json(LNK_PS, [e.path for e in lnks], ctx, "lnk targets") or []
        tmap = {t.get("p", "").lower(): t for t in targets if isinstance(t, dict)}
        for e in lnks:
            t = tmap.get(e.path.lower())
            if t and t.get("target"):
                e.command = f'{t["target"]} {t.get("args") or ""}'.strip()
                e.path = t["target"]
    return res


WINLOGON_DEFAULTS = {
    "Shell": ["explorer.exe"],
    "Userinit": [r"c:\windows\system32\userinit.exe,", r"c:\windows\system32\userinit.exe", "userinit.exe,", "userinit.exe"],
    "Taskman": [], "AppSetup": [], "VMApplet": ["systempropertiesperformance.exe /pagefile"], "GinaDLL": [],
}


@collector("winlogon")
def c_winlogon(ctx):
    res = []
    for hive, path, label in ((HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "all users"),
                              (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon", "all users")):
        for v, defaults in WINLOGON_DEFAULTS.items():
            data = as_text(reg_get(hive, path, v)).strip()
            if not data:
                continue
            e = Entry("Winlogon", loc(hive, path, v), v, data, user=label)
            if data.lower() not in defaults:
                e.flag("high", f"Non-default Winlogon {v} (default: {defaults[0] if defaults else 'not set'})")
            if v == "Userinit":
                e.path = extract_path(data.split(",")[0])
            res.append(e)
        for sk in reg_subkeys(hive, path + r"\Notify"):
            dll = as_text(reg_get(hive, rf"{path}\Notify\{sk}", "DllName"))
            e = Entry("Winlogon", loc(hive, rf"{path}\Notify\{sk}"), sk, dll, path=dll_path(dll), user=label)
            e.flag("medium", "Winlogon Notify package (legacy; unusual on Windows 10/11)")
            res.append(e)
    for label, hive, pre in ctx.users:
        p = pre + r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        sh = as_text(reg_get(hive, p, "Shell"))
        if sh:
            e = Entry("Winlogon", loc(hive, p, "Shell"), "Shell (per-user)", sh, user=label)
            e.flag("high", "Per-user Winlogon Shell override")
            res.append(e)
        scr = as_text(reg_get(hive, pre + "Environment", "UserInitMprLogonScript"))
        if scr:
            e = Entry("Winlogon", loc(hive, pre + "Environment", "UserInitMprLogonScript"), "UserInitMprLogonScript", scr, user=label)
            e.flag("high", "Logon script set via HKCU\\Environment (T1037.001)")
            res.append(e)
    return res


ACCESSIBILITY = ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe",
                 "atbroker.exe", "editionupgrademanager.exe")


@collector("ifeo")
def c_ifeo(ctx):
    res = []
    for base in (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"):
        for exe in reg_subkeys(HKLM, base):
            dbg = as_text(reg_get(HKLM, rf"{base}\{exe}", "Debugger"))
            if dbg:
                e = Entry("IFEO", loc(HKLM, rf"{base}\{exe}", "Debugger"), exe, dbg)
                sev = "high" if exe.lower() in ACCESSIBILITY else "medium"
                e.flag(sev, f"Debugger hijack: launching {exe} runs this instead")
                res.append(e)
            gf = reg_get(HKLM, rf"{base}\{exe}", "GlobalFlag")
            if isinstance(gf, int) and gf & 0x200:
                mon = as_text(reg_get(HKLM, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exe}", "MonitorProcess"))
                if mon:
                    e = Entry("IFEO", loc(HKLM, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exe}", "MonitorProcess"), exe, mon)
                    e.flag("high", f"SilentProcessExit monitor: runs when {exe} exits")
                    res.append(e)
    # accessibility binaries replaced by a shell
    ref = {}
    for n in ("cmd.exe", "powershell.exe", "explorer.exe", "taskmgr.exe"):
        p = os.path.join(SYS32 if n != "powershell.exe" else os.path.join(SYS32, r"WindowsPowerShell\v1.0"), n)
        if n == "explorer.exe":
            p = os.path.join(WINDIR, n)
        h = sha256(p)
        if h:
            ref[h] = n
    for n in ACCESSIBILITY:
        p = os.path.join(SYS32, n)
        h = sha256(p)
        if h and h in ref:
            e = Entry("IFEO", p, n, p, path=p)
            e.flag("high", f"{n} is byte-identical to {ref[h]} (sticky-keys style backdoor)")
            res.append(e)
    return res


@collector("appinit")
def c_appinit(ctx):
    res = []
    for base in (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"):
        dlls = as_text(reg_get(HKLM, base, "AppInit_DLLs")).strip()
        load = reg_get(HKLM, base, "LoadAppInit_DLLs")
        if dlls:
            for d in re.split(r"[ ,;]+", dlls):
                if not d:
                    continue
                e = Entry("AppInit", loc(HKLM, base, "AppInit_DLLs"), d, dlls, path=dll_path(d))
                e.enabled = bool(load)
                e.flag("high" if load else "medium", "AppInit_DLLs loads into every GUI process" + ("" if load else " (LoadAppInit_DLLs=0)"))
                res.append(e)
    p = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
    for n, data, _ in reg_values(HKLM, p):
        e = Entry("AppInit", loc(HKLM, p, n), n, as_text(data), path=dll_path(as_text(data)))
        e.flag("high", "AppCertDlls loads into every process calling CreateProcess")
        res.append(e)
    return res


@collector("bootexec")
def c_bootexec(ctx):
    res = []
    p = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    for v in ("BootExecute", "SetupExecute", "Execute", "S0InitialCommand", "BootExecuteNoPnpSync"):
        data = reg_get(HKLM, p, v)
        items = data if isinstance(data, list) else ([data] if data else [])
        for it in items:
            if not it:
                continue
            e = Entry("Boot execute", loc(HKLM, p, v), v, it, no_file=True)
            if not (v == "BootExecute" and it.strip().lower() in ("autocheck autochk *", "autocheck autochk /q /v *")):
                e.flag("high", f"Non-default {v} entry runs before Windows starts")
            res.append(e)
    return res


LSA_DEFAULTS = {
    "Authentication Packages": {"msv1_0"},
    "Notification Packages": {"scecli", "rassfm"},
    "Security Packages": {'""', "", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp"},
}


@collector("lsa")
def c_lsa(ctx):
    res = []
    for p in (r"SYSTEM\CurrentControlSet\Control\Lsa", r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"):
        for v, ok in LSA_DEFAULTS.items():
            data = reg_get(HKLM, p, v)
            items = data if isinstance(data, list) else ([data] if data else [])
            for it in items:
                if not it or it == '""':
                    continue
                e = Entry("LSA", loc(HKLM, p, v), it, it, path=dll_path(it))
                if it.lower() not in ok:
                    e.flag("high" if v == "Notification Packages" else "medium",
                           f"Non-default LSA {v[:-1].lower()} (loaded into lsass.exe; "
                           + ("password filter" if v == "Notification Packages" else "SSP/AP") + ")")
                res.append(e)
    return res


PRINT_DEFAULT = {"localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll", "appmon.dll", "winprint.dll",
                 "apmon.dll", "pjlmon.dll", "msonpmon.dll", "fxsmon.dll", "ipmon.dll", "mfmon.dll"}


@collector("print")
def c_print(ctx):
    res = []
    for base, kind in ((r"SYSTEM\CurrentControlSet\Control\Print\Monitors", "monitor"),
                       (r"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors", "processor")):
        for sk in reg_subkeys(HKLM, base):
            drv = as_text(reg_get(HKLM, rf"{base}\{sk}", "Driver"))
            if not drv:
                continue
            path = dll_path(drv) if "\\" in drv else drv
            if kind == "processor" and "\\" not in drv:
                path = os.path.join(SYS32, r"spool\prtprocs\x64", drv)
            e = Entry("Print", loc(HKLM, rf"{base}\{sk}", "Driver"), f"{kind}: {sk}", drv, path=path)
            if os.path.basename(drv).lower() not in PRINT_DEFAULT:
                e.flag("low", f"Non-default print {kind} DLL (loaded by spoolsv.exe as SYSTEM)")
            res.append(e)
    return res


START = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}


@collector("services")
def c_services(ctx):
    res = []
    base = r"SYSTEM\CurrentControlSet\Services"
    for sk in reg_subkeys(HKLM, base):
        p = rf"{base}\{sk}"
        typ = reg_get(HKLM, p, "Type")
        start = reg_get(HKLM, p, "Start")
        img = as_text(reg_get(HKLM, p, "ImagePath"))
        sdll = as_text(reg_get(HKLM, p + r"\Parameters", "ServiceDll") or reg_get(HKLM, p, "ServiceDll"))
        fail = as_text(reg_get(HKLM, p, "FailureCommand"))
        if not isinstance(typ, int) or (not img and not sdll):
            continue
        is_driver = bool(typ & 0x3)
        cat = "Drivers" if is_driver else "Services"
        file_ = dll_path(sdll) if sdll else extract_path(img)
        e = Entry(cat, loc(HKLM, p), sk, img + (f"  [ServiceDll: {sdll}]" if sdll else ""), path=file_,
                  user=as_text(reg_get(HKLM, p, "ObjectName")))
        e.note = f"start={START.get(start, start)}; " + as_text(reg_get(HKLM, p, "DisplayName"))[:60]
        e.enabled = start != 4
        keep = start in (0, 1, 2) or ctx.args.all_services or bool(fail)
        if sdll and not sdll.lower().startswith((r"%systemroot%\system32", r"c:\windows\system32")):
            e.flag("medium", "svchost ServiceDll outside System32")
            keep = True
        if re.search(r"\b(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32)(\.exe)?\b", img, re.I):
            e.flag("high", "Service runs a script host / LOLBin directly")
            keep = True
        if fail:
            e.flag("medium", f"FailureCommand runs on service failure: {fail}")
        if keep:
            res.append(e)
    return res


TASK_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def parse_task_xml(path: str, data: bytes) -> dict:
    root = ET.fromstring(data)
    g = lambda q: (root.find(q, TASK_NS).text if root.find(q, TASK_NS) is not None and root.find(q, TASK_NS).text else "")
    actions = []
    for ex in root.findall("t:Actions/t:Exec", TASK_NS):
        cmd = (ex.findtext("t:Command", "", TASK_NS) or "").strip()
        args = (ex.findtext("t:Arguments", "", TASK_NS) or "").strip()
        actions.append(("exec", f'"{cmd}" {args}'.strip() if " " in cmd and not cmd.startswith('"') else f"{cmd} {args}".strip(), cmd))
    for ch in root.findall("t:Actions/t:ComHandler", TASK_NS):
        actions.append(("com", ch.findtext("t:ClassId", "", TASK_NS), ""))
    trig = [t.tag.split("}")[-1] for t in (root.find("t:Triggers", TASK_NS) or [])]
    return {
        "author": g("t:RegistrationInfo/t:Author"),
        "date": g("t:RegistrationInfo/t:Date"),
        "uri": g("t:RegistrationInfo/t:URI"),
        "hidden": g("t:Settings/t:Hidden").lower() == "true",
        "enabled": g("t:Settings/t:Enabled").lower() != "false",
        "user": g("t:Principals/t:Principal/t:UserId") or g("t:Principals/t:Principal/t:GroupId"),
        "runlevel": g("t:Principals/t:Principal/t:RunLevel"),
        "triggers": trig,
        "actions": actions,
    }


@collector("tasks")
def c_tasks(ctx):
    res = []
    tdir = os.path.join(SYS32, "Tasks")
    for dirpath, _, files in os.walk(tdir, onerror=lambda e: ctx.err("tasks folder", e)):
        for f in files:
            full = os.path.join(dirpath, f)
            rel = full[len(tdir):]
            try:
                with open(full, "rb") as fh:
                    info = parse_task_xml(full, fh.read())
            except PermissionError:
                ctx.err("scheduled task (run as admin)", rel)
                continue
            except Exception as e:
                ent = Entry("Scheduled tasks", rel, os.path.basename(rel), "")
                ent.flag("medium", f"Task file is not valid task XML ({type(e).__name__})")
                res.append(ent)
                continue
            for kind, cmd, exe in info["actions"] or [("none", "", "")]:
                if kind == "com":
                    srv, where = clsid_path(cmd, ctx.users)
                    e = Entry("Scheduled tasks", rel, os.path.basename(rel), f"COM {cmd} -> {srv}", path=extract_path(srv) if srv else "")
                else:
                    e = Entry("Scheduled tasks", rel, os.path.basename(rel), cmd, path=extract_path(exe) if exe else "")
                e.user = info["user"]
                e.enabled = info["enabled"]
                e.note = f"author={info['author'] or '-'}; triggers={','.join(info['triggers']) or '-'}; runlevel={info['runlevel'] or '-'}"
                if info["hidden"]:
                    e.flag("low", "Task is marked Hidden")
                if not rel.lower().startswith("\\microsoft\\") and info["runlevel"] == "HighestAvailable" and info["user"] in ("S-1-5-18", "SYSTEM"):
                    e.flag("low", "Non-Microsoft task running as SYSTEM")
                res.append(e)
    # Tarrask-style hidden tasks: TaskCache\Tree entry without a security descriptor
    tree = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

    def walk(path, depth=0):
        if depth > 12:
            return
        for sk in reg_subkeys(HKLM, path):
            sp = rf"{path}\{sk}"
            names = {n for n, _, _ in reg_values(HKLM, sp)}
            if "Id" in names and "SD" not in names:
                e = Entry("Scheduled tasks", loc(HKLM, sp), sk, "task Id " + as_text(reg_get(HKLM, sp, "Id")), no_file=True)
                e.flag("high", "Task registered with no security descriptor (hidden from schtasks/Task Scheduler)")
                res.append(e)
            walk(sp, depth + 1)
    walk(tree)
    return res


WMI_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ns = 'root/subscription'
$f = Get-CimInstance -Namespace $ns -ClassName __EventFilter | ForEach-Object { [pscustomobject]@{Name=$_.Name; Query=$_.Query; EventNamespace=$_.EventNamespace} }
$c = Get-CimInstance -Namespace $ns -ClassName __EventConsumer | ForEach-Object {
  [pscustomobject]@{Class=$_.CimClass.CimClassName; Name=$_.Name; CommandLineTemplate=$_.CommandLineTemplate;
    ExecutablePath=$_.ExecutablePath; ScriptText=$_.ScriptText; ScriptFileName=$_.ScriptFileName; ScriptingEngine=$_.ScriptingEngine} }
$b = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | ForEach-Object {
  [pscustomobject]@{Filter=[string]$_.Filter.Name; Consumer=[string]$_.Consumer.Name} }
[pscustomobject]@{filters=@($f); consumers=@($c); bindings=@($b)} | ConvertTo-Json -Depth 4 -Compress
"""
WMI_BENIGN = {"SCM Event Log Consumer", "SCM Event Log Filter", "BVTFilter", "BVTConsumer"}


@collector("wmi")
def c_wmi(ctx):
    res = []
    data = ps_json(WMI_PS, None, ctx, "WMI subscriptions")
    if not isinstance(data, dict):
        return res
    bound = {}
    for b in data.get("bindings") or []:
        bound.setdefault(b.get("Consumer"), []).append(b.get("Filter"))
    filters = {f.get("Name"): f for f in data.get("filters") or []}
    for c in data.get("consumers") or []:
        cls, name = c.get("Class", ""), c.get("Name", "")
        cmd = c.get("CommandLineTemplate") or c.get("ExecutablePath") or c.get("ScriptFileName") or (c.get("ScriptText") or "")[:500]
        fl = bound.get(name, [])
        q = "; ".join((filters.get(x) or {}).get("Query", "") or "" for x in fl)
        e = Entry("WMI", rf"root\subscription\{cls}", name, cmd, path=extract_path(c.get("ExecutablePath") or c.get("CommandLineTemplate") or ""))
        e.note = f"filters={','.join(fl) or 'unbound'}; query={q[:120]}"
        if name not in WMI_BENIGN:
            if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
                e.flag("high", f"{cls}: runs code when the WMI event fires")
            else:
                e.flag("low", "Non-default WMI consumer")
        res.append(e)
    for name, f in filters.items():
        if name not in WMI_BENIGN and not any(name in v for v in bound.values()):
            e = Entry("WMI", r"root\subscription\__EventFilter", name, f.get("Query", ""), no_file=True)
            e.flag("low", "WMI event filter with no binding (leftover or staging)")
            res.append(e)
    return res


@collector("com")
def c_com(ctx):
    res = []
    for label, hive, pre in ctx.users:
        base = pre + r"Software\Classes\CLSID"
        for clsid in reg_subkeys(hive, base):
            for srv in ("InprocServer32", "LocalServer32"):
                v = as_text(reg_get(hive, rf"{base}\{clsid}\{srv}"))
                if not v:
                    continue
                e = Entry("COM (per-user)", loc(hive, rf"{base}\{clsid}\{srv}"), clsid, v, path=extract_path(v), user=label)
                machine = as_text(reg_get(HKLM, rf"SOFTWARE\Classes\CLSID\{clsid}\{srv}"))
                if machine and os.path.normcase(expand(machine)) != os.path.normcase(expand(v)):
                    e.flag("high", f"Per-user COM entry overrides the system one ({machine})")
                    e.note = "HKCU wins over HKLM for this CLSID"
                res.append(e)
    return res


@collector("explorer")
def c_explorer(ctx):
    res = []
    specs = [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "keys", "BHO"),
        (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "keys", "BHO"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "values", "ShellServiceObject"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", "values", "SharedTaskScheduler"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "values", "ShellExecuteHook"),
    ]
    for path, mode, kind in specs:
        clsids = list(reg_subkeys(HKLM, path)) if mode == "keys" else \
            [(as_text(d) if as_text(d).startswith("{") else n) for n, d, _ in reg_values(HKLM, path)]
        for clsid in clsids:
            srv, where = clsid_path(clsid, ctx.users)
            e = Entry("Explorer", loc(HKLM, path), f"{kind} {clsid}", srv or f"(unresolved {clsid})", path=extract_path(srv) if srv else "")
            if kind in ("SharedTaskScheduler", "ShellExecuteHook"):
                e.flag("medium", f"{kind} entries are rare on Windows 10/11")
            res.append(e)
    return res


@collector("activesetup")
def c_activesetup(ctx):
    res = []
    for base in (r"SOFTWARE\Microsoft\Active Setup\Installed Components",
                 r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"):
        for sk in reg_subkeys(HKLM, base):
            stub = as_text(reg_get(HKLM, rf"{base}\{sk}", "StubPath"))
            if stub:
                name = as_text(reg_get(HKLM, rf"{base}\{sk}")) or sk
                e = Entry("Active Setup", loc(HKLM, rf"{base}\{sk}", "StubPath"), name, stub)
                e.enabled = reg_get(HKLM, rf"{base}\{sk}", "IsInstalled") != 0
                res.append(e)
    return res


@collector("netsh")
def c_netsh(ctx):
    res = []
    for base in (r"SOFTWARE\Microsoft\NetSh", r"SOFTWARE\WOW6432Node\Microsoft\NetSh"):
        for n, d, _ in reg_values(HKLM, base):
            dll = as_text(d)
            e = Entry("Netsh helper", loc(HKLM, base, n), n, dll, path=dll_path(dll))
            if "\\" in dll:
                e.flag("medium", "Netsh helper DLL given with a full path (defaults are bare System32 names)")
            res.append(e)
    return res


@collector("cmdautorun")
def c_cmdautorun(ctx):
    res = []
    keys = [(HKLM, r"SOFTWARE\Microsoft\Command Processor", "all users"),
            (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Command Processor", "all users")]
    keys += [(h, pre + r"Software\Microsoft\Command Processor", lbl) for lbl, h, pre in ctx.users]
    for h, p, lbl in keys:
        v = as_text(reg_get(h, p, "AutoRun"))
        if v:
            e = Entry("Cmd AutoRun", loc(h, p, "AutoRun"), "AutoRun", v, user=lbl)
            e.flag("high", "Runs every time cmd.exe starts")
            res.append(e)
    return res


OFFICE_APPS = ("Word", "Excel", "PowerPoint", "Outlook", "Access", "Visio", "MS Project", "OneNote", "Publisher")


@collector("office")
def c_office(ctx):
    res = []
    for lbl, h, pre in ctx.users:
        p = pre + r"Software\Microsoft\Office test\Special\Perf"
        v = as_text(reg_get(h, p))
        if v:
            e = Entry("Office", loc(h, p), "Office test DLL", v, path=dll_path(v), user=lbl)
            e.flag("high", "'Office test' DLL loads into every Office application")
            res.append(e)
    roots = [(HKLM, "", "all users"), (HKLM, "WOW6432Node\\", "all users")]
    for app in OFFICE_APPS:
        for h, wow, lbl in roots:
            base = rf"SOFTWARE\{wow}Microsoft\Office\{app}\Addins"
            for prog in reg_subkeys(h, base):
                lb = reg_get(h, rf"{base}\{prog}", "LoadBehavior")
                res.append(Entry("Office", loc(h, rf"{base}\{prog}"), f"{app} add-in {prog}",
                                 as_text(reg_get(h, rf"{base}\{prog}", "Manifest")) or prog, user=lbl,
                                 enabled=lb in (3, 9, 16), note=f"LoadBehavior={lb}", no_file=True))
        for lbl, h, pre in ctx.users:
            base = pre + rf"Software\Microsoft\Office\{app}\Addins"
            for prog in reg_subkeys(h, base):
                lb = reg_get(h, rf"{base}\{prog}", "LoadBehavior")
                res.append(Entry("Office", loc(h, rf"{base}\{prog}"), f"{app} add-in {prog}",
                                 as_text(reg_get(h, rf"{base}\{prog}", "Manifest")) or prog, user=lbl,
                                 enabled=lb in (3, 9, 16), note=f"LoadBehavior={lb}", no_file=True))
    # template / workbook startup folders
    for prof in glob.glob(os.path.join(USERS_DIR, "*")):
        for sub in (r"AppData\Roaming\Microsoft\Word\STARTUP", r"AppData\Roaming\Microsoft\Excel\XLSTART",
                    r"AppData\Roaming\Microsoft\AddIns"):
            d = os.path.join(prof, sub)
            for f in glob.glob(os.path.join(d, "*")):
                e = Entry("Office", d, os.path.basename(f), f, path=f, user=os.path.basename(prof))
                if f.lower().endswith((".dotm", ".xlsm", ".xlam", ".xla", ".wll", ".xll", ".ppam")):
                    e.flag("medium", "Macro-enabled file auto-loads with Office")
                res.append(e)
    return res


@collector("screensaver")
def c_screensaver(ctx):
    res = []
    for lbl, h, pre in ctx.users:
        p = pre + r"Control Panel\Desktop"
        v = as_text(reg_get(h, p, "SCRNSAVE.EXE"))
        if v:
            e = Entry("Screensaver", loc(h, p, "SCRNSAVE.EXE"), "SCRNSAVE.EXE", v, path=extract_path(v), user=lbl)
            e.enabled = as_text(reg_get(h, p, "ScreenSaveActive")) == "1"
            if not expand(v).lower().startswith(SYS32.lower()):
                e.flag("medium", "Screensaver outside System32")
            res.append(e)
    return res


@collector("psprofile")
def c_psprofile(ctx):
    res = []
    cands = [(os.path.join(SYS32, r"WindowsPowerShell\v1.0", n), "all users") for n in
             ("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.PowerShellISE_profile.ps1")]
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    for d in glob.glob(os.path.join(pf, "PowerShell", "*")):
        cands += [(os.path.join(d, n), "all users") for n in ("profile.ps1", "Microsoft.PowerShell_profile.ps1")]
    for prof in glob.glob(os.path.join(USERS_DIR, "*")):
        for docs in glob.glob(os.path.join(prof, "Documents")) + glob.glob(os.path.join(prof, "OneDrive*", "Documents")):
            for sub in ("WindowsPowerShell", "PowerShell"):
                for n in ("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.VSCode_profile.ps1",
                          "Microsoft.PowerShellISE_profile.ps1"):
                    cands.append((os.path.join(docs, sub, n), os.path.basename(prof)))
    for p, lbl in cands:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(200_000)
            except OSError as e:
                ctx.err("PowerShell profile", e)
                text = ""
            first = " ".join(l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))[:300]
            e = Entry("PowerShell profile", os.path.dirname(p), os.path.basename(p), first, path=p, user=lbl)
            e.note = "runs in every PowerShell session"
            res.append(e)
    return res


@collector("timeprov")
def c_timeprov(ctx):
    res = []
    base = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
    for sk in reg_subkeys(HKLM, base):
        dll = as_text(reg_get(HKLM, rf"{base}\{sk}", "DllName"))
        if dll:
            e = Entry("Time provider", loc(HKLM, rf"{base}\{sk}", "DllName"), sk, dll, path=dll_path(dll))
            e.enabled = reg_get(HKLM, rf"{base}\{sk}", "Enabled") == 1
            if os.path.basename(expand(dll)).lower() not in ("w32time.dll", "vmictimeprovider.dll"):
                e.flag("high", "Non-default time provider DLL (loaded by svchost as LocalService)")
            res.append(e)
    return res


@collector("shims")
def c_shims(ctx):
    res = []
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
    for sk in reg_subkeys(HKLM, base + r"\InstalledSDB"):
        p = as_text(reg_get(HKLM, rf"{base}\InstalledSDB\{sk}", "DatabasePath"))
        desc = as_text(reg_get(HKLM, rf"{base}\InstalledSDB\{sk}", "DatabaseDescription"))
        e = Entry("Shims", loc(HKLM, rf"{base}\InstalledSDB\{sk}"), desc or sk, p, path=expand(p))
        e.flag("medium", "Custom shim database installed (can inject DLLs into the target program)")
        res.append(e)
    for exe in reg_subkeys(HKLM, base + r"\Custom"):
        for n, d, _ in reg_values(HKLM, rf"{base}\Custom\{exe}"):
            e = Entry("Shims", loc(HKLM, rf"{base}\Custom\{exe}"), exe, n, no_file=True)
            e.flag("medium", f"Custom shim applied to {exe}")
            res.append(e)
    return res


@collector("debuggers")
def c_debuggers(ctx):
    res = []
    for base in (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"):
        v = as_text(reg_get(HKLM, base, "Debugger"))
        if v:
            e = Entry("Debuggers", loc(HKLM, base, "Debugger"), "AeDebug", v)
            e.enabled = as_text(reg_get(HKLM, base, "Auto")) == "1"
            if e.enabled and not re.search(r"(vsjitdebugger|werfault|drwtsn32|windbg|procdump)", v, re.I):
                e.flag("medium", "Unusual post-mortem debugger that starts automatically on any crash")
            res.append(e)
    p = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs"
    v = as_text(reg_get(HKLM, p, "ReflectDebugger"))
    if v:
        e = Entry("Debuggers", loc(HKLM, p, "ReflectDebugger"), "WER ReflectDebugger", v)
        e.flag("high", "WER ReflectDebugger set (rarely legitimate)")
        res.append(e)
    return res


@collector("bits")
def c_bits(ctx):
    res = []
    exe = os.path.join(SYS32, "bitsadmin.exe")
    if not os.path.exists(exe):
        return res
    cmd = [exe, "/list", "/allusers", "/verbose"] if is_admin() else [exe, "/list", "/verbose"]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=60).stdout.decode("mbcs" if IS_WIN else "utf-8", "replace")
    except Exception as e:
        ctx.err("BITS", e)
        return res
    for block in re.split(r"\r?\n(?=GUID: )", out):
        if not block.startswith("GUID:"):
            continue
        g = lambda k: (re.search(rf"^{k}:\s*(.*)$", block, re.M) or [None, ""])[1].strip()
        name = re.search(r"DISPLAY:\s*'?([^'\r\n]*)", block)
        notify = g("NOTIFICATION COMMAND LINE")
        files = re.findall(r"^\s*\S.*? -> \S.*$", block, re.M)
        e = Entry("BITS", "BITS job " + g("GUID").split()[0] if g("GUID") else "BITS job",
                  name.group(1).strip() if name else "", notify or "; ".join(f.strip() for f in files[:3]),
                  user=g("OWNER"), no_file=True)
        e.note = f"state={g('STATE')}"
        if notify and notify.lower() not in ("none", ""):
            e.path, e.no_file = extract_path(notify.strip("'")), False
            e.flag("high", "BITS job with a notification command (runs when the job completes or errors)")
        res.append(e)
    return res


@collector("gposcripts")
def c_gposcripts(ctx):
    res = []
    for scope in ("Machine", "User"):
        for ini in ("scripts.ini", "psscripts.ini"):
            p = os.path.join(SYS32, "GroupPolicy", scope, "Scripts", ini)
            if not os.path.isfile(p):
                continue
            raw = open(p, "rb").read()
            text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
            cp = configparser.ConfigParser(interpolation=None)
            try:
                cp.read_string(text)
            except configparser.Error as e:
                ctx.err(p, e)
                continue
            for sec in cp.sections():
                items = dict(cp.items(sec))
                for k, v in items.items():
                    if k.endswith("cmdline"):
                        idx = k[: -len("cmdline")]
                        params = items.get(idx + "parameters", "")
                        e = Entry("GPO scripts", p, f"{scope} {sec}", f"{v} {params}".strip(), path=v)
                        e.flag("medium", f"Local Group Policy {sec.lower()} script")
                        res.append(e)
    return res


# ---------------------------------------------------------------------------
# PowerShell helpers (signatures, lnk targets, WMI)
# ---------------------------------------------------------------------------

LNK_PS = r"""
param($in, $out)
$sh = New-Object -ComObject WScript.Shell
$items = Get-Content -LiteralPath $in -Raw -Encoding UTF8 | ConvertFrom-Json
$r = foreach ($x in $items) {
  try { $l = $sh.CreateShortcut($x); [pscustomobject]@{p=$x; target=$l.TargetPath; args=$l.Arguments} }
  catch { [pscustomobject]@{p=$x; target=''; args=''} } }
ConvertTo-Json -InputObject @($r) -Compress | Set-Content -LiteralPath $out -Encoding UTF8
"""

SIG_PS = r"""
param($in, $out)
$items = Get-Content -LiteralPath $in -Raw -Encoding UTF8 | ConvertFrom-Json
$r = foreach ($x in $items) {
  $s = Get-AuthenticodeSignature -LiteralPath $x -ErrorAction SilentlyContinue
  $sub = ''; if ($s -and $s.SignerCertificate) { $sub = $s.SignerCertificate.Subject }
  [pscustomobject]@{p=$x; status=[string]$s.Status; signer=$sub} }
ConvertTo-Json -InputObject @($r) -Compress | Set-Content -LiteralPath $out -Encoding UTF8
"""


def ps_json(script: str, items, ctx, what):
    """Run a PowerShell snippet. With items: pass them as a JSON file and read JSON back."""
    ps = shutil.which("powershell") or os.path.join(SYS32, r"WindowsPowerShell\v1.0\powershell.exe")
    if not os.path.exists(ps):
        ctx.err(what, "PowerShell not found")
        return None
    try:
        with tempfile.TemporaryDirectory() as td:
            sp = os.path.join(td, "s.ps1")
            with open(sp, "w", encoding="utf-8-sig") as fh:
                fh.write(script)
            base = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", sp]
            if items is None:
                r = subprocess.run(base, capture_output=True, timeout=120)
                txt = r.stdout.decode("utf-8", "replace").strip()
            else:
                ip, op = os.path.join(td, "in.json"), os.path.join(td, "out.json")
                with open(ip, "w", encoding="utf-8") as fh:
                    json.dump(list(items), fh)
                subprocess.run(base + [ip, op], capture_output=True, timeout=600)
                if not os.path.exists(op):
                    ctx.err(what, "PowerShell produced no output")
                    return None
                txt = open(op, encoding="utf-8-sig").read().strip()
            if not txt:
                return None
            data = json.loads(txt)
            return [data] if isinstance(data, dict) and items is not None else data
    except Exception as e:
        ctx.err(what, e)
        return None


def check_signatures(entries, ctx):
    paths = sorted({e.path for e in entries if e.exists and e.path})
    sigs = {}
    for i in range(0, len(paths), 300):
        for r in ps_json(SIG_PS, paths[i:i + 300], ctx, "signature check") or []:
            if isinstance(r, dict):
                sigs[(r.get("p") or "").lower()] = r
    for e in entries:
        r = sigs.get((e.path or "").lower())
        if r:
            e.sig_status = r.get("status") or ""
            m = re.search(r"CN=([^,]+)", r.get("signer") or "")
            e.signer = m.group(1).strip('"') if m else (r.get("signer") or "")


def sha256(p: str) -> str:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

USER_WRITABLE = re.compile(r"\\(appdata|temp|tmp|users\\public|downloads|\$recycle\.bin|perflogs|windows\\tasks|"
                           r"windows\\temp|programdata|windows\\debug|windows\\tracing|intel)\\", re.I)
PATTERNS = [
    ("high", r"\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en|enc|enco|encod\w*)\s", "PowerShell encoded command"),
    ("high", r"(iex\b|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|"
             r"start-bitstransfer|frombase64string|invoke-restmethod|\birm\b)", "Download or in-memory execution cradle"),
    ("high", r"\bregsvr32(\.exe)?\b.*(/i:|scrobj)", "regsvr32 scriptlet (Squiblydoo)"),
    ("high", r"\brundll32(\.exe)?\b.*(javascript:|vbscript:|url\.dll|shell32\.dll,\s*shellexec_rundll|advpack\.dll|pcwutl\.dll)", "rundll32 proxy execution"),
    ("high", r"\bmshta(\.exe)?\b.*(http|javascript:|vbscript:)", "mshta running remote or inline script"),
    ("high", r"\bcertutil(\.exe)?\b.*(-urlcache|-decode|-decodehex)", "certutil download/decode"),
    ("high", r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com|bat|cmd|js|vbs|lnk)\b", "Double file extension"),
    ("medium", r"\b(mshta|wscript|cscript)(\.exe)?\b", "Script host"),
    ("medium", r"https?://|\bftp://", "URL in command line"),
    ("medium", r"^\s*\\\\[^\\]+\\|\s\\\\[^\\]+\\", "Runs from a network (UNC/WebDAV) path"),
    ("medium", r"-w(indowstyle)?\s+h(idden)?\b|-nop\b|-noni\b|-executionpolicy\s+bypass|-ep\s+bypass", "Hidden/bypass PowerShell switches"),
    ("medium", r"[A-Za-z0-9+/]{120,}={0,2}", "Long base64-like blob"),
    ("low", r"\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd|scr|pif)\b", "Script or screensaver file"),
    ("low", r"\bcmd(\.exe)?\s+/[ck]\b", "cmd /c wrapper"),
]
PATTERNS = [(s, re.compile(p, re.I), t) for s, p, t in PATTERNS]
TRUSTED_SIGNERS = re.compile(r"^(Microsoft Windows|Microsoft Corporation|Microsoft Windows Publisher|"
                             r"Microsoft Windows Hardware Compatibility Publisher)", re.I)


def analyse(e: Entry, ctx):
    a = ctx.args
    if e.no_file:
        e.path = ""
    if e.path:
        e.path = expand(e.path)
        e.exists = os.path.exists(e.path)
        if e.exists:
            try:
                st = os.stat(e.path)
                m = dt.datetime.fromtimestamp(max(st.st_mtime, st.st_ctime))
                e.modified = m.strftime("%Y-%m-%d %H:%M")
                if (dt.datetime.now() - m).days < a.recent_days:
                    e.flag("low", f"File created/modified in the last {a.recent_days} days")
            except OSError:
                pass
            if a.hash:
                e.sha256 = sha256(e.path)
        elif e.category not in ("Drivers",):
            e.flag("low", "Referenced file not found (orphaned or wrong path)")
    text = f"{e.command} {e.path}"
    for sev, rx, title in PATTERNS:
        if rx.search(text):
            e.flag(sev, title)
    if e.path and USER_WRITABLE.search(e.path):
        e.flag("medium", "Runs from a user-writable folder")


def signature_flags(e: Entry):
    if not e.exists or not e.path:
        return
    st = e.sig_status
    if st == "Valid":
        if TRUSTED_SIGNERS.match(e.signer or "") and e.severity in ("low", "medium") and \
                all(f.startswith(("Runs from a user-writable", "File created")) for f in e.flags):
            e.severity = "info"   # Microsoft-signed file in an expected-but-writable place (e.g. Defender in ProgramData)
        return
    if st in ("HashMismatch", "NotTrusted"):
        e.flag("high", f"Signature is {st}")
    elif st == "NotSigned":
        ext = os.path.splitext(e.path)[1].lower()
        if ext in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"):
            e.flag("medium" if SYS32.lower() not in e.path.lower() else "high",
                   "Unsigned binary" + (" in System32" if SYS32.lower() in e.path.lower() else ""))
    elif st and st not in ("UnknownError", "NotSupportedFileFormat"):
        e.flag("low", f"Signature status: {st}")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

COL = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[37m", "end": "\033[0m", "dim": "\033[2m"}


def console(entries, ctx, use_color=True):
    width = shutil.get_terminal_size((160, 40)).columns
    c = COL if use_color else {k: "" for k in COL}
    cur = None
    for e in entries:
        if e.category != cur:
            cur = e.category
            print(f"\n{c['dim']}=== {cur} ==={c['end']}")
        sig = e.signer or (e.sig_status if e.sig_status and e.sig_status != "Valid" else "")
        state = "" if e.enabled else " [disabled]"
        head = f"{c[e.severity]}{e.severity.upper():<6}{c['end']} {e.name}{state}"
        print(head[: width + 20])
        cmd = e.command.replace("\n", " ")
        print(f"       {cmd[: width - 8]}")
        meta = " | ".join(x for x in [e.location, f"user={e.user}" if e.user else "", f"signer={sig}" if sig else "",
                                       "MISSING FILE" if e.exists is False else "", e.note] if x)
        print(f"       {c['dim']}{meta[: width - 8]}{c['end']}")
        for f in e.flags:
            print(f"       {c[e.severity]}! {f}{c['end']}")


def write_csv(entries, path):
    cols = ["severity", "category", "name", "command", "path", "location", "user", "enabled", "exists",
            "sig_status", "signer", "sha256", "modified", "flags", "note"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for e in entries:
            d = asdict(e)
            d["flags"] = " | ".join(e.flags)
            w.writerow({k: d.get(k, "") for k in cols})


def write_html(entries, path, summary):
    rows = []
    for e in entries:
        rows.append(
            f'<tr class="{e.severity}{"" if e.enabled else " off"}"><td>{e.severity}</td><td>{html.escape(e.category)}</td>'
            f'<td>{html.escape(e.name)}</td><td class="m">{html.escape(e.command)}</td>'
            f'<td class="m">{html.escape(e.path)}{" (missing)" if e.exists is False else ""}</td>'
            f'<td>{html.escape(e.signer or e.sig_status)}</td><td>{html.escape(e.user)}</td>'
            f'<td>{"<br>".join(html.escape(f) for f in e.flags)}</td>'
            f'<td class="m s">{html.escape(e.location)}<br>{html.escape(e.note)}</td></tr>')
    doc = f"""<!doctype html><meta charset="utf-8"><title>Persistence report - {html.escape(summary['host'])}</title>
<style>
:root{{color-scheme:light dark;--bg:#f6f7f9;--fg:#1b1f24;--line:#d5d9e0;--hi:#c62828;--me:#b26a00;--lo:#00838f}}
@media(prefers-color-scheme:dark){{:root{{--bg:#14171c;--fg:#e3e6ea;--line:#2b3038;--hi:#ff6b6b;--me:#f5b041;--lo:#4dd0e1}}}}
body{{font:13px system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}}
h1{{font-size:18px;margin:0 0 4px}} .sum{{margin:0 0 12px;opacity:.8}}
input,select{{font:inherit;padding:4px 8px;margin:0 8px 10px 0}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top}}
th{{position:sticky;top:0;background:var(--bg);cursor:pointer}}
.m{{font-family:Consolas,monospace;word-break:break-all}} .s{{font-size:11px;opacity:.75}}
tr.high td:first-child{{color:var(--hi);font-weight:700}} tr.medium td:first-child{{color:var(--me);font-weight:700}}
tr.low td:first-child{{color:var(--lo)}} tr.off{{opacity:.55}}
</style>
<h1>Persistence report: {html.escape(summary['host'])}</h1>
<p class="sum">{html.escape(summary['time'])} &middot; admin={summary['admin']} &middot; {summary['counts']}
&middot; heuristic flags are leads, not verdicts</p>
<input id="q" placeholder="Filter text..."> <select id="sev"><option value="0">All severities</option>
<option value="1">low+</option><option value="2">medium+</option><option value="3">high</option></select>
<div class="wrap"><table id="t"><thead><tr><th>Sev</th><th>Category</th><th>Name</th><th>Command</th><th>File</th>
<th>Signer</th><th>User</th><th>Flags</th><th>Location / note</th></tr></thead><tbody>
{''.join(rows)}</tbody></table></div>
<script>
const O={{info:0,low:1,medium:2,high:3}},q=document.getElementById('q'),s=document.getElementById('sev');
function f(){{const t=q.value.toLowerCase(),m=+s.value;for(const r of document.querySelectorAll('#t tbody tr'))
r.hidden=!(r.textContent.toLowerCase().includes(t)&&O[r.className.split(' ')[0]]>=m)}}
q.oninput=f;s.onchange=f;
document.querySelectorAll('th').forEach((h,i)=>h.onclick=()=>{{const b=h.closest('table').tBodies[0];
[...b.rows].sort((a,c)=>i==0?O[c.className.split(' ')[0]]-O[a.className.split(' ')[0]]:a.cells[i].textContent.localeCompare(c.cells[i].textContent)).forEach(r=>b.append(r))}});
</script>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="List Windows persistence locations and flag suspicious entries (read-only).",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="Collectors: " + ", ".join(sorted(["runkeys", "startup", "winlogon", "ifeo", "appinit", "bootexec", "lsa", "print", "services", "tasks", "wmi", "com", "explorer", "activesetup", "netsh", "cmdautorun", "office", "screensaver", "psprofile", "timeprov", "shims", "debuggers", "bits", "gposcripts"])))
    p.add_argument("--only", help="comma-separated collectors to run")
    p.add_argument("--skip", help="comma-separated collectors to skip")
    p.add_argument("--list-collectors", action="store_true")
    p.add_argument("--min-severity", default="info", choices=list(SEV_ORDER), help="hide entries below this severity")
    p.add_argument("--hide-microsoft", action="store_true", help="hide unflagged entries whose file is validly signed by Microsoft")
    p.add_argument("--hide-disabled", action="store_true", help="hide entries that are disabled")
    p.add_argument("--no-signatures", action="store_true", help="skip Authenticode checks (faster)")
    p.add_argument("--hash", action="store_true", help="compute SHA-256 of every referenced file")
    p.add_argument("--all-services", action="store_true", help="include demand-start services/drivers too")
    p.add_argument("--recent-days", type=int, default=7, help="flag files changed within N days (default 7)")
    p.add_argument("--csv", help="write CSV report")
    p.add_argument("--json", help="write JSON (also usable as a --baseline later)")
    p.add_argument("--html", help="write an HTML report with filtering")
    p.add_argument("--baseline", help="JSON from an earlier run: mark entries that are new since then")
    p.add_argument("--only-new", action="store_true", help="with --baseline, show only new entries")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true", help="no console table (just the summary and files)")
    a = p.parse_args(argv)

    if a.list_collectors:
        for k in COLLECTORS:
            print(k)
        return 0
    if not IS_WIN or winreg is None:
        print("This script must run on Windows (it reads the Windows registry).", file=sys.stderr)
        return 2
    os.system("")  # enable ANSI colours in classic consoles

    t0 = time.time()
    ctx = Ctx(a)
    admin = is_admin()
    if not admin:
        print("! Not running as Administrator: coverage will be partial (other users, many tasks, BITS, some keys).",
              file=sys.stderr)
    names = list(COLLECTORS)
    if a.only:
        names = [n.strip() for n in a.only.split(",") if n.strip() in COLLECTORS]
    if a.skip:
        skip = {n.strip() for n in a.skip.split(",")}
        names = [n for n in names if n not in skip]

    entries: list[Entry] = []
    for n in names:
        print(f"[*] {n}", file=sys.stderr, flush=True)
        try:
            entries += COLLECTORS[n](ctx)
        except Exception as e:
            ctx.err(f"collector {n}", f"{type(e).__name__}: {e}")

    for e in entries:
        if not e.path and e.command and not e.no_file:
            e.path = extract_path(e.command)
        analyse(e, ctx)
    if not a.no_signatures:
        print("[*] checking signatures", file=sys.stderr, flush=True)
        check_signatures(entries, ctx)
        for e in entries:
            signature_flags(e)

    if a.baseline:
        try:
            old = {Entry(**{k: v for k, v in d.items() if k in Entry.__dataclass_fields__}).key()
                   for d in json.load(open(a.baseline, encoding="utf-8"))["entries"]}
            for e in entries:
                if e.key() not in old:
                    e.flag("medium", "NEW since baseline")
        except Exception as ex:
            ctx.err("baseline", ex)

    cat_order = {}
    for e in entries:
        cat_order.setdefault(e.category, len(cat_order))
    entries.sort(key=lambda e: (cat_order[e.category], -SEV_ORDER[e.severity], e.name.lower()))

    shown = [e for e in entries if SEV_ORDER[e.severity] >= SEV_ORDER[a.min_severity]]
    if a.hide_microsoft:
        shown = [e for e in shown if not (e.sig_status == "Valid" and TRUSTED_SIGNERS.match(e.signer or "") and not e.flags)]
    if a.hide_disabled:
        shown = [e for e in shown if e.enabled]
    if a.only_new:
        shown = [e for e in shown if "NEW since baseline" in e.flags]

    if not a.quiet:
        console(shown, ctx, not a.no_color)

    counts = {s: sum(1 for e in entries if e.severity == s) for s in ("high", "medium", "low", "info")}
    summary = {"host": os.environ.get("COMPUTERNAME", ""), "time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "admin": admin, "counts": ", ".join(f"{v} {k}" for k, v in counts.items()),
               "collectors": names, "errors": ctx.errors}
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "entries": [asdict(e) for e in entries]}, fh, indent=2)
    if a.csv:
        write_csv(shown, a.csv)
    if a.html:
        write_html(shown, a.html, summary)

    print(f"\n{len(entries)} entries ({summary['counts']}); showing {len(shown)}. "
          f"{time.time() - t0:.1f}s, admin={admin}", file=sys.stderr)
    if ctx.errors:
        print(f"{len(ctx.errors)} location(s) could not be read:", file=sys.stderr)
        for m in ctx.errors[:15]:
            print(f"  - {m}", file=sys.stderr)
        if len(ctx.errors) > 15:
            print(f"  ... and {len(ctx.errors) - 15} more (see --json summary)", file=sys.stderr)
    for k, v in (("CSV", a.csv), ("JSON", a.json), ("HTML", a.html)):
        if v:
            print(f"{k}: {os.path.abspath(v)}", file=sys.stderr)
    return 1 if counts["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
