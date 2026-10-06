#!/usr/bin/env python3
r"""
win11_file_forensics.py — gather every Windows 11 forensic artifact that references a file.

Given a file path (or just a file name) the script sweeps the file system, NTFS
metadata, registry, execution, user-activity, browser, event-log and persistence
artifacts for anything that mentions the file, and writes a JSON report, a CSV
super-timeline and a self-contained HTML report.

Modes
  live     (default) run on the Windows 11 machine itself, ideally as Administrator.
  offline  --root E:\  analyse a mounted image / KAPE / triage copy. The target
           path is the path as it was on the original system (C:\Users\...).

Examples
  python win11_file_forensics.py "C:\Users\max\Downloads\invoice.exe"
  python win11_file_forensics.py invoice.exe                      # name-only sweep
  python win11_file_forensics.py "C:\Users\max\Desktop\a.docx" --root F:\ --out case42
  python win11_file_forensics.py "C:\Tools\x.exe" --modules prefetch,amcache,eventlogs

Optional dependencies (pip install ...):
  regipy   offline registry hives + Amcache.hve        (strongly recommended)
  olefile  Jump Lists (AutomaticDestinations)
  pefile   PE version-info / imphash
  python-evtx  event logs when not running on Windows

Read-only: the script never modifies the evidence. Locked files are copied to a
temp directory (via a VSS snapshot with esentutl.exe when needed) and parsed there.
"""
from __future__ import annotations

import argparse
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
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from pathlib import PureWindowsPath

__version__ = "1.0.0"
IS_WIN = os.name == "nt"

if IS_WIN:
    import winreg
    from ctypes import wintypes

try:
    from regipy.registry import RegistryHive
    HAVE_REGIPY = True
except Exception:  # pragma: no cover
    HAVE_REGIPY = False
try:
    import olefile
except Exception:
    olefile = None
try:
    import pefile
except Exception:
    pefile = None

UTC = dt.timezone.utc
EPOCH1601 = dt.datetime(1601, 1, 1, tzinfo=UTC)
EPOCH1970 = dt.datetime(1970, 1, 1, tzinfo=UTC)

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _sane(d):
    return d if d and 1980 <= d.year <= 2100 else None


def ft2dt(ft):
    """Windows FILETIME (100ns since 1601) -> aware datetime."""
    try:
        ft = int(ft)
        if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
            return None
        return _sane(EPOCH1601 + dt.timedelta(microseconds=ft // 10))
    except Exception:
        return None


def webkit2dt(us):
    try:
        return _sane(EPOCH1601 + dt.timedelta(microseconds=int(us))) if us else None
    except Exception:
        return None


def unix2dt(sec, scale=1):
    try:
        return _sane(EPOCH1970 + dt.timedelta(seconds=int(sec) / scale)) if sec else None
    except Exception:
        return None


def parse_dt(s, fmts=("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S")):
    if not s:
        return None
    s = s.strip()
    for f in fmts:
        try:
            return dt.datetime.strptime(s, f).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def iso(d):
    if not d:
        return None
    if isinstance(d, str):
        return d
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, enc="cp1252"):
    return b[o:].split(b"\x00", 1)[0].decode(enc, "replace")


def wstr(b, o):
    end = o
    while end + 1 < len(b) and b[end:end + 2] != b"\x00\x00":
        end += 2
    return b[o:end].decode("utf-16le", "replace")


def to_bytes(v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", v or ""):
        return bytes.fromhex(v)
    return None


def strings_from_bytes(b, minlen=3):
    """UTF-16LE (both alignments) + ASCII strings from a blob."""
    out = []
    for off in (0, 1):
        seg = b[off:]
        seg = seg[: len(seg) - (len(seg) % 2)]
        s = seg.decode("utf-16le", "ignore")
        out += [x for x in re.split(r"[\x00-\x1f\ufffd]+", s) if len(x) >= minlen]
    out += [x.decode("latin-1") for x in re.findall(rb"[\x20-\x7e]{%d,}" % max(minlen, 4), b)]
    return out


def value_strings(data):
    if data is None:
        return []
    if isinstance(data, str):
        return [data]
    if isinstance(data, (list, tuple)):
        return [str(x) for x in data]
    if isinstance(data, (bytes, bytearray)):
        return strings_from_bytes(bytes(data))
    return [str(data)]


def read_text_any(path, limit=None):
    with open(path, "rb") as f:
        b = f.read(limit) if limit else f.read()
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "ignore")
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "ignore")
    sample = b[1:400:2]
    if sample and sample.count(0) > len(sample) * 0.6:
        return b.decode("utf-16le", "ignore")
    return b.decode("utf-8", "ignore")


def run(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=0x08000000 if IS_WIN else 0)  # CREATE_NO_WINDOW
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return -1, b"", str(e).encode()


def decode_console(b):
    for enc in ("utf-8", "oem" if IS_WIN else "latin-1", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("latin-1", "replace")


def powershell_json(script, timeout=180):
    if not IS_WIN:
        return None
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';" + script
    rc, out, _ = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                      "-Command", full], timeout)
    try:
        return json.loads(out.decode("utf-8", "ignore") or "null")
    except Exception:
        return None


def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def blob_hits(data, target, maxhits=25):
    """Find the target name inside a binary blob (ASCII + UTF-16LE) and return context strings."""
    hits = []
    if not target.name:
        return hits
    low = data.lower()
    for needle, width in ((target.name.encode("latin-1", "ignore"), 1),
                          (target.name.encode("utf-16le"), 2)):
        if not needle:
            continue
        start = 0
        while len(hits) < maxhits:
            i = low.find(needle, start)
            if i < 0:
                break
            start = i + len(needle)

            def ok(j):
                if width == 1:
                    return 0 <= j < len(data) and 0x20 <= data[j] < 0x7F
                return 0 <= j and j + 1 < len(data) and data[j + 1] == 0 and 0x20 <= data[j] < 0x7F
            a = i
            while ok(a - width) and i - a < 520:
                a -= width
            e = i + len(needle)
            while ok(e) and e - i < 520:
                e += width
            s = data[a:e].decode("latin-1" if width == 1 else "utf-16le", "ignore")
            if target.match(s) and s not in hits:
                hits.append(s)
    return hits


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def _clean(o):
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items() if v not in (None, "", [], {})}
    if isinstance(o, (list, tuple)):
        return [_clean(x) for x in o]
    if isinstance(o, dt.datetime):
        return iso(o)
    if isinstance(o, (bytes, bytearray)):
        return o[:256].hex() + ("…" if len(o) > 256 else "")
    return o


class Report:
    def __init__(self):
        self.findings, self.errors, self.notes = [], [], []

    def add(self, module, artifact, source, summary, details=None, times=None, match=None):
        times = {k: v for k, v in (times or {}).items() if v}
        self.findings.append({
            "module": module, "artifact": artifact, "source": str(source), "summary": summary,
            "match": match, "times": {k: iso(v) for k, v in times.items()},
            "details": _clean(details or {}),
        })

    def error(self, module, msg):
        self.errors.append({"module": module, "error": msg})

    def note(self, module, msg):
        self.notes.append({"module": module, "note": msg})

    def timeline(self):
        rows = []
        for f in self.findings:
            for label, ts in f["times"].items():
                rows.append({"timestamp": ts, "event": label, "module": f["module"],
                             "artifact": f["artifact"], "summary": f["summary"],
                             "source": f["source"], "match": f["match"]})
        rows.sort(key=lambda r: r["timestamp"])
        return rows


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #


class Target:
    def __init__(self, spec, ctx):
        spec = spec.strip().strip('"')
        self.spec = spec
        self.is_path = any(c in spec for c in "\\/:")
        self.path = self.nodrive = self.parent = self.local = None
        self.drive = None
        self.md5 = self.sha1 = self.sha256 = None
        if self.is_path:
            full = os.path.abspath(spec) if (ctx.live and IS_WIN) else spec
            wp = PureWindowsPath(full)
            if not wp.drive:
                wp = PureWindowsPath("C:\\") / wp
            self.path = str(wp)
            self.drive = wp.drive.upper()
            self.name = wp.name.lower()
            self.nodrive = self.path[len(wp.drive):].lower()
            self.parent = str(wp.parent).lower()
            self.local = ctx.map_path(self.path)
        else:
            self.name = spec.lower()
        self.stem = os.path.splitext(self.name)[0]
        self.ext = os.path.splitext(self.name)[1]
        self._rx_name = re.compile(r"(?<![\w.\-])" + re.escape(self.name) + r"(?!\w)", re.I)
        self._rx_path = re.compile(re.escape(self.nodrive) + r"(?![\w])", re.I) if self.nodrive else None
        self.exists = bool(self.local and os.path.exists(self.local))
        self.is_dir = bool(self.exists and os.path.isdir(self.local))
        if self.exists and not self.is_dir:
            self._hash()

    def _hash(self):
        h = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        try:
            with open(self.local, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    for x in h:
                        x.update(chunk)
            self.md5, self.sha1, self.sha256 = (x.hexdigest() for x in h)
        except OSError:
            pass

    def match(self, text):
        """Return 'path', 'hash', 'name' or None."""
        if text is None:
            return None
        t = text if isinstance(text, str) else str(text)
        if "%" in t:
            t = t + " " + urllib.parse.unquote(t)
        t = html.unescape(t).replace("\\\\", "\\").replace("/", "\\")
        if self._rx_path and self._rx_path.search(t):
            return "path"
        if self.sha1 and self.sha1 in t.lower():
            return "hash"
        if self._rx_name.search(t):
            return "name"
        return None

    def match_any(self, items):
        best = (None, None)
        rank = {"path": 3, "hash": 2, "name": 1, None: 0}
        for s in items:
            m = self.match(s)
            if rank[m] > rank[best[0]]:
                best = (m, s)
                if m == "path":
                    break
        return best


# --------------------------------------------------------------------------- #
# Registry abstraction (live winreg  <->  offline regipy)
# --------------------------------------------------------------------------- #

REG_TYPES = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_EXPAND": 2, "REG_BINARY": 3, "REG_DWORD": 4,
             "REG_DWORD_BIG_ENDIAN": 5, "REG_LINK": 6, "REG_MULTI_SZ": 7, "REG_QWORD": 11, "REG_NONE": 0}


class LiveKey:
    def __init__(self, root, path, handle):
        self.root, self.path, self.h = root, path, handle
        self.name = path.rsplit("\\", 1)[-1]
        ns, nv, lw = winreg.QueryInfoKey(handle)
        self._ns, self._nv, self.lastwrite = ns, nv, ft2dt(lw)

    @staticmethod
    def open(root, path):
        try:
            h = winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            return LiveKey(root, path, h)
        except OSError:
            return None

    def child(self, name):
        return LiveKey.open(self.root, self.path + "\\" + name)

    def subkeys(self):
        for i in range(self._ns):
            try:
                n = winreg.EnumKey(self.h, i)
            except OSError:
                break
            k = self.child(n)
            if k:
                yield k

    def values(self):
        for i in range(self._nv):
            try:
                n, d, t = winreg.EnumValue(self.h, i)
            except OSError:
                break
            yield n, d, t

    def value(self, name):
        try:
            return winreg.QueryValueEx(self.h, name)[0]
        except OSError:
            return None


class LiveReg:
    def __init__(self, root, base, label):
        self.root, self.base, self.label = root, base, label

    def key(self, rel=""):
        p = self.base + ("\\" + rel.strip("\\") if rel else "")
        return LiveKey.open(self.root, p)

    @staticmethod
    def exists(root, path):
        return LiveKey.open(root, path) is not None


class HiveKey:
    def __init__(self, nk, path):
        self.nk, self.path = nk, path
        self.name = nk.name
        self.lastwrite = ft2dt(nk.header.last_modified)

    def child(self, name):
        try:
            return HiveKey(self.nk.get_subkey(name), self.path + "\\" + name)
        except Exception:
            return None

    def subkeys(self):
        try:
            for sk in self.nk.iter_subkeys():
                yield HiveKey(sk, self.path + "\\" + sk.name)
        except Exception:
            return

    def values(self):
        try:
            for v in self.nk.iter_values(as_json=False, trim_values=False):
                yield ("" if v.name == "(default)" else v.name), v.value, REG_TYPES.get(str(v.value_type), 0)
        except Exception:
            return

    def value(self, name):
        for n, d, _ in self.values():
            if n.lower() == name.lower():
                return d
        return None


class HiveReg:
    def __init__(self, path, label):
        self.hive = RegistryHive(path)
        self.label = label

    def key(self, rel=""):
        try:
            if not rel:
                return HiveKey(self.hive.root, "")
            return HiveKey(self.hive.get_key("\\" + rel.strip("\\")), rel.strip("\\"))
        except Exception:
            return None


def walk_keys(key, depth=0, maxdepth=64):
    yield key
    if depth < maxdepth:
        for sk in key.subkeys():
            yield from walk_keys(sk, depth + 1, maxdepth)


class User:
    def __init__(self, name, sid, profile, ntuser, usrclass):
        self.name, self.sid, self.profile, self.ntuser, self.usrclass = name, sid, profile, ntuser, usrclass

    def label(self):
        return f"{self.name} ({self.sid or 'SID?'})"


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #


class Ctx:
    def __init__(self, args):
        self.args = args
        self.live = args.root is None
        self.root = args.root or (os.environ.get("SystemDrive", "C:") + "\\")
        self.tmp = tempfile.mkdtemp(prefix="w11ff_")
        self.r = Report()
        self.admin = is_admin()
        self._copies = {}
        self._system = self._software = self._users = self._amcache = None
        self._dosdev = None
        self.target = Target(args.target, self)

    # paths --------------------------------------------------------------
    def sp(self, *parts):
        return os.path.join(self.root, *parts)

    def map_path(self, winpath):
        if self.live:
            return winpath
        parts = PureWindowsPath(winpath).parts[1:]
        return os.path.join(self.root, *parts)

    def user_dirs(self):
        skip = {"default", "default user", "all users", "defaultapppool"}
        out = []
        for d in sorted(glob.glob(self.sp("Users", "*"))):
            n = os.path.basename(d)
            if os.path.isdir(d) and n.lower() not in skip and not os.path.islink(d):
                out.append((n, d))
        return out

    # copying locked files -------------------------------------------------
    def copy(self, src, companions=("-wal", "-shm", ".LOG1", ".LOG2")):
        if src in self._copies:
            return self._copies[src]
        if not os.path.isfile(src):
            self._copies[src] = None
            return None
        dst = os.path.join(self.tmp, f"{len(self._copies):04d}_{os.path.basename(src)}")

        def one(s, d):
            try:
                shutil.copyfile(s, d)
                return True
            except OSError:
                pass
            if IS_WIN and self.admin and not self.args.no_vss:
                run(["esentutl.exe", "/y", s, "/vss", "/d", d], timeout=600)
                return os.path.isfile(d)
            return False

        ok = one(src, dst)
        if ok:
            for c in companions:
                if os.path.isfile(src + c):
                    one(src + c, dst + c)
        else:
            self.r.error("copy", f"could not read locked file {src}"
                                 + ("" if self.admin else " (run as Administrator)"))
        self._copies[src] = dst if ok else None
        return self._copies[src]

    def open_hive(self, path, label):
        if not HAVE_REGIPY:
            if "regipy" not in str(self.r.errors):
                self.r.error("registry", "regipy not installed - offline hives/Amcache skipped (pip install regipy)")
            return None
        c = self.copy(path)
        if not c:
            return None
        log1, log2 = c + ".LOG1", c + ".LOG2"
        if os.path.isfile(log1):
            try:
                from regipy.recovery import apply_transaction_logs
                restored = c + ".restored"
                apply_transaction_logs(c, log1, log2 if os.path.isfile(log2) else None, restored)
                if os.path.isfile(restored):
                    c = restored
            except Exception:
                pass
        try:
            return HiveReg(c, label)
        except Exception as e:
            self.r.error("registry", f"cannot parse hive {path}: {e}")
            return None

    # hives ------------------------------------------------------------------
    @property
    def system(self):
        if self._system is None:
            if self.live:
                self._system = (LiveReg(winreg.HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM"), "CurrentControlSet")
            else:
                h = self.open_hive(self.sp("Windows", "System32", "config", "SYSTEM"), "SYSTEM")
                ccs = "ControlSet001"
                if h:
                    k = h.key("Select")
                    cur = k.value("Current") if k else None
                    ccs = f"ControlSet{int(cur or 1):03d}"
                self._system = (h, ccs)
        return self._system

    @property
    def software(self):
        if self._software is None:
            if self.live:
                self._software = LiveReg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE")
            else:
                self._software = self.open_hive(self.sp("Windows", "System32", "config", "SOFTWARE"), "SOFTWARE") or False
        return self._software or None

    @property
    def users(self):
        if self._users is not None:
            return self._users
        profiles = {}
        sw = self.software
        if sw:
            k = sw.key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
            for sk in (k.subkeys() if k else []):
                p = sk.value("ProfileImagePath")
                if p and (sk.name.startswith("S-1-5-21") or sk.name.startswith("S-1-12-")):
                    profiles[sk.name] = os.path.expandvars(str(p)) if self.live else str(p)
        users = []
        if self.live:
            for sid, prof in profiles.items():
                if not os.path.isdir(prof):
                    continue
                name = os.path.basename(prof)
                if LiveReg.exists(winreg.HKEY_USERS, sid):
                    nt = LiveReg(winreg.HKEY_USERS, sid, f"HKU\\{sid}")
                else:
                    nt = self.open_hive(os.path.join(prof, "NTUSER.DAT"), f"{name}\\NTUSER.DAT")
                if LiveReg.exists(winreg.HKEY_USERS, sid + "_Classes"):
                    uc = LiveReg(winreg.HKEY_USERS, sid + "_Classes", f"HKU\\{sid}_Classes")
                else:
                    uc = self.open_hive(os.path.join(prof, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
                                        f"{name}\\UsrClass.dat")
                users.append(User(name, sid, prof, nt, uc))
        else:
            by_name = {PureWindowsPath(p).name.lower(): s for s, p in profiles.items()}
            for name, d in self.user_dirs():
                nt_path = os.path.join(d, "NTUSER.DAT")
                if not os.path.isfile(nt_path):
                    continue
                nt = self.open_hive(nt_path, f"{name}\\NTUSER.DAT")
                uc = self.open_hive(os.path.join(d, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
                                    f"{name}\\UsrClass.dat")
                users.append(User(name, by_name.get(name.lower()), d, nt, uc))
        self._users = users
        return users

    @property
    def amcache(self):
        if self._amcache is None:
            self._amcache = self.open_hive(self.sp("Windows", "appcompat", "Programs", "Amcache.hve"), "Amcache.hve") or False
        return self._amcache or None

    def dos_devices(self):
        """\\Device\\HarddiskVolumeN -> C: (live only)."""
        if self._dosdev is None:
            self._dosdev = {}
            if IS_WIN and self.live:
                buf = ctypes.create_unicode_buffer(1024)
                for L in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    if ctypes.windll.kernel32.QueryDosDeviceW(f"{L}:", buf, 1024):
                        self._dosdev[buf.value.lower()] = f"{L}:"
        return self._dosdev

    def device_to_dos(self, p):
        m = re.match(r"(\\device\\harddiskvolume\d+)(.*)", p, re.I)
        if m and m.group(1).lower() in self.dos_devices():
            return self.dos_devices()[m.group(1).lower()] + m.group(2)
        return p


# --------------------------------------------------------------------------- #
# Module registry
# --------------------------------------------------------------------------- #

MODULES = {}


def module(name, desc, default=True, needs_windows=False, live_only=False):
    def deco(fn):
        MODULES[name] = dict(fn=fn, desc=desc, default=default, needs_windows=needs_windows, live_only=live_only)
        return fn
    return deco


# --------------------------------------------------------------------------- #
# Win32 helpers (ctypes)
# --------------------------------------------------------------------------- #

if IS_WIN:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.OpenFileById.restype = wintypes.HANDLE
    k32.OpenFileById.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD]
    k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    k32.FindFirstStreamW.restype = wintypes.HANDLE
    k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.FindClose.argtypes = [wintypes.HANDLE]
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

GENERIC_READ = 0x80000000
FILE_READ_ATTRIBUTES = 0x80
FILE_SHARE_ALL = 7
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FSCTL_GET_NTFS_FILE_RECORD = 0x00090068
FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB


def win_open(path, access=FILE_READ_ATTRIBUTES, flags=FILE_FLAG_BACKUP_SEMANTICS):
    h = k32.CreateFileW(path, access, FILE_SHARE_ALL, None, OPEN_EXISTING, flags, None)
    if h in (None, INVALID_HANDLE):
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def ioctl(h, code, inbuf, outsize):
    out = ctypes.create_string_buffer(outsize)
    ret = wintypes.DWORD()
    inb = ctypes.create_string_buffer(inbuf, len(inbuf)) if inbuf else None
    ok = k32.DeviceIoControl(h, code, inb, len(inbuf) if inbuf else 0, out, outsize, ctypes.byref(ret), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return out.raw[: ret.value]


def file_reference(path):
    h = win_open(path)
    try:
        buf = ctypes.create_string_buffer(52)
        if not k32.GetFileInformationByHandle(h, buf):
            raise ctypes.WinError(ctypes.get_last_error())
        f = struct.unpack("<I3Q6I", buf.raw)
        serial, hi, lo = f[4], f[8], f[9]
        return (hi << 32) | lo, serial
    finally:
        k32.CloseHandle(h)


class FrnResolver:
    """Resolve NTFS file reference numbers to paths via OpenFileById (live)."""

    def __init__(self, drive):
        self.drive = drive
        self.cache = {}
        try:
            self.vh = win_open(drive + "\\")
        except Exception:
            self.vh = None

    def path(self, frn):
        if frn in self.cache:
            return self.cache[frn]
        p = None
        if self.vh:
            desc = struct.pack("<IIQ8x", 24, 0, frn)
            h = k32.OpenFileById(self.vh, ctypes.create_string_buffer(desc, 24), 0, FILE_SHARE_ALL, None,
                                 FILE_FLAG_BACKUP_SEMANTICS)
            if h not in (None, INVALID_HANDLE):
                buf = ctypes.create_unicode_buffer(1024)
                n = k32.GetFinalPathNameByHandleW(h, buf, 1024, 0)
                k32.CloseHandle(h)
                if n:
                    p = buf.value.replace("\\\\?\\", "")
        self.cache[frn] = p
        return p


# --------------------------------------------------------------------------- #
# Binary format parsers (pure Python, OS-independent)
# --------------------------------------------------------------------------- #

FILE_ATTRS = {0x1: "READONLY", 0x2: "HIDDEN", 0x4: "SYSTEM", 0x10: "DIRECTORY", 0x20: "ARCHIVE",
              0x40: "DEVICE", 0x80: "NORMAL", 0x100: "TEMPORARY", 0x200: "SPARSE", 0x400: "REPARSE_POINT",
              0x800: "COMPRESSED", 0x1000: "OFFLINE", 0x2000: "NOT_CONTENT_INDEXED", 0x4000: "ENCRYPTED",
              0x8000: "INTEGRITY_STREAM", 0x20000: "NO_SCRUB_DATA", 0x40000: "RECALL_ON_OPEN",
              0x80000: "PINNED", 0x100000: "UNPINNED", 0x400000: "RECALL_ON_DATA_ACCESS"}


def flags_str(v, table):
    return "|".join(n for b, n in table.items() if v & b) or hex(v)


KNOWN_FOLDERS = {
    "20D04FE0-3AEA-1069-A2D8-08002B30309D": "My Computer",
    "59031A47-3F72-44A7-89C5-5595FE6B30EE": "%USERPROFILE%",
    "F02C1A0D-BE21-4350-88B0-7367FC96EF3C": "Network",
    "645FF040-5081-101B-9F08-00AA002F954E": "Recycle Bin",
    "679F85CB-0220-4080-B29B-5540CC05AAB6": "Quick Access",
    "031E4825-7B94-4DC3-B131-E946B44C8DD5": "Libraries",
    "374DE290-123F-4565-9164-39C4925E467B": "Downloads",
    "088E3905-0323-4B02-9826-5D99428E115F": "Downloads",
    "FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
    "D3162B92-9365-467A-956B-92703ACA08AF": "Documents",
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
    "33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
    "24AD3AD4-A569-4530-98E1-AB02F9417AA8": "Pictures",
    "F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A": "Videos",
    "3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE": "Music",
    "018D5C66-4533-4307-9B53-224DE2ED1FE6": "OneDrive",
    "6D809377-6AF0-444B-8957-A3773F02200E": "C:\\Program Files",
    "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": "C:\\Program Files (x86)",
    "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": "C:\\Windows\\System32",
    "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": "C:\\Windows\\SysWOW64",
    "F38BF404-1D43-42F2-9305-67DE0B28FC23": "C:\\Windows",
    "0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    "9E3995AB-1F9C-4F13-B827-48B24B6C7174": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
}


def _utf16_runs(b):
    runs = []
    for off in (0, 1):
        for m in re.finditer(rb"(?:[\x20-\x7e\xa0-\xff]\x00){1,}", b[off:]):
            runs.append(m.group().decode("utf-16le"))
    return runs


def parse_shell_item(b):
    """Return a display name for one shell item (best effort)."""
    if len(b) < 3:
        return None
    t = b[2]
    try:
        if t == 0x1F and len(b) >= 20:
            g = str(uuid.UUID(bytes_le=b[4:20])).upper()
            return KNOWN_FOLDERS.get(g, "{" + g + "}")
        if 0x20 <= t <= 0x2F:
            s = cstr(b, 3)
            return s.rstrip("\\") if s else None
        if 0x30 <= t <= 0x3F and len(b) > 14:
            short = cstr(b, 14)
            i = b.find(b"\x04\x00\xef\xbe")
            if i > 0:
                runs = [r for r in _utf16_runs(b[i + 4:]) if len(r) >= 1]
                cand = [r for r in runs if short and r.lower()[:3] == short.lower()[:3]] or runs
                if cand:
                    return max(cand, key=len)
            return short or None
        if 0x40 <= t <= 0x4F:
            return cstr(b, 5) or None
        if t == 0x00 or t == 0x74 or t == 0x71:
            runs = _utf16_runs(b)
            return max(runs, key=len) if runs else None
    except Exception:
        return None
    runs = _utf16_runs(b)
    return max(runs, key=len) if runs else None


def join_shell_path(parts):
    out = ""
    for p in parts:
        if not p:
            continue
        if p in ("My Computer",):
            continue
        if re.fullmatch(r"[A-Za-z]:", p) or p.startswith("\\\\"):
            out = p
        elif not out:
            out = p
        else:
            out = out.rstrip("\\") + "\\" + p
    return out


def parse_idlist(b):
    parts, off = [], 0
    while off + 2 <= len(b):
        sz = u16(b, off)
        if sz == 0:
            break
        parts.append(parse_shell_item(b[off:off + sz]))
        off += sz
    return join_shell_path(parts)


DRIVE_TYPES = {0: "UNKNOWN", 1: "NO_ROOT_DIR", 2: "REMOVABLE", 3: "FIXED", 4: "REMOTE", 5: "CDROM", 6: "RAMDISK"}


def uuid1_info(u):
    try:
        if u.version == 1:
            t = dt.datetime(1582, 10, 15, tzinfo=UTC) + dt.timedelta(microseconds=u.time // 10)
            mac = ":".join(f"{(u.node >> s) & 0xFF:02x}" for s in range(40, -1, -8))
            return _sane(t), mac
    except Exception:
        pass
    return None, None


def parse_lnk(b):
    if len(b) < 0x4C or b[:4] != b"\x4c\x00\x00\x00":
        raise ValueError("not a shell link")
    flags, attrs = struct.unpack_from("<II", b, 0x14)
    ct, at, mt = struct.unpack_from("<QQQ", b, 0x1C)
    r = {"target_created": ft2dt(ct), "target_accessed": ft2dt(at), "target_modified": ft2dt(mt),
         "target_size": u32(b, 0x34), "target_attributes": flags_str(attrs, FILE_ATTRS)}
    off = 0x4C
    if flags & 0x1:
        n = u16(b, off)
        r["idlist_path"] = parse_idlist(b[off + 2:off + 2 + n])
        off += 2 + n
    if flags & 0x2:
        li_size, li_hdr, li_flags, vol_off, lbp_off, cnrl_off, cps_off = struct.unpack_from("<7I", b, off)
        li = b[off:off + li_size]
        lbp = cstr(li, lbp_off) if (li_flags & 1 and lbp_off) else ""
        cps = cstr(li, cps_off) if cps_off else ""
        if li_hdr >= 0x24:
            lbpu, cpsu = struct.unpack_from("<II", li, 28)
            if lbpu:
                lbp = wstr(li, lbpu)
            if cpsu:
                cps = wstr(li, cpsu)
        if li_flags & 1 and vol_off:
            _, dtype, serial, lab_off = struct.unpack_from("<4I", li, vol_off)
            label = wstr(li, vol_off + u32(li, vol_off + 16)) if lab_off == 0x14 else cstr(li, vol_off + lab_off)
            r.update(drive_type=DRIVE_TYPES.get(dtype, dtype), volume_serial=f"{serial:08X}", volume_label=label)
        net = ""
        if li_flags & 2 and cnrl_off:
            c = cnrl_off
            _, cflags, nn_off, dev_off = struct.unpack_from("<4I", li, c)
            net = cstr(li, c + nn_off)
            r["network_share"] = net
            if cflags & 1 and dev_off:
                r["network_device"] = cstr(li, c + dev_off)
        if lbp:
            r["target_path"] = lbp + cps
        elif net:
            r["target_path"] = net.rstrip("\\") + ("\\" + cps if cps else "")
        off += li_size
    uni = flags & 0x80
    for bit, key in ((0x4, "name"), (0x8, "relative_path"), (0x10, "working_dir"),
                     (0x20, "arguments"), (0x40, "icon_location")):
        if flags & bit and off + 2 <= len(b):
            n = u16(b, off)
            off += 2
            if uni:
                r[key] = b[off:off + 2 * n].decode("utf-16le", "replace")
                off += 2 * n
            else:
                r[key] = b[off:off + n].decode("cp1252", "replace")
                off += n
    while off + 8 <= len(b):
        sz = u32(b, off)
        if sz < 8:
            break
        sig = u32(b, off + 4)
        blk = b[off:off + sz]
        if sig == 0xA0000003 and sz >= 0x60:
            r["machine_id"] = cstr(blk, 16, "latin-1")
            vol = uuid.UUID(bytes_le=blk[32:48])
            fil = uuid.UUID(bytes_le=blk[48:64])
            r["droid_volume"] = str(vol)
            r["droid_file"] = str(fil)
            t, mac = uuid1_info(fil)
            r["droid_created"], r["droid_mac"] = t, mac
            bfil = uuid.UUID(bytes_le=blk[80:96])
            r["birth_droid_file"] = str(bfil)
        elif sig == 0xA0000001 and sz >= 0x314:
            r["env_target"] = wstr(blk, 268) or cstr(blk, 8)
        off += sz
    r["target"] = r.get("target_path") or r.get("env_target") or r.get("idlist_path") or r.get("relative_path")
    return r


def parse_destlist(b):
    ver, n = u32(b, 0), u32(b, 4)
    out, off = [], 32
    for _ in range(n):
        try:
            if ver >= 3:
                host = cstr(b, off + 72, "latin-1")[:16]
                eid, mt = u32(b, off + 88), u64(b, off + 100)
                pin, cnt, plen = struct.unpack_from("<i", b, off + 108)[0], u32(b, off + 116), u16(b, off + 128)
                path = b[off + 130:off + 130 + 2 * plen].decode("utf-16le", "replace")
                off += 130 + 2 * plen + 4
            else:
                host = cstr(b, off + 72, "latin-1")[:16]
                eid, mt = u64(b, off + 88), u64(b, off + 100)
                pin, plen = struct.unpack_from("<i", b, off + 108)[0], u16(b, off + 112)
                cnt = int(struct.unpack_from("<f", b, off + 96)[0])
                path = b[off + 114:off + 114 + 2 * plen].decode("utf-16le", "replace")
                off += 114 + 2 * plen
            out.append({"entry_id": eid, "hostname": host, "last_access": ft2dt(mt), "pinned": pin != -1,
                        "access_count": cnt, "path": path})
        except Exception:
            break
    return out


JUMPLIST_APPIDS = {
    "5f7b5f1e01b83767": "Quick Access (Explorer)", "f01b4d95cf55d32a": "Windows Explorer",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)", "1b4dd67f29cb1962": "Windows Explorer (pinned)",
    "9839aec31243a928": "Microsoft Excel 2010", "a7bd71699cd38d1c": "Microsoft Word 2010",
    "fb3b0dbfee58fac8": "Microsoft Word 365", "b8ab77100df80ab2": "Microsoft Excel 365",
    "d00655d2aa12ff6d": "Microsoft PowerPoint 365", "12dc1ea8e34b5a6": "Microsoft Paint",
    "9fda41b86ddcf1db": "VLC", "5d696d521de238c3": "Google Chrome", "9d1f905ce5044aee": "Microsoft Edge",
    "6824f4a902c78fbd": "Mozilla Firefox", "7e4dca80246863e3": "Control Panel",
    "1bc392b8e104a00e": "Remote Desktop (mstsc)", "ccba5a5986c77e43": "Microsoft Edge (Chromium)",
    "290532160612e071": "WinRAR", "23646679aaccfae0": "Adobe Acrobat Reader", "e2a593822e01aed3": "Adobe Acrobat",
}

USN_REASONS = {0x1: "DATA_OVERWRITE", 0x2: "DATA_EXTEND", 0x4: "DATA_TRUNCATION", 0x10: "NAMED_DATA_OVERWRITE",
               0x20: "NAMED_DATA_EXTEND", 0x40: "NAMED_DATA_TRUNCATION", 0x100: "FILE_CREATE",
               0x200: "FILE_DELETE", 0x400: "EA_CHANGE", 0x800: "SECURITY_CHANGE", 0x1000: "RENAME_OLD_NAME",
               0x2000: "RENAME_NEW_NAME", 0x4000: "INDEXABLE_CHANGE", 0x8000: "BASIC_INFO_CHANGE",
               0x10000: "HARD_LINK_CHANGE", 0x20000: "COMPRESSION_CHANGE", 0x40000: "ENCRYPTION_CHANGE",
               0x80000: "OBJECT_ID_CHANGE", 0x100000: "REPARSE_POINT_CHANGE", 0x200000: "STREAM_CHANGE",
               0x400000: "TRANSACTED_CHANGE", 0x800000: "INTEGRITY_CHANGE", 0x80000000: "CLOSE"}


def parse_mft_record(rec):
    if rec[:4] != b"FILE":
        raise ValueError("bad MFT record signature")
    rec = bytearray(rec)
    usa_off, usa_cnt = u16(rec, 4), u16(rec, 6)
    usn = rec[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        end = i * 512 - 2
        if end + 2 <= len(rec) and rec[end:end + 2] == usn:
            rec[end:end + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    seq, links, attr_off, flags = u16(rec, 0x10), u16(rec, 0x12), u16(rec, 0x14), u16(rec, 0x16)
    out = {"sequence": seq, "hard_links": links, "in_use": bool(flags & 1), "is_directory": bool(flags & 2),
           "record_number": u32(rec, 0x2C), "si": None, "fn": [], "data_streams": []}
    off = attr_off
    while off + 16 <= len(rec):
        atype = u32(rec, off)
        if atype == 0xFFFFFFFF:
            break
        alen = u32(rec, off + 4)
        if alen == 0:
            break
        nonres, nlen, noff = rec[off + 8], rec[off + 9], u16(rec, off + 10)
        aname = rec[off + noff:off + noff + 2 * nlen].decode("utf-16le", "replace") if nlen else ""
        if not nonres:
            clen, coff = u32(rec, off + 16), u16(rec, off + 20)
            c = bytes(rec[off + coff:off + coff + clen])
        else:
            c = b""
        if atype == 0x10 and len(c) >= 0x30:
            cr, mo, mft, ac = struct.unpack_from("<4Q", c, 0)
            out["si"] = {"created": cr, "modified": mo, "mft_modified": mft, "accessed": ac,
                         "flags": flags_str(u32(c, 0x20), FILE_ATTRS),
                         "usn": u64(c, 0x40) if len(c) >= 0x48 else None}
        elif atype == 0x30 and len(c) >= 0x42:
            parent = u64(c, 0)
            cr, mo, mft, ac = struct.unpack_from("<4Q", c, 8)
            nl, ns = c[0x40], c[0x41]
            out["fn"].append({"parent_ref": parent, "created": cr, "modified": mo, "mft_modified": mft,
                              "accessed": ac, "alloc_size": u64(c, 0x28), "real_size": u64(c, 0x30),
                              "namespace": {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32&DOS"}.get(ns, ns),
                              "name": c[0x42:0x42 + 2 * nl].decode("utf-16le", "replace")})
        elif atype == 0x80:
            size = u64(rec, off + 48) if nonres else len(c)
            out["data_streams"].append({"name": aname or "(unnamed)", "resident": not nonres, "size": size})
        off += alen
    return out


def parse_shimcache(b):
    """Windows 10/11 AppCompatCache value."""
    out = []
    if len(b) < 0x34:
        return out
    off = u32(b, 0)
    if off not in (0x30, 0x34):
        off = 0x34
    i = 0
    while off + 12 <= len(b) and b[off:off + 4] == b"10ts":
        size = u32(b, off + 8)
        e = off + 12
        plen = u16(b, e)
        path = b[e + 2:e + 2 + plen].decode("utf-16le", "replace")
        p = e + 2 + plen
        ts = u64(b, p) if p + 8 <= len(b) else 0
        dlen = u32(b, p + 8) if p + 12 <= len(b) else 0
        data = b[p + 12:p + 12 + dlen]
        out.append({"position": i, "path": path, "last_modified": ft2dt(ts), "data_len": dlen,
                    "exec_flag": (u32(data, len(data) - 4) if len(data) >= 4 else None)})
        off = e + size
        i += 1
    return out


def rot13(s):
    return s.translate(str.maketrans("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
                                     "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"))


def expand_known_guids(p):
    def rep(m):
        return KNOWN_FOLDERS.get(m.group(1).upper(), m.group(0))
    return re.sub(r"\{([0-9A-Fa-f\-]{36})\}", rep, p)


def pf_decompress(data):
    if data[:3] != b"MAM":
        return data
    usize = u32(data, 4)
    comp = data[8:]
    if IS_WIN:
        nt = ctypes.WinDLL("ntdll")
        ws, fws = ctypes.c_ulong(), ctypes.c_ulong()
        nt.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(4), ctypes.byref(ws), ctypes.byref(fws))
        out = ctypes.create_string_buffer(usize)
        wsb = ctypes.create_string_buffer(max(ws.value, 1))
        final = ctypes.c_ulong()
        src = ctypes.create_string_buffer(comp, len(comp))
        st = nt.RtlDecompressBufferEx(ctypes.c_ushort(4), out, ctypes.c_ulong(usize), src,
                                      ctypes.c_ulong(len(comp)), ctypes.byref(final), wsb)
        if st != 0:
            raise OSError(f"RtlDecompressBufferEx NTSTATUS 0x{st & 0xFFFFFFFF:08X}")
        return out.raw[: final.value]
    try:
        from dissect.util.compression import lzxpress_huffman
        return lzxpress_huffman.decompress(comp)
    except ImportError:
        raise RuntimeError("MAM-compressed prefetch needs Windows or `pip install dissect.util`")


def parse_prefetch(raw):
    d = pf_decompress(raw)
    if d[4:8] != b"SCCA":
        raise ValueError("not a prefetch file")
    ver = u32(d, 0)
    exe = d[0x10:0x10 + 60].decode("utf-16le", "replace").split("\x00")[0]
    r = {"version": ver, "executable": exe, "hash": f"{u32(d, 0x4C):08X}"}
    fs_off, fs_size = u32(d, 0x64), u32(d, 0x68)
    vol_off, vol_cnt = u32(d, 0x6C), u32(d, 0x70)
    if ver in (26, 30, 31):
        times = [ft2dt(u64(d, 0x80 + 8 * i)) for i in range(8)]
        if ver == 26:
            rc_off = 0xD0
        else:
            rc_off = 0xC8 if u32(d, 0x54) == 0x128 else 0xD0
    elif ver == 23:
        times, rc_off = [ft2dt(u64(d, 0x80))], 0x98
    else:
        times, rc_off = [ft2dt(u64(d, 0x78))], 0x90
    r["last_run_times"] = [t for t in times if t]
    r["run_count"] = u32(d, rc_off)
    r["files"] = [x for x in d[fs_off:fs_off + fs_size].decode("utf-16le", "replace").split("\x00") if x]
    vols = []
    esz = 96 if ver >= 30 else (104 if ver == 26 else 40)
    for i in range(min(vol_cnt, 16)):
        e = vol_off + i * esz
        try:
            dp_off, dp_len, vct, ser = u32(d, e), u32(d, e + 4), u64(d, e + 8), u32(d, e + 16)
            dev = d[vol_off + dp_off:vol_off + dp_off + 2 * dp_len].decode("utf-16le", "replace")
            vols.append({"device": dev, "serial": f"{ser:08X}", "created": ft2dt(vct)})
        except Exception:
            break
    r["volumes"] = vols
    return r


def parse_recycle_i(b):
    ver = u64(b, 0)
    size, ts = u64(b, 8), u64(b, 16)
    if ver == 2:
        n = u32(b, 24)
        name = b[28:28 + 2 * n].decode("utf-16le", "replace").rstrip("\x00")
    else:
        name = b[24:24 + 520].decode("utf-16le", "replace").split("\x00")[0]
    return {"version": ver, "size": size, "deleted": ft2dt(ts), "original_path": name}


# --------------------------------------------------------------------------- #
# MODULES
# --------------------------------------------------------------------------- #

def _magic(path):
    sigs = [(b"MZ", "PE/DOS executable"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP/OOXML/JAR"),
            (b"\xd0\xcf\x11\xe0", "OLE2 (legacy Office/MSI)"), (b"\x7fELF", "ELF"), (b"Rar!", "RAR"),
            (b"7z\xbc\xaf", "7-Zip"), (b"\x89PNG", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"GIF8", "GIF"),
            (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)"), (b"{\\rtf", "RTF"),
            (b"\x1f\x8b", "GZIP"), (b"MSCF", "CAB"), (b"ITSF", "CHM"), (b"#!", "script"),
            (b"\xef\xbb\xbf", "UTF-8 text (BOM)"), (b"\xff\xfe", "UTF-16 text (BOM)")]
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None, None
    for s, n in sigs:
        if head.startswith(s):
            return n, head.hex()
    return "unknown", head.hex()


def _pe_info(path):
    info = {}
    try:
        with open(path, "rb") as f:
            b = f.read(4096)
        if b[:2] != b"MZ":
            return None
        e = u32(b, 0x3C)
        if b[e:e + 4] != b"PE\x00\x00":
            return None
        machine, nsec, ts = struct.unpack_from("<HHI", b, e + 4)
        chars = u16(b, e + 22)
        opt = e + 24
        magic = u16(b, opt)
        info.update(machine={0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine, hex(machine)),
                    sections=nsec, compile_time=unix2dt(ts), is_dll=bool(chars & 0x2000),
                    pe32plus=magic == 0x20B, subsystem={2: "GUI", 3: "CUI (console)", 1: "native"}.get(
                        u16(b, opt + 68), u16(b, opt + 68)))
    except Exception:
        return None
    if pefile:
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                                                   pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            vi = {}
            for fi in getattr(pe, "FileInfo", None) or []:
                for entry in (fi if isinstance(fi, list) else [fi]):
                    for st in getattr(entry, "StringTable", []) or []:
                        for k, v in st.entries.items():
                            vi[k.decode(errors="ignore")] = v.decode(errors="ignore")
            info["version_info"] = vi
            try:
                info["imphash"] = pe.get_imphash()
            except Exception:
                pass
            pe.close()
        except Exception as e:
            info["pefile_error"] = str(e)
    return info


@module("filesystem", "File metadata, hashes, magic, owner/ACL, PE header, Authenticode signature")
def m_filesystem(ctx):
    t = ctx.target
    if not t.is_path:
        ctx.r.note("filesystem", "name-only target: on-disk checks skipped")
        return
    if not t.exists:
        ctx.r.add("filesystem", "File system", t.path, "File NOT present on disk (deleted, moved or renamed?)",
                  {"expected_local_path": t.local}, match="path")
        return
    st = os.stat(t.local)
    birth = getattr(st, "st_birthtime", None) or (st.st_ctime if IS_WIN else None)
    magic, head = _magic(t.local) if not t.is_dir else ("directory", None)
    det = {"local_path": t.local, "size": st.st_size, "attributes": flags_str(getattr(st, "st_file_attributes", 0), FILE_ATTRS),
           "magic": magic, "header_hex": head, "md5": t.md5, "sha1": t.sha1, "sha256": t.sha256}
    if magic and t.ext and ((magic.startswith("PE") and t.ext not in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi", ".mui", ".drv"))):
        det["WARNING"] = f"extension {t.ext} does not match content ({magic})"
    times = {"created (SI, Win32)": unix2dt(birth) if birth else None, "modified (SI, Win32)": unix2dt(st.st_mtime),
             "accessed (SI, Win32)": unix2dt(st.st_atime)}
    ctx.r.add("filesystem", "File system metadata", t.local, f"{st.st_size} bytes, {magic}", det, times, "path")

    if not t.is_dir:
        pe = _pe_info(t.local)
        if pe:
            vi = pe.get("version_info", {})
            orig = vi.get("OriginalFilename") or vi.get("InternalName")
            if orig and orig.lower() != t.name:
                pe["WARNING"] = f"OriginalFilename '{orig}' differs from on-disk name (renamed / masquerading?)"
            ctx.r.add("filesystem", "PE header", t.local,
                      f"{pe.get('machine')} {'DLL' if pe.get('is_dll') else 'EXE'}, compiled {iso(pe.get('compile_time'))}",
                      pe, {"PE compile timestamp": pe.get("compile_time")}, "path")

    if IS_WIN:
        q = ps_quote(t.local)
        acl = powershell_json(f"$a=Get-Acl -LiteralPath {q}; [pscustomobject]@{{Owner=$a.Owner;Group=$a.Group;"
                              f"Access=$a.AccessToString;Sddl=$a.Sddl}} | ConvertTo-Json -Compress")
        if acl:
            ctx.r.add("filesystem", "Owner / ACL", t.local, f"owner {acl.get('Owner')}", acl, match="path")
        if not t.is_dir:
            sig = powershell_json(
                f"$s=Get-AuthenticodeSignature -LiteralPath {q}; [pscustomobject]@{{Status=[string]$s.Status;"
                f"Message=$s.StatusMessage;SignatureType=[string]$s.SignatureType;IsOSBinary=$s.IsOSBinary;"
                f"Signer=$s.SignerCertificate.Subject;Issuer=$s.SignerCertificate.Issuer;"
                f"Thumbprint=$s.SignerCertificate.Thumbprint;NotBefore=[string]$s.SignerCertificate.NotBefore;"
                f"NotAfter=[string]$s.SignerCertificate.NotAfter;TimeStamper=$s.TimeStamperCertificate.Subject}}"
                f" | ConvertTo-Json -Compress")
            if sig:
                ctx.r.add("filesystem", "Authenticode signature", t.local,
                          f"{sig.get('Status')} - {sig.get('Signer') or 'unsigned'}", sig, match="path")


@module("ads", "Alternate data streams incl. Zone.Identifier (Mark-of-the-Web: download URL)", needs_windows=True)
def m_ads(ctx):
    t = ctx.target
    if not (t.exists and IS_WIN):
        return
    data = WIN32_FIND_STREAM_DATA()
    h = k32.FindFirstStreamW(t.local, 0, ctypes.byref(data), 0)
    if h in (None, INVALID_HANDLE):
        return
    streams = []
    try:
        while True:
            streams.append((data.cStreamName, data.StreamSize))
            if not k32.FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        k32.FindClose(h)
    for name, size in streams:
        if name == "::$DATA":
            continue
        sname = name.split(":")[1]
        content = b""
        try:
            with open(f"{t.local}:{sname}", "rb") as f:
                content = f.read(65536)
        except OSError as e:
            content = str(e).encode()
        det = {"stream": sname, "size": size}
        summary = f"ADS '{sname}' ({size} bytes)"
        if sname.lower() == "zone.identifier":
            txt = content.decode("utf-8", "ignore")
            kv = dict(re.findall(r"^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$", txt, re.M))
            zones = {"0": "Local", "1": "Intranet", "2": "Trusted", "3": "Internet", "4": "Restricted"}
            det.update(kv)
            det["zone"] = zones.get(kv.get("ZoneId", ""), kv.get("ZoneId"))
            summary = f"Mark-of-the-Web: zone {det['zone']}" + (f", from {kv.get('HostUrl')}" if kv.get("HostUrl") else "")
        else:
            det["content_preview"] = content[:1024].decode("utf-8", "replace")
            det["content_sha256"] = hashlib.sha256(content).hexdigest()
        ctx.r.add("ads", "Alternate data stream", f"{t.local}:{sname}", summary, det, match="path")


@module("mft", "$MFT record: $STANDARD_INFORMATION vs $FILE_NAME times (timestomp detection)", needs_windows=True)
def m_mft(ctx):
    t = ctx.target
    if not (t.exists and IS_WIN):
        return
    if not ctx.admin:
        ctx.r.error("mft", "Administrator required to read $MFT records")
        return
    frn, _ = file_reference(t.local)
    drive = os.path.splitdrive(os.path.abspath(t.local))[0]
    vh = win_open("\\\\.\\" + drive, GENERIC_READ, 0)
    try:
        out = ioctl(vh, FSCTL_GET_NTFS_FILE_RECORD, struct.pack("<Q", frn & 0xFFFFFFFFFFFF), 4096 + 64)
    finally:
        k32.CloseHandle(vh)
    got = u64(out, 0) & 0xFFFFFFFFFFFF
    rec = parse_mft_record(out[12:12 + u32(out, 8)])
    if got != frn & 0xFFFFFFFFFFFF:
        ctx.r.error("mft", f"FSCTL returned record {got} instead of {frn & 0xFFFFFFFFFFFF}")
        return
    res = FrnResolver(drive)
    si = rec["si"] or {}
    det = {"mft_record": frn & 0xFFFFFFFFFFFF, "sequence": rec["sequence"], "hard_links": rec["hard_links"],
           "si_flags": si.get("flags"), "si_usn": si.get("usn"), "data_streams": rec["data_streams"]}
    times = {f"$SI {k}": ft2dt(si.get(k)) for k in ("created", "modified", "mft_modified", "accessed")}
    flags = []
    for fn in rec["fn"]:
        fn["parent_path"] = res.path(fn["parent_ref"])
        if fn["namespace"] != "DOS":
            for k in ("created", "modified", "mft_modified", "accessed"):
                times[f"$FN {k}"] = ft2dt(fn[k])
        if si.get("created") and fn["created"] and si["created"] < fn["created"]:
            flags.append("$SI created earlier than $FN created (classic timestomp indicator)")
    for k in ("created", "modified"):
        v = si.get(k)
        if v and v % 10_000_000 == 0:
            flags.append(f"$SI {k} has zero sub-second precision (tool-set timestamp?)")
    if si.get("modified") and si.get("created") and si["modified"] < si["created"]:
        flags.append("$SI modified before created (file copied, or timestamps altered)")
    det["file_names"] = [{k: (iso(ft2dt(v)) if k in ("created", "modified", "mft_modified", "accessed") else v)
                          for k, v in fn.items()} for fn in rec["fn"]]
    det["anomalies"] = flags
    ctx.r.add("mft", "$MFT record", f"{drive} MFT #{frn & 0xFFFFFFFFFFFF}",
              f"MFT entry {frn & 0xFFFFFFFFFFFF} seq {rec['sequence']}" + (f" - {len(flags)} anomaly(ies)" if flags else ""),
              det, {k: v for k, v in times.items()}, "path")


@module("usn", "NTFS $UsnJrnl:$J change journal: create/rename/delete history", needs_windows=True, live_only=True)
def m_usn(ctx):
    t = ctx.target
    if not IS_WIN:
        return
    if not ctx.admin:
        ctx.r.error("usn", "Administrator required to read the USN journal")
        return
    drive = t.drive or os.environ.get("SystemDrive", "C:")
    my_rec = None
    if t.exists:
        frn, _ = file_reference(t.local)
        my_rec = frn & 0xFFFFFFFFFFFF
    vh = win_open("\\\\.\\" + drive, GENERIC_READ, 0)
    recs = []
    try:
        jd = ioctl(vh, FSCTL_QUERY_USN_JOURNAL, None, 80)
        jid, first, nxt = struct.unpack_from("<QqQ", jd, 0)
        start = first
        buf_sz = 1 << 20
        while True:
            inp = struct.pack("<qIIQQQ", start, 0xFFFFFFFF, 0, 0, 0, jid)
            try:
                data = ioctl(vh, FSCTL_READ_USN_JOURNAL, inp, buf_sz)
            except OSError as e:
                ctx.r.error("usn", f"read journal: {e}")
                break
            if len(data) <= 8:
                break
            start = struct.unpack_from("<q", data, 0)[0]
            off = 8
            while off + 60 <= len(data):
                rl = u32(data, off)
                if rl == 0:
                    break
                major = u16(data, off + 4)
                if major == 2:
                    frn, pfrn, usn, ts, reason, _, _, attrs, fnl, fno = struct.unpack_from("<QQqQIIIIHH", data, off + 8)
                elif major == 3:
                    f16, p16, usn, ts, reason, _, _, attrs, fnl, fno = struct.unpack_from("<16s16sqQIIIIHH", data, off + 8)
                    frn, pfrn = int.from_bytes(f16[:8], "little"), int.from_bytes(p16[:8], "little")
                else:
                    off += rl
                    continue
                name = data[off + fno:off + fno + fnl].decode("utf-16le", "replace")
                recs.append((frn, pfrn, usn, ts, reason, attrs, name))
                off += rl
    finally:
        k32.CloseHandle(vh)
    frns = {r[0] for r in recs if r[6].lower() == t.name or (my_rec is not None and (r[0] & 0xFFFFFFFFFFFF) == my_rec)}
    hits = [r for r in recs if r[0] in frns]
    res = FrnResolver(drive)
    ctx.r.note("usn", f"scanned {len(recs)} USN records on {drive}; {len(hits)} relate to the target")
    for frn, pfrn, usn, ts, reason, attrs, name in hits[: ctx.args.max_usn]:
        parent = res.path(pfrn) or f"<parent MFT #{pfrn & 0xFFFFFFFFFFFF}>"
        rs = flags_str(reason, USN_REASONS)
        ctx.r.add("usn", "$UsnJrnl:$J", f"{drive} USN {usn}", f"{rs}: {parent}\\{name}",
                  {"usn": usn, "mft_record": frn & 0xFFFFFFFFFFFF, "sequence": frn >> 48,
                   "parent": parent, "name": name, "reason": rs, "attributes": flags_str(attrs, FILE_ATTRS)},
                  {f"USN {rs}": ft2dt(ts)}, "name" if name.lower() == t.name else "path")


@module("vss", "Volume Shadow Copies: earlier versions of the file", needs_windows=True, live_only=True)
def m_vss(ctx):
    t = ctx.target
    if not (IS_WIN and t.is_path):
        return
    if not ctx.admin:
        ctx.r.error("vss", "Administrator required to enumerate shadow copies")
        return
    data = powershell_json(
        "$v=@{}; Get-CimInstance Win32_Volume | % { $v[$_.DeviceID]=$_.DriveLetter };"
        "@(Get-CimInstance Win32_ShadowCopy | % { [pscustomobject]@{Dev=$_.DeviceObject;Drive=$v[$_.VolumeName];"
        "Created=$_.InstallDate.ToUniversalTime().ToString('o');Id=$_.ID} }) | ConvertTo-Json -Compress")
    if not data:
        ctx.r.note("vss", "no shadow copies found")
        return
    for s in (data if isinstance(data, list) else [data]):
        if (s.get("Drive") or "").upper() != t.drive:
            continue
        p = s["Dev"] + t.path[2:]
        if not os.path.exists(p):
            continue
        st = os.stat(p)
        h = None
        if os.path.isfile(p):
            with open(p, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
        same = (h == t.sha256) if h and t.sha256 else None
        ctx.r.add("vss", "Volume Shadow Copy", p,
                  f"file present in shadow copy {s['Created']}" + (" (identical)" if same else " (DIFFERENT content)" if same is False else ""),
                  {"shadow_id": s.get("Id"), "size": st.st_size, "sha256": h, "identical_to_current": same},
                  {"VSS snapshot": parse_dt(s["Created"][:26].replace("T", " ")), "modified (in VSS)": unix2dt(st.st_mtime)},
                  "path")


@module("prefetch", "Prefetch: execution count & last 8 run times; files loaded by other programs")
def m_prefetch(ctx):
    t = ctx.target
    pfdir = ctx.sp("Windows", "Prefetch")
    files = glob.glob(os.path.join(pfdir, "*.pf"))
    if not files:
        ctx.r.note("prefetch", "no prefetch files (disabled, SSD heuristics, or no access)")
        return
    for pf in files:
        base = os.path.basename(pf)
        is_exe_pf = base.lower().rsplit("-", 1)[0] == t.name[:29]
        try:
            with open(pf, "rb") as f:
                raw = f.read()
        except OSError as e:
            ctx.r.error("prefetch", f"{pf}: {e}")
            continue
        if not is_exe_pf and not blob_hits_fast(raw, t):
            continue
        try:
            p = parse_prefetch(raw)
        except Exception as e:
            ctx.r.error("prefetch", f"{base}: {e}")
            continue
        refs = [f for f in p["files"] if t.match(f)]
        exe_match = p["executable"].lower() == t.name[:29]
        if exe_match and t.nodrive:
            exe_paths = [f for f in p["files"] if f.lower().endswith("\\" + t.name)]
            if exe_paths and not any(t.match(f) == "path" for f in exe_paths):
                exe_match = "name"  # same exe name but different folder
        if not (exe_match or refs):
            continue
        st = os.stat(pf)
        times = {f"executed (run #{i + 1} most recent)" if i else "last executed": x for i, x in enumerate(p["last_run_times"])}
        times["prefetch file created (~first run)"] = unix2dt(getattr(st, "st_birthtime", None) or st.st_ctime) if IS_WIN else None
        if exe_match:
            ctx.r.add("prefetch", "Prefetch (execution)", pf,
                      f"{p['executable']} executed {p['run_count']}x, last {iso(p['last_run_times'][0]) if p['last_run_times'] else '?'}",
                      {"run_count": p["run_count"], "hash": p["hash"], "version": p["version"],
                       "volumes": p["volumes"], "loaded_files_count": len(p["files"]),
                       "suspicious_loaded_files": [f for f in p["files"] if re.search(r"\\(temp|downloads|appdata|public|programdata)\\", f, re.I)][:50]},
                      times, "path" if exe_match is True else "name")
        if refs and not exe_match:
            ctx.r.add("prefetch", "Prefetch (file loaded by another program)", pf,
                      f"{p['executable']} touched the file during its first 10s (run count {p['run_count']})",
                      {"program": p["executable"], "referenced_as": refs, "run_count": p["run_count"]},
                      {"loading program last executed": p["last_run_times"][0] if p["last_run_times"] else None},
                      t.match_any(refs)[0])


def blob_hits_fast(raw, t):
    """Quick pre-filter on compressed/uncompressed blobs (compressed .pf needs decompression first)."""
    if raw[:3] == b"MAM":
        try:
            raw = pf_decompress(raw)
        except Exception:
            return False
    n = t.name.encode("utf-16le")
    return n in raw.lower() or n.upper() in raw


@module("pca", "Windows 11 Program Compatibility Assistant launch logs (PcaAppLaunchDic / PcaGeneralDb)")
def m_pca(ctx):
    t = ctx.target
    d = ctx.sp("Windows", "appcompat", "pca")
    f = os.path.join(d, "PcaAppLaunchDic.txt")
    if os.path.isfile(f):
        for line in read_text_any(f).splitlines():
            if "|" in line and t.match(line):
                path, _, ts = line.rpartition("|")
                ctx.r.add("pca", "PcaAppLaunchDic.txt", f, f"launched: {path}", {"path": path},
                          {"PCA last launch (UTC)": parse_dt(ts)}, t.match(path))
    for f in glob.glob(os.path.join(d, "PcaGeneralDb*.txt")):
        for line in read_text_any(f).splitlines():
            if t.match(line):
                p = line.split("|")
                det = dict(zip(["runtime", "run_status", "path", "description", "vendor", "version",
                                "program_id", "exit_code"], p))
                ctx.r.add("pca", os.path.basename(f), f, f"PCA record: {det.get('path')}", det,
                          {"PCA runtime (UTC)": parse_dt(det.get("runtime"))}, t.match(line))


@module("amcache", "Amcache.hve: file inventory with SHA-1, publisher, version, first-seen")
def m_amcache(ctx):
    t = ctx.target
    am = ctx.amcache
    if not am:
        return
    root = am.key("Root")
    if not root:
        return
    for sub in ("InventoryApplicationFile", "InventoryDriverBinary", "InventoryApplicationShortcut", "File"):
        k = root.child(sub)
        if not k:
            continue
        for e in (walk_keys(k, maxdepth=2) if sub == "File" else k.subkeys()):
            vals = {n: d for n, d, _ in e.values()}
            texts = [e.name] + [str(v) for v in vals.values() if isinstance(v, (str, int))]
            m, _ = t.match_any(texts)
            if not m:
                continue
            sha1 = str(vals.get("FileId", vals.get("101", "")))[4:] or None
            det = {k2: v for k2, v in vals.items() if not isinstance(v, (bytes, bytearray))}
            det["sha1"] = sha1
            if sha1 and t.sha1:
                det["sha1_matches_current_file"] = sha1.lower() == t.sha1
            path = vals.get("LowerCaseLongPath") or vals.get("DriverName") or vals.get("ShortcutPath") or e.name
            ctx.r.add("amcache", f"Amcache {sub}", f"Amcache.hve\\Root\\{sub}\\{e.name}",
                      f"{path} (publisher: {vals.get('Publisher') or '-'}, sha1 {sha1 or '-'})", det,
                      {"Amcache key last write (~first seen/installed)": e.lastwrite,
                       "PE link date": parse_dt(str(vals.get("LinkDate") or ""))}, m)


@module("shimcache", "AppCompatCache (ShimCache): file presence + last-modified time")
def m_shimcache(ctx):
    t = ctx.target
    sysreg, ccs = ctx.system
    if not sysreg:
        return
    k = sysreg.key(rf"{ccs}\Control\Session Manager\AppCompatCache")
    data = k.value("AppCompatCache") if k else None
    data = to_bytes(data)
    if not data:
        return
    entries = parse_shimcache(data)
    for e in entries:
        m = t.match(e["path"])
        if m:
            ctx.r.add("shimcache", "AppCompatCache", f"SYSTEM\\{ccs}\\...\\AppCompatCache",
                      f"#{e['position']} of {len(entries)}: {e['path']}",
                      {**e, "note": "Presence proves the file existed; on Win10/11 it does NOT prove execution. "
                                    "Lower position = more recently cached."},
                      {"file last modified (ShimCache)": e["last_modified"], "SYSTEM key last write": k.lastwrite}, m)


@module("bam", "Background Activity Moderator (BAM/DAM): last execution time per user")
def m_bam(ctx):
    t = ctx.target
    sysreg, ccs = ctx.system
    if not sysreg:
        return
    for svc in ("bam", "dam"):
        for base in (rf"{ccs}\Services\{svc}\State\UserSettings", rf"{ccs}\Services\{svc}\UserSettings"):
            k = sysreg.key(base)
            if not k:
                continue
            for uk in k.subkeys():
                for name, data, _ in uk.values():
                    if name in ("Version", "SequenceNumber"):
                        continue
                    m = t.match(name)
                    if m:
                        b = to_bytes(data) or b""
                        ctx.r.add("bam", svc.upper(), f"SYSTEM\\{base}\\{uk.name}",
                                  f"{ctx.device_to_dos(name)} run by {uk.name}",
                                  {"user_sid": uk.name, "value": name, "dos_path": ctx.device_to_dos(name)},
                                  {f"{svc.upper()} last execution": ft2dt(u64(b, 0)) if len(b) >= 8 else None}, m)


@module("userassist", "UserAssist: GUI program launches, run count, focus time (per user)")
def m_userassist(ctx):
    t = ctx.target
    for u in ctx.users:
        if not u.ntuser:
            continue
        k = u.ntuser.key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
        for gk in (k.subkeys() if k else []):
            ck = gk.child("Count")
            for name, data, _ in (ck.values() if ck else []):
                dec = expand_known_guids(rot13(name))
                m = t.match(dec)
                if not m:
                    continue
                b = to_bytes(data) or b""
                det = {"user": u.label(), "entry": dec, "guid": gk.name}
                last = None
                if len(b) >= 72:
                    det.update(run_count=u32(b, 4), focus_count=u32(b, 8), focus_time_ms=u32(b, 12))
                    last = ft2dt(u64(b, 60))
                ctx.r.add("userassist", "UserAssist", f"{u.ntuser.label}\\...\\UserAssist\\{gk.name}",
                          f"{dec} (runs: {det.get('run_count', '?')})", det, {"UserAssist last executed": last}, m)


MRU_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage",
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    r"Software\Microsoft\Windows\CurrentVersion\Applets",
    r"Software\Microsoft\Terminal Server Client",
    r"Software\Microsoft\Office",
    r"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    r"Software\WinRAR\ArcHistory", r"Software\7-Zip", r"Software\Microsoft\Notepad",
]
USRCLASS_KEYS = [r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache"]


@module("mru", "Registry MRUs: RecentDocs, Open/Save dialogs, Office MRU, RunMRU, MuiCache, PCA store, WordWheel")
def m_mru(ctx):
    t = ctx.target
    for u in ctx.users:
        for hive, keys in ((u.ntuser, MRU_KEYS), (u.usrclass, USRCLASS_KEYS)):
            if not hive:
                continue
            for kp in keys:
                k = hive.key(kp)
                if not k:
                    continue
                for key in walk_keys(k, maxdepth=6):
                    order = None
                    for name, data, typ in key.values():
                        cands = [name] + value_strings(data)
                        if typ == 3 and isinstance(data, (bytes, bytearray)) and data[:2] != b"\x00\x00":
                            # PIDL values (OpenSavePidlMRU / LastVisited): also rebuild path
                            try:
                                cands.append(parse_idlist(bytes(data)))
                            except Exception:
                                pass
                        m, s = t.match_any(cands)
                        if not m:
                            continue
                        det = {"user": u.label(), "key": key.path, "value": name, "matched_text": s}
                        times = {"MRU key last write": key.lastwrite}
                        if order is None:
                            mrul = key.value("MRUListEx")
                            mb = to_bytes(mrul)
                            order = [u32(mb, i) for i in range(0, len(mb) - 4, 4)] if mb else []
                        if name.isdigit() and order:
                            pos = order.index(int(name)) if int(name) in order else None
                            det["mru_position"] = pos
                            if pos == 0:
                                times["most recent item -> key last write = last opened"] = key.lastwrite
                        mo = re.search(r"\[T([0-9A-F]{16})\]", str(data))
                        if mo:
                            times["Office MRU last opened"] = ft2dt(int(mo.group(1), 16))
                        if "MuiCache" in key.path:
                            det["meaning"] = "program was executed (friendly name cached)"
                        if "Compatibility Assistant" in key.path:
                            det["meaning"] = "PCA: program was executed"
                        if "Layers" in key.path:
                            det["meaning"] = "compatibility mode / RUNASADMIN flag set"
                        if "WordWheelQuery" in key.path:
                            det["meaning"] = "user typed this in Explorer search"
                        base = kp.split("\\")[-1]
                        area = base if key.path.rstrip("\\").endswith(base) else f"{base} ({key.name})"
                        ctx.r.add("mru", area, f"{hive.label}\\{key.path}", f"{s[:200]}", det, times, m)


@module("shellbags", "ShellBags: folders browsed in Explorer (parent folder of the target)")
def m_shellbags(ctx):
    t = ctx.target
    want = {x for x in ((t.path or "").lower() if t.is_dir else (t.parent or ""),) if x}

    def walk(key, parts, depth, hive, user):
        for name, data, _ in key.values():
            if not name.isdigit():
                continue
            b = to_bytes(data)
            if not b:
                continue
            comp = parse_shell_item(b)
            p = parts + [comp]
            path = join_shell_path(p)
            sub = key.child(name)
            pl = path.lower()
            m = None
            if want and (pl in want or pl.rstrip("\\") in want):
                m = "path"
            elif t.match(comp or ""):
                m = "name"
            if m:
                ctx.r.add("shellbags", "ShellBags", f"{hive.label}\\{key.path}\\{name}",
                          f"Explorer browsed: {path}", {"user": user.label(), "path": path},
                          {"BagMRU key last write (folder interacted)": sub.lastwrite if sub else key.lastwrite}, m)
            if sub and depth < 40:
                walk(sub, p, depth + 1, hive, user)

    for u in ctx.users:
        for hive, kp in ((u.usrclass, r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"),
                         (u.ntuser, r"Software\Microsoft\Windows\Shell\BagMRU")):
            if hive:
                k = hive.key(kp)
                if k:
                    walk(k, [], 0, hive, u)


def _lnk_finding(ctx, src, info, artifact, extra_times=None, extra=None):
    t = ctx.target
    m, s = t.match_any([info.get("target"), info.get("target_path"), info.get("idlist_path"),
                        info.get("env_target"), info.get("relative_path"), info.get("arguments"),
                        info.get("working_dir"), info.get("name")])
    if not m:
        return False
    det = dict(info)
    det.update(extra or {})
    times = {"target created (per LNK)": info.get("target_created"),
             "target modified (per LNK)": info.get("target_modified"),
             "target accessed (per LNK)": info.get("target_accessed")}
    times.update(extra_times or {})
    if info.get("target_size") and t.exists and not t.is_dir:
        det["size_matches_current"] = info["target_size"] == os.path.getsize(t.local) & 0xFFFFFFFF
    ctx.r.add("lnk" if artifact.startswith("LNK") else "jumplists", artifact, src,
              f"{info.get('target')} [{info.get('drive_type', '')} vol {info.get('volume_serial', '?')}, host {info.get('machine_id', '?')}]",
              det, times, m)
    return True


@module("lnk", "LNK shortcut files: Recent, Office Recent, Desktop, Start Menu, Startup")
def m_lnk(ctx):
    pats = [r"AppData\Roaming\Microsoft\Windows\Recent\*.lnk",
            r"AppData\Roaming\Microsoft\Office\Recent\*.lnk",
            r"Desktop\*.lnk", r"OneDrive*\Desktop\*.lnk",
            r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\**\*.lnk",
            r"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\**\*.lnk"]
    files = []
    for _, d in ctx.user_dirs():
        for p in pats:
            files += glob.glob(os.path.join(d, *p.split("\\")), recursive=True)
    files += glob.glob(ctx.sp("ProgramData", "Microsoft", "Windows", "Start Menu", "**", "*.lnk"), recursive=True)
    for f in files:
        try:
            with open(f, "rb") as fh:
                info = parse_lnk(fh.read())
        except Exception:
            continue
        st = os.stat(f)
        is_recent = "\\recent\\" in f.lower().replace("/", "\\")
        created = unix2dt(getattr(st, "st_birthtime", None) or st.st_ctime) if IS_WIN else None
        _lnk_finding(ctx, f, info, "LNK (Recent item)" if is_recent else "LNK shortcut",
                     {("LNK created (~first opened)" if is_recent else "LNK created"): created,
                      ("LNK modified (~last opened)" if is_recent else "LNK modified"): unix2dt(st.st_mtime)})


@module("jumplists", "Jump Lists: AutomaticDestinations (DestList) & CustomDestinations")
def m_jumplists(ctx):
    for _, d in ctx.user_dirs():
        base = os.path.join(d, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
        for f in glob.glob(os.path.join(base, "AutomaticDestinations", "*.automaticDestinations-ms")):
            appid = os.path.basename(f).split(".")[0]
            app = JUMPLIST_APPIDS.get(appid, appid)
            if not olefile:
                ctx.r.error("jumplists", "olefile not installed - AutomaticDestinations skipped (pip install olefile)")
                return
            try:
                ole = olefile.OleFileIO(f)
            except Exception:
                continue
            dest = {}
            if ole.exists("DestList"):
                try:
                    for e in parse_destlist(ole.openstream("DestList").read()):
                        dest[e["entry_id"]] = e
                except Exception:
                    pass
            for s in ole.listdir():
                sname = s[0]
                if sname == "DestList":
                    continue
                try:
                    info = parse_lnk(ole.openstream(sname).read())
                except Exception:
                    continue
                try:
                    de = dest.get(int(sname, 16), {})
                except ValueError:
                    de = {}
                if not info.get("target") and de.get("path"):
                    info["target"] = de["path"]
                _lnk_finding(ctx, f"{f}::{sname}", info, f"Jump List ({app})",
                             {"Jump List entry last accessed": de.get("last_access")},
                             {"app_id": appid, "application": app, "access_count": de.get("access_count"),
                              "pinned": de.get("pinned"), "hostname": de.get("hostname")})
            # DestList entries whose LNK stream is missing
            ole.close()
        for f in glob.glob(os.path.join(base, "CustomDestinations", "*.customDestinations-ms")):
            appid = os.path.basename(f).split(".")[0]
            try:
                with open(f, "rb") as fh:
                    b = fh.read()
            except OSError:
                continue
            for m in re.finditer(re.escape(b"\x4c\x00\x00\x00\x01\x14\x02\x00"), b):
                try:
                    info = parse_lnk(b[m.start():])
                except Exception:
                    continue
                _lnk_finding(ctx, f"{f}@{m.start()}", info,
                             f"Jump List custom ({JUMPLIST_APPIDS.get(appid, appid)})",
                             {"customDestinations modified": unix2dt(os.stat(f).st_mtime)}, {"app_id": appid})


@module("recyclebin", "Recycle Bin $I files: original path, size, deletion time")
def m_recyclebin(ctx):
    t = ctx.target
    for f in glob.glob(ctx.sp("$Recycle.Bin", "*", "$I*")):
        try:
            with open(f, "rb") as fh:
                info = parse_recycle_i(fh.read())
        except Exception:
            continue
        m = t.match(info["original_path"])
        if not m:
            continue
        rfile = os.path.join(os.path.dirname(f), "$R" + os.path.basename(f)[2:])
        info["sid"] = os.path.basename(os.path.dirname(f))
        info["recoverable_copy"] = rfile if os.path.exists(rfile) else None
        if info["recoverable_copy"] and os.path.isfile(rfile):
            with open(rfile, "rb") as fh:
                info["recoverable_sha256"] = hashlib.sha256(fh.read()).hexdigest()
        ctx.r.add("recyclebin", "Recycle Bin", f, f"deleted {info['original_path']} ({info['size']} bytes)",
                  info, {"deleted to Recycle Bin": info["deleted"]}, m)


def _sqlite(ctx, path):
    c = ctx.copy(path)
    if not c:
        return None
    try:
        con = sqlite3.connect(c)
        con.row_factory = sqlite3.Row
        con.execute("select 1 from sqlite_master limit 1")
        return con
    except Exception as e:
        ctx.r.error("sqlite", f"{path}: {e}")
        return None


def _decode_prop(v, name=""):
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        if len(b) == 8 and ("date" in name.lower() or "time" in name.lower()):
            return ft2dt(u64(b, 0))
        if len(b) >= 2 and len(b) % 2 == 0 and b[1::2].count(0) > len(b) // 4:
            return b.decode("utf-16le", "ignore").rstrip("\x00")
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.hex() if len(b) <= 64 else b[:64].hex() + "…"
    return v


@module("search", "Windows Search index (Win11 Windows.db / Windows-gather.db)")
def m_search(ctx):
    t = ctx.target
    d = ctx.sp("ProgramData", "Microsoft", "Search", "Data", "Applications", "Windows")
    db = os.path.join(d, "Windows.db")
    if not os.path.isfile(db):
        if os.path.isfile(os.path.join(d, "Windows.edb")):
            ctx.r.note("search", "only ESE Windows.edb present (Win10-style) - not parsed; use SIDR / libesedb")
        return
    con = _sqlite(ctx, db)
    if not con:
        return
    try:
        cols = {r[0]: r[1] for r in con.execute("select Id, UniqueKey from SystemIndex_1_PropertyStore_Metadata")}
    except Exception as e:
        ctx.r.error("search", f"unexpected Windows.db schema: {e}")
        return
    name_cols = [i for i, k in cols.items() if any(x in k for x in ("ItemPathDisplay", "ItemNameDisplay", "FileName", "ItemUrl"))]
    hits = set()
    if name_cols:
        q = f"select WorkId, Value from SystemIndex_1_PropertyStore where ColumnId in ({','.join(map(str, name_cols))})"
        for wid, val in con.execute(q):
            if t.match(_decode_prop(val)):
                hits.add(wid)
    for wid in sorted(hits)[:200]:
        props = {}
        for cid, val in con.execute("select ColumnId, Value from SystemIndex_1_PropertyStore where WorkId=?", (wid,)):
            n = re.sub(r"^\d+-", "", cols.get(cid, str(cid))).replace("_", ".", 1)
            props[n] = _decode_prop(val, n)
        path = props.get("System.ItemPathDisplay") or props.get("System.ItemUrl") or props.get("System.ItemNameDisplay")
        times = {f"Search index {k}": v for k, v in props.items() if isinstance(v, dt.datetime)}
        ctx.r.add("search", "Windows Search (Windows.db)", f"{db} WorkId {wid}", f"indexed: {path}",
                  {k: v for k, v in props.items() if not isinstance(v, dt.datetime)}, times, t.match(str(path)) or "name")


@module("timeline", "Windows Timeline ActivitiesCache.db (if present)")
def m_timeline(ctx):
    t = ctx.target
    for _, d in ctx.user_dirs():
        for db in glob.glob(os.path.join(d, "AppData", "Local", "ConnectedDevicesPlatform", "*", "ActivitiesCache.db")):
            con = _sqlite(ctx, db)
            if not con:
                continue
            try:
                rows = con.execute("select * from Activity").fetchall()
            except Exception:
                continue
            for r in rows:
                r = dict(r)
                payload = _decode_prop(r.get("Payload"))
                appid = _decode_prop(r.get("AppId"))
                m = t.match(f"{appid} {payload}")
                if not m:
                    continue
                ctx.r.add("timeline", "ActivitiesCache", db, f"activity type {r.get('ActivityType')}: {str(payload)[:150]}",
                          {"app_id": appid, "payload": payload, "activity_type": r.get("ActivityType"),
                           "platform_device_id": r.get("PlatformDeviceId")},
                          {"activity start": unix2dt(r.get("StartTime")), "activity end": unix2dt(r.get("EndTime")),
                           "last modified": unix2dt(r.get("LastModifiedTime"))}, m)


CHROMIUM = [r"AppData\Local\Google\Chrome\User Data", r"AppData\Local\Microsoft\Edge\User Data",
            r"AppData\Local\BraveSoftware\Brave-Browser\User Data", r"AppData\Local\Vivaldi\User Data",
            r"AppData\Local\Chromium\User Data", r"AppData\Roaming\Opera Software"]


@module("browsers", "Browser downloads & file:// history (Chrome/Edge/Brave/Vivaldi/Opera/Firefox)")
def m_browsers(ctx):
    t = ctx.target
    for user, d in ctx.user_dirs():
        hists = []
        for b in CHROMIUM:
            base = os.path.join(d, *b.split("\\"))
            hists += glob.glob(os.path.join(base, "*", "History")) + glob.glob(os.path.join(base, "History"))
        for h in hists:
            con = _sqlite(ctx, h)
            if not con:
                continue
            browser = h.split(os.sep)[-4] if "User Data" in h else "Opera"
            try:
                for r in con.execute("select * from downloads"):
                    r = dict(r)
                    m, s = t.match_any([r.get("target_path"), r.get("current_path")])
                    if not m:
                        continue
                    chain = [x[0] for x in con.execute(
                        "select url from downloads_url_chains where id=? order by chain_index", (r["id"],))]
                    det = {k: r.get(k) for k in ("target_path", "current_path", "received_bytes", "total_bytes",
                                                   "state", "danger_type", "interrupt_reason", "opened", "referrer",
                                                   "tab_url", "tab_referrer_url", "mime_type", "original_mime_type",
                                                   "site_url", "by_ext_name")}
                    det["url_chain"] = chain
                    det["user"] = user
                    ctx.r.add("browsers", f"{browser} download", h, f"downloaded from {chain[-1] if chain else r.get('tab_url')}",
                              det, {"download started": webkit2dt(r.get("start_time")),
                                    "download finished": webkit2dt(r.get("end_time")),
                                    "last opened via browser": webkit2dt(r.get("last_access_time"))}, m)
            except Exception as e:
                ctx.r.error("browsers", f"{h}: {e}")
            try:
                for r in con.execute("select url, title, visit_count, last_visit_time from urls where url like 'file:%'"):
                    m = t.match(r["url"])
                    if m:
                        ctx.r.add("browsers", f"{browser} file:// history", h, f"opened in browser: {urllib.parse.unquote(r['url'])}",
                                  {"url": r["url"], "title": r["title"], "visits": r["visit_count"], "user": user},
                                  {"last visited in browser": webkit2dt(r["last_visit_time"])}, m)
            except Exception:
                pass
        for pl in glob.glob(os.path.join(d, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "*", "places.sqlite")):
            con = _sqlite(ctx, pl)
            if not con:
                continue
            try:
                q = ("select p.url as src, a.content as dest, a.dateAdded as added from moz_annos a "
                     "join moz_places p on p.id=a.place_id join moz_anno_attributes n on n.id=a.anno_attribute_id "
                     "where n.name='downloads/destinationFileURI'")
                for r in con.execute(q):
                    m = t.match(r["dest"])
                    if m:
                        ctx.r.add("browsers", "Firefox download", pl, f"downloaded from {r['src']}",
                                  {"source_url": r["src"], "destination": urllib.parse.unquote(r["dest"]), "user": user},
                                  {"download added": unix2dt(r["added"], 1_000_000)}, m)
                for r in con.execute("select url, title, visit_count, last_visit_date from moz_places where url like 'file:%'"):
                    m = t.match(r["url"])
                    if m:
                        ctx.r.add("browsers", "Firefox file:// history", pl, urllib.parse.unquote(r["url"]),
                                  {"url": r["url"], "visits": r["visit_count"], "user": user},
                                  {"last visited in browser": unix2dt(r["last_visit_date"], 1_000_000)}, m)
            except Exception as e:
                ctx.r.error("browsers", f"{pl}: {e}")


EVENT_SOURCES = [
    ("Security", [4688, 4663, 4656, 4660, 4698, 4699, 4702, 5145, 4697], "Security"),
    ("Microsoft-Windows-Sysmon/Operational", [1, 2, 3, 6, 7, 11, 15, 22, 23, 25, 26, 27, 29], "Sysmon"),
    ("Microsoft-Windows-Windows Defender/Operational", [1006, 1015, 1116, 1117, 1118, 1119, 1121, 1122, 5007], "Defender"),
    ("Microsoft-Windows-PowerShell/Operational", [4103, 4104], "PowerShell"),
    ("Windows PowerShell", [400, 600, 800], "PowerShell (classic)"),
    ("System", [7045, 7036], "System"),
    ("Microsoft-Windows-TaskScheduler/Operational", [106, 129, 140, 141, 200, 201], "TaskScheduler"),
    ("Microsoft-Windows-AppLocker/EXE and DLL", [8002, 8003, 8004], "AppLocker"),
    ("Microsoft-Windows-AppLocker/MSI and Script", [8005, 8006, 8007], "AppLocker"),
    ("Microsoft-Windows-Shell-Core/Operational", [9707, 9708], "Shell-Core (Run keys)"),
    ("Microsoft-Windows-SmartScreen/Debug", [1000], "SmartScreen"),
    ("Microsoft-Windows-CodeIntegrity/Operational", [3033, 3034, 3076, 3077, 3089], "CodeIntegrity"),
    ("Microsoft-Windows-Bits-Client/Operational", [3, 59, 60], "BITS"),
    ("Microsoft-Windows-WMI-Activity/Operational", [5857, 5860, 5861], "WMI"),
    ("Application", [1000, 1001, 1002, 1033, 1034, 11707, 11724], "Application (crash/MSI)"),
]
EVENT_FIELDS = ["Image", "TargetFilename", "CommandLine", "NewProcessName", "ProcessName", "ObjectName",
                "Threat Name", "Path", "Process Name", "ImageLoaded", "ParentImage", "ParentCommandLine",
                "User", "SubjectUserName", "TaskName", "ServiceName", "ImagePath", "Hashes", "QueryName",
                "DestinationIp", "Action Name", "Detection User", "FilePath", "FullFilePath", "url", "Url",
                "ScriptBlockText", "Payload", "AccessMask", "ShareName", "RelativeTargetName"]
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_event(x):
    e = ET.fromstring(x)
    sysn = e.find(NS + "System")
    eid = int(sysn.findtext(NS + "EventID"))
    tc = sysn.find(NS + "TimeCreated").get("SystemTime", "")
    m = re.match(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d+))?", tc)
    ts = None
    if m:
        ts = dt.datetime.strptime(f"{m.group(1)} {m.group(2)}.{(m.group(3) or '0')[:6].ljust(6, '0')}",
                                  "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)
    data = {}
    for i, d in enumerate(e.iter(NS + "Data")):
        data[d.get("Name") or f"Data{i}"] = d.text or ""
    ud = e.find(NS + "UserData")
    if ud is not None:
        for el in ud.iter():
            if len(el) == 0 and el.text and el.text.strip():
                data[el.tag.split("}")[-1]] = el.text.strip()
    return eid, ts, sysn.findtext(NS + "Computer"), sysn.findtext(NS + "EventRecordID"), data


def _events(ctx, channel, ids):
    q = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"
    n = str(ctx.args.max_events)
    if ctx.live:
        src, extra = channel, []
    else:
        src = ctx.sp("Windows", "System32", "winevt", "Logs", channel.replace("/", "%4") + ".evtx")
        if not os.path.isfile(src):
            return None
        extra = ["/lf:true"]
    if IS_WIN:
        rc, out, err = run(["wevtutil.exe", "qe", src, *extra, f"/q:{q}", f"/c:{n}", "/rd:true", "/f:xml"], timeout=900)
        if rc != 0:
            return None
        return re.findall(r"<Event .*?</Event>", decode_console(out), re.S)
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        ctx.r.error("eventlogs", "offline .evtx on non-Windows needs `pip install python-evtx`")
        return []
    out, idset = [], set(map(str, ids))
    with Evtx(src) as log:
        for rec in log.records():
            try:
                xml = rec.xml()
            except Exception:
                continue
            mm = re.search(r"<EventID[^>]*>(\d+)<", xml)
            if mm and mm.group(1) in idset:
                out.append(xml)
    return out[-ctx.args.max_events:][::-1]


@module("eventlogs", "Event logs: Sysmon, Security 4688/4663, Defender, PowerShell, services, tasks, AppLocker...")
def m_eventlogs(ctx):
    t = ctx.target
    if ctx.live and not ctx.admin:
        ctx.r.note("eventlogs", "not Administrator: Security / some channels will be unreadable")
    for channel, ids, label in EVENT_SOURCES:
        evs = _events(ctx, channel, ids)
        if not evs:
            continue
        hits = 0
        for x in evs:
            if not t.match(x):
                continue
            try:
                eid, ts, comp, rid, data = _parse_event(x)
            except Exception:
                continue
            m, s = t.match_any(list(data.values()))
            if not m:
                continue
            key = {k: data[k] for k in EVENT_FIELDS if data.get(k)}
            summ = "; ".join(f"{k}={str(v)[:120]}" for k, v in list(key.items())[:3])
            if "ScriptBlockText" in data:
                data["ScriptBlockText"] = data["ScriptBlockText"][:4000]
            ctx.r.add("eventlogs", f"{label} {eid}", f"{channel} #{rid}", summ or s[:200],
                      {"event_id": eid, "computer": comp, "record_id": rid, **data},
                      {f"{label} event {eid}": ts}, m)
            hits += 1
        ctx.r.note("eventlogs", f"{channel}: {len(evs)} candidate events scanned, {hits} matched")


@module("defender", "Microsoft Defender MPLog / detection history")
def m_defender(ctx):
    t = ctx.target
    base = ctx.sp("ProgramData", "Microsoft", "Windows Defender")
    for f in glob.glob(os.path.join(base, "Support", "MPLog-*.log")):
        try:
            txt = read_text_any(f)
        except OSError as e:
            ctx.r.error("defender", f"{f}: {e}")
            continue
        for line in txt.splitlines():
            if t.match(line):
                mt = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)", line)
                ts = parse_dt(mt.group(1).replace("T", " ")[:26]) if mt else None
                ctx.r.add("defender", "MPLog", f, line.strip()[:300], {"line": line.strip()},
                          {"Defender MPLog entry": ts}, t.match(line))
    for f in glob.glob(os.path.join(base, "Scans", "History", "Service", "DetectionHistory", "**", "*"), recursive=True):
        if not os.path.isfile(f):
            continue
        try:
            with open(f, "rb") as fh:
                hits = blob_hits(fh.read(), t)
        except OSError:
            continue
        if hits:
            ctx.r.add("defender", "Defender DetectionHistory", f, f"detection record mentions {hits[0][:150]}",
                      {"strings": hits}, {"detection file modified": unix2dt(os.stat(f).st_mtime)}, t.match_any(hits)[0])
    q = os.path.join(base, "Quarantine", "Entries")
    if os.path.isdir(q) and os.listdir(q):
        ctx.r.note("defender", f"{len(os.listdir(q))} quarantine entries present (RC4-encrypted, not decoded)")


@module("persistence", "Persistence: Run keys, services, scheduled tasks, Startup folders, IFEO, Winlogon, WMI")
def m_persistence(ctx):
    t = ctx.target
    sw = ctx.software
    sysreg, ccs = ctx.system
    keys = []
    if sw:
        for kp in (r"Microsoft\Windows\CurrentVersion\Run", r"Microsoft\Windows\CurrentVersion\RunOnce",
                   r"Microsoft\Windows\CurrentVersion\RunOnceEx", r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                   r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run", r"WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                   r"Microsoft\Windows NT\CurrentVersion\Winlogon", r"Microsoft\Windows NT\CurrentVersion\Windows",
                   r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                   r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                   r"Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad",
                   r"Microsoft\Active Setup\Installed Components", r"Microsoft\Windows\CurrentVersion\App Paths",
                   r"Microsoft\Windows\CurrentVersion\Uninstall", r"Classes\CLSID"):
            keys.append((sw, kp, 3 if "CLSID" in kp else 2))
    if sysreg:
        keys += [(sysreg, rf"{ccs}\Services", 2), (sysreg, rf"{ccs}\Control\Session Manager", 1),
                 (sysreg, rf"{ccs}\Control\Print\Monitors", 2), (sysreg, rf"{ccs}\Control\Lsa", 1)]
    for u in ctx.users:
        if u.ntuser:
            for kp in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                       r"Software\Microsoft\Windows NT\CurrentVersion\Windows", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                       r"Environment", r"Software\Classes"):
                keys.append((u.ntuser, kp, 3 if kp.endswith("Classes") else 1))
    for hive, kp, depth in keys:
        k = hive.key(kp)
        if not k:
            continue
        for key in walk_keys(k, maxdepth=depth):
            for name, data, _ in key.values():
                m, s = t.match_any([str(x) for x in value_strings(data) if isinstance(data, (str, list))])
                if m:
                    ctx.r.add("persistence", "Registry autostart/config", f"{hive.label}\\{key.path}",
                              f"{name or '(default)'} = {s[:200]}", {"key": key.path, "value": name, "data": s},
                              {"key last write": key.lastwrite}, m)
    for f in glob.glob(ctx.sp("Windows", "System32", "Tasks", "**", "*"), recursive=True):
        if not os.path.isfile(f):
            continue
        try:
            txt = read_text_any(f, 1 << 20)
        except OSError:
            continue
        if t.match(txt):
            g = lambda tag: (re.search(rf"<{tag}>(.*?)</{tag}>", txt, re.S) or [None, None])[1]
            ctx.r.add("persistence", "Scheduled task", f,
                      f"task {g('URI') or os.path.basename(f)} runs {g('Command')} {g('Arguments') or ''}",
                      {"uri": g("URI"), "command": g("Command"), "arguments": g("Arguments"), "author": g("Author"),
                       "registration_date": g("Date"), "user_id": g("UserId"), "run_level": g("RunLevel")},
                      {"task registration date": parse_dt((g("Date") or "")[:19].replace("T", " ")),
                       "task file modified": unix2dt(os.stat(f).st_mtime)}, t.match(txt))
    startups = [ctx.sp("ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "StartUp")]
    startups += [os.path.join(d, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
                 for _, d in ctx.user_dirs()]
    for sd in startups:
        for f in glob.glob(os.path.join(sd, "*")):
            tgt = None
            if f.lower().endswith(".lnk"):
                try:
                    with open(f, "rb") as fh:
                        tgt = parse_lnk(fh.read()).get("target")
                except Exception:
                    pass
            m = t.match(f) or t.match(tgt or "")
            if m:
                ctx.r.add("persistence", "Startup folder", f, f"startup item -> {tgt or f}", {"lnk_target": tgt},
                          {"startup item created": unix2dt(os.stat(f).st_ctime) if IS_WIN else None}, m)
    wmi = ctx.sp("Windows", "System32", "wbem", "Repository", "OBJECTS.DATA")
    if os.path.isfile(wmi):
        c = ctx.copy(wmi, companions=())
        if c:
            with open(c, "rb") as fh:
                hits = blob_hits(fh.read(), t)
            if hits:
                ctx.r.add("persistence", "WMI repository", wmi, f"WMI repository references the file ({len(hits)} hits)",
                          {"strings": hits, "note": "check for __EventConsumer / CommandLineEventConsumer"}, match=t.match_any(hits)[0])


@module("notepad", "Windows 11 Notepad TabState (opened/unsaved files)")
def m_notepad(ctx):
    t = ctx.target
    for _, d in ctx.user_dirs():
        for f in glob.glob(os.path.join(d, "AppData", "Local", "Packages", "Microsoft.WindowsNotepad_*",
                                        "LocalState", "*State", "*.bin")):
            try:
                with open(f, "rb") as fh:
                    hits = blob_hits(fh.read(), t)
            except OSError:
                continue
            if hits:
                ctx.r.add("notepad", "Notepad TabState", f, f"Notepad tab references {hits[0][:150]}", {"strings": hits},
                          {"TabState modified": unix2dt(os.stat(f).st_mtime)}, t.match_any(hits)[0])


@module("deepreg", "Exhaustive registry string search (all hives) - slow", default=False)
def m_deepreg(ctx):
    t = ctx.target
    hives = [ctx.software, ctx.system[0]] + [h for u in ctx.users for h in (u.ntuser, u.usrclass)]
    seen = 0
    for hive in [h for h in hives if h]:
        root = hive.key("")
        if not root:
            continue
        for key in walk_keys(root, maxdepth=40):
            seen += 1
            if t.match(key.name):
                ctx.r.add("deepreg", "Registry key name", f"{hive.label}\\{key.path}", key.path, {},
                          {"key last write": key.lastwrite}, t.match(key.name))
            for name, data, _ in key.values():
                m, s = t.match_any([name] + value_strings(data))
                if m:
                    ctx.r.add("deepreg", "Registry value", f"{hive.label}\\{key.path}", f"{name}: {s[:200]}",
                              {"value": name, "matched": s}, {"key last write": key.lastwrite}, m)
    ctx.r.note("deepreg", f"walked {seen} keys")


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def write_outputs(ctx, outdir, elapsed):
    r, t = ctx.r, ctx.target
    os.makedirs(outdir, exist_ok=True)
    meta = {"tool": f"win11_file_forensics {__version__}", "generated": iso(dt.datetime.now(UTC)),
            "mode": "live" if ctx.live else f"offline ({ctx.root})", "administrator": ctx.admin,
            "host": os.environ.get("COMPUTERNAME"), "elapsed_s": round(elapsed, 1),
            "target": {"spec": t.spec, "path": t.path, "name": t.name, "exists": t.exists,
                       "md5": t.md5, "sha1": t.sha1, "sha256": t.sha256}}
    tl = r.timeline()
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "findings": r.findings, "timeline": tl, "notes": r.notes, "errors": r.errors},
                  f, indent=2, ensure_ascii=False, default=str)
    with open(os.path.join(outdir, "timeline.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp", "event", "module", "artifact", "summary", "source", "match"])
        w.writeheader()
        w.writerows(tl)
    e = html.escape
    by_mod = {}
    for fi in r.findings:
        by_mod.setdefault(fi["module"], []).append(fi)
    secs = []
    for mod, items in by_mod.items():
        rows = "".join(
            f"<tr><td>{e(fi['artifact'])}</td><td><span class='m m-{e(str(fi['match']))}'>{e(str(fi['match']))}</span></td>"
            f"<td>{e(fi['summary'])}<details><summary>details</summary><pre>{e(json.dumps(fi['details'], indent=1, ensure_ascii=False, default=str))}</pre>"
            f"<div class='src'>{e(fi['source'])}</div></details></td>"
            f"<td class='ts'>{'<br>'.join(f'{e(k)}: <b>{e(v)}</b>' for k, v in fi['times'].items())}</td></tr>"
            for fi in items)
        secs.append(f"<h2 id='{e(mod)}'>{e(mod)} <small>({len(items)})</small></h2><table><tr><th>Artifact</th>"
                    f"<th>Match</th><th>Summary</th><th>Times (UTC)</th></tr>{rows}</table>")
    tlrows = "".join(f"<tr><td class='ts'>{e(x['timestamp'])}</td><td>{e(x['event'])}</td><td>{e(x['module'])}</td>"
                     f"<td>{e(x['summary'][:200])}</td></tr>" for x in tl)
    nav = " · ".join(f"<a href='#{e(m)}'>{e(m)} ({len(v)})</a>" for m, v in by_mod.items())
    notes = "".join(f"<li><b>{e(n['module'])}</b>: {e(n['note'])}</li>" for n in r.notes)
    errs = "".join(f"<li><b>{e(n['module'])}</b>: {e(n['error'])}</li>" for n in r.errors)
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>File forensics - {e(t.name)}</title><style>
:root{{--bg:#fff;--fg:#1d1d1f;--mut:#6b6b70;--line:#e3e3e8;--card:#f6f6f8;--acc:#0b63ce}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141416;--fg:#e8e8ea;--mut:#9a9aa0;--line:#2c2c30;--card:#1d1d20;--acc:#5aa2ff}}}}
body{{font:14px/1.45 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1400px}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}}
small,.src{{color:var(--mut)}} a{{color:var(--acc)}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}} th{{color:var(--mut);font-weight:600}}
.ts{{font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:nowrap}} pre{{background:var(--card);padding:8px;overflow:auto;max-height:360px;font-size:12px}}
.card{{background:var(--card);padding:12px 16px;border-radius:8px;margin:12px 0}} .m{{font-size:11px;padding:1px 6px;border-radius:9px;border:1px solid var(--line)}}
.m-path{{background:#1f8f4e;color:#fff}} .m-hash{{background:#7b3fe4;color:#fff}} .m-name{{background:#c98a00;color:#fff}}
@media (max-width:700px){{body{{padding:16px}} td,th{{display:block}} .ts{{white-space:normal}}}}
</style></head><body>
<h1>File forensics report: {e(t.path or t.name)}</h1>
<div class="card"><pre>{e(json.dumps(meta, indent=1, default=str))}</pre>
<b>{len(r.findings)}</b> findings, <b>{len(tl)}</b> timeline events. Match: <span class='m m-path'>path</span> full path,
<span class='m m-hash'>hash</span> SHA-1, <span class='m m-name'>name</span> file name only (could be a different file with the same name).</div>
<div>{nav} · <a href="#timeline">timeline</a></div>
{''.join(secs)}
<h2 id="timeline">Super-timeline (UTC)</h2><table><tr><th>Time</th><th>Event</th><th>Module</th><th>Summary</th></tr>{tlrows}</table>
<h2>Notes</h2><ul>{notes}</ul><h2>Errors / skipped</h2><ul>{errs}</ul>
</body></html>"""
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(doc)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect Windows 11 forensic artifacts referencing a file.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Examples")[1])
    ap.add_argument("target", nargs="?", help="full path (best) or file name to investigate")
    ap.add_argument("--root", help="offline mode: root of a mounted image / triage collection (e.g. E:\\)")
    ap.add_argument("--out", help="output directory (default: ./<name>_forensics_<timestamp>)")
    ap.add_argument("--modules", help="comma-separated modules to run (default: all default modules)")
    ap.add_argument("--skip", help="comma-separated modules to skip")
    ap.add_argument("--deep-registry", action="store_true", help="also run exhaustive registry search (slow)")
    ap.add_argument("--max-events", type=int, default=20000, help="max events read per log channel (default 20000)")
    ap.add_argument("--max-usn", type=int, default=1000, help="max USN records reported (default 1000)")
    ap.add_argument("--no-vss", action="store_true", help="never use esentutl /vss to copy locked files")
    ap.add_argument("--list-modules", action="store_true", help="list modules and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.list_modules:
        for n, m in MODULES.items():
            tags = ("" if m["default"] else " [opt-in]") + (" [Windows]" if m["needs_windows"] else "") + (
                " [live]" if m["live_only"] else "")
            print(f"  {n:<12} {m['desc']}{tags}")
        return 0
    if not args.target:
        ap.error("target is required")
    if args.root is None and not IS_WIN:
        ap.error("live mode needs Windows - use --root <mounted image> for offline analysis")
    if args.root and not os.path.isdir(args.root):
        ap.error(f"--root {args.root} is not a directory")

    t0 = time.time()
    ctx = Ctx(args)
    if ctx.live and not ctx.admin:
        print("[!] Not running as Administrator: $MFT, USN, VSS, Security log, other users and locked files will be skipped.",
              file=sys.stderr)
    tg = ctx.target
    print(f"[*] target : {tg.path or tg.name}  ({'exists' if tg.exists else 'not on disk' if tg.is_path else 'name-only'})")
    if tg.sha256:
        print(f"[*] sha256 : {tg.sha256}")

    sel = [m.strip() for m in args.modules.split(",")] if args.modules else \
        [n for n, m in MODULES.items() if m["default"] or (n == "deepreg" and args.deep_registry)]
    skip = {m.strip() for m in (args.skip or "").split(",") if m.strip()}
    for name in sel:
        if name in skip:
            continue
        mod = MODULES.get(name)
        if not mod:
            print(f"[!] unknown module {name}", file=sys.stderr)
            continue
        if mod["needs_windows"] and not IS_WIN:
            ctx.r.note(name, "skipped: requires Windows")
            continue
        if mod["live_only"] and not ctx.live:
            ctx.r.note(name, "skipped: live-system only")
            continue
        n0, s0 = len(ctx.r.findings), time.time()
        print(f"[*] {name:<12} ...", end="", flush=True)
        try:
            mod["fn"](ctx)
        except Exception as e:
            ctx.r.error(name, f"{type(e).__name__}: {e}")
            if os.environ.get("W11FF_DEBUG"):
                traceback.print_exc()
        print(f" {len(ctx.r.findings) - n0:4d} finding(s)  {time.time() - s0:5.1f}s")

    out = args.out or f"{re.sub(r'[^A-Za-z0-9._-]', '_', tg.name)}_forensics_{dt.datetime.now():%Y%m%d_%H%M%S}"
    write_outputs(ctx, out, time.time() - t0)
    shutil.rmtree(ctx.tmp, ignore_errors=True)
    print(f"[+] {len(ctx.r.findings)} findings, {len(ctx.r.errors)} errors -> {os.path.join(os.path.abspath(out), 'report.html')}")
    for e in ctx.r.errors[:15]:
        print(f"    ! {e['module']}: {e['error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
