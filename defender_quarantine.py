#!/usr/bin/env python3
"""
defender_quarantine.py - list and extract Microsoft Defender quarantined files.

Defender stores quarantine under:
    %ProgramData%\\Microsoft\\Windows Defender\\Quarantine\\
        Entries\\{GUID}                 RC4-encrypted metadata (detection, time, paths)
        ResourceData\\<xx>\\<SHA1>       RC4-encrypted file content (+ security descriptor)
        Resources\\<xx>\\<SHA1>          legacy pointer files (not needed)

Both use the same static RC4 key from mpengine.dll. Format and key are as
documented by ERNW (github.com/ernw/quarantine-formats) and implemented in
knez/defender-dump. This script adds hash verification, all resource types,
orphan recovery, safe output containers and CSV/JSON reports.

Works on a live Windows host (must run elevated - the folder is SYSTEM/Admin
only) or against a mounted image / collected folder on any OS.

Usage:
  python defender_quarantine.py list    [ROOT] [--csv r.csv] [--json r.json]
  python defender_quarantine.py extract [ROOT] -o OUT [--format tar|zip|raw] [--orphans]

ROOT may be a volume root (C:\\ or /mnt/img), the ProgramData folder, or the
Quarantine folder itself. Defaults to C:\\ on Windows.

!! Extracted files are LIVE MALWARE. Default output is an uncompressed .tar so
nothing executable lands on disk. --format zip uses AES with password
"infected" (needs `pip install pyzipper`). --format raw writes loose files with
a ".quarantined" suffix - only do this in an isolated analysis VM, and expect
Defender to re-quarantine them on a live host.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import struct
import sys
import tarfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Optional

# --------------------------------------------------------------------------- #
# RC4 with Defender's static key
# --------------------------------------------------------------------------- #
KEY = bytes([
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
    0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
    0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
    0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
    0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
    0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
    0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
    0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
    0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
])
assert len(KEY) == 256


def _ksa() -> list[int]:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + KEY[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


_SBOX = _ksa()


def _rc4_py(data: bytes) -> bytes:
    s = _SBOX[:]                       # fresh state each call
    out = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        si = s[i]
        j = (j + si) & 0xFF
        sj = s[j]
        s[i], s[j] = sj, si
        out[k] = b ^ s[(si + sj) & 0xFF]
    return bytes(out)


class _Keystream:
    """Every Defender RC4 call starts from the same key state, so the keystream
    is always identical. Generate it once (incrementally), cache it, and XOR
    with big-int arithmetic - orders of magnitude faster than byte-wise RC4."""

    def __init__(self):
        self.s = _SBOX[:]
        self.i = self.j = 0
        self.buf = bytearray()

    def get(self, n: int) -> bytes:
        if n > len(self.buf):
            need = max(n - len(self.buf), 1 << 20)
            s, i, j = self.s, self.i, self.j
            chunk = bytearray(need)
            for k in range(need):
                i = (i + 1) & 0xFF
                si = s[i]
                j = (j + si) & 0xFF
                sj = s[j]
                s[i], s[j] = sj, si
                chunk[k] = s[(si + sj) & 0xFF]
            self.i, self.j = i, j
            self.buf += chunk
        return bytes(self.buf[:n])


_KS = _Keystream()


def rc4(data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return b""
    ks = _KS.get(n)
    return (int.from_bytes(data, "little") ^ int.from_bytes(ks, "little")).to_bytes(n, "little")


RC4_BACKEND = "cached-keystream"


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def filetime_to_iso(ft: int) -> Optional[str]:
    if ft <= 0:
        return None
    try:
        return (dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                + dt.timedelta(microseconds=ft // 10)).isoformat()
    except OverflowError:
        return None


@dataclass
class Resource:
    entry_file: str
    entry_guid: str
    detection: str
    quarantined_utc: Optional[str]
    rtype: str                         # file, regkey, process, ...
    original_path: str
    sha1: Optional[str] = None         # name of ResourceData blob = SHA1 of original
    data_file: Optional[str] = None
    content_present: bool = False
    size: Optional[int] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    sha1_verified: Optional[bool] = None
    extracted_as: Optional[str] = None
    note: str = ""


def _parse_resource(blob: bytes) -> tuple[str, str, Optional[str]]:
    """Return (path, type, sha1) for one resource record inside Entries data2."""
    # Path: NUL-terminated UTF-16LE. Find an even-aligned 00 00 terminator.
    end = 0
    while end + 1 < len(blob):
        if blob[end] == 0 and blob[end + 1] == 0:
            break
        end += 2
    path = blob[:end].decode("utf-16-le", "replace")
    if path.startswith("\\\\?\\"):
        path = path[4:]
    elif path[2:4] == "?\\":          # "\??\C:\..." style
        path = path[4:]
    pos = end + 2                      # skip UTF-16 NUL terminator
    pos += 2                           # uint16 field count
    tend = blob.find(b"\x00", pos)
    if tend < 0:
        return path, "?", None
    rtype = blob[pos:tend].decode("utf-8", "replace")
    pos = tend + 1
    pos += (-pos) % 4                  # align to 4
    pos += 4                           # extra metadata dword
    sha1 = None
    if rtype == "file" and pos + 20 <= len(blob):
        sha1 = blob[pos:pos + 20].hex().upper()
    return path, rtype, sha1


def parse_entry(path: Path) -> list[Resource]:
    raw = path.read_bytes()
    if len(raw) < 0x3C:
        raise ValueError("file shorter than header")
    header = rc4(raw[:0x3C])
    len1, len2 = struct.unpack_from("<II", header, 0x28)
    if 0x3C + len1 + len2 > len(raw):
        raise ValueError(f"lengths {len1}/{len2} exceed file size {len(raw)} (wrong format/version?)")
    data1 = rc4(raw[0x3C:0x3C + len1])
    data2 = rc4(raw[0x3C + len1:0x3C + len1 + len2])

    (ft,) = struct.unpack_from("<Q", data1, 0x20)
    detection = data1[0x34:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    when = filetime_to_iso(ft)

    (count,) = struct.unpack_from("<I", data2, 0)
    if count > 10_000 or 4 + 4 * count > len(data2):
        raise ValueError(f"implausible resource count {count}")
    offsets = struct.unpack_from(f"<{count}I", data2, 4)

    out = []
    for off in offsets:
        try:
            p, t, h = _parse_resource(data2[off:])
            note = ""
        except Exception as e:  # noqa: BLE001
            p, t, h, note = "", "?", None, f"resource parse error: {e}"
        out.append(Resource(str(path), path.name, detection, when, t, p, h, note=note))
    return out


def decode_resource_data(raw: bytes) -> bytes:
    """Decrypt a ResourceData blob and return the original file bytes."""
    dec = rc4(raw)
    (sd_len,) = struct.unpack_from("<I", dec, 0x08)
    hdr = 0x28 + sd_len
    (flen,) = struct.unpack_from("<Q", dec, sd_len + 0x1C)
    if hdr + flen > len(dec):
        raise ValueError(f"declared length {flen} exceeds blob ({len(dec) - hdr} available)")
    return dec[hdr:hdr + flen]


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
QUAR_REL = Path("ProgramData") / "Microsoft" / "Windows Defender" / "Quarantine"


def find_quarantine(root: Path) -> Path:
    cands = [root, root / "Quarantine", root / "Microsoft" / "Windows Defender" / "Quarantine",
             root / QUAR_REL]
    for c in cands:
        if (c / "Entries").is_dir() or (c / "ResourceData").is_dir():
            return c
    raise FileNotFoundError(
        f"no Defender Quarantine folder (Entries/ResourceData) found under {root}. "
        "On a live host run from an elevated prompt.")


def resource_data_path(qdir: Path, sha1: str) -> Path:
    return qdir / "ResourceData" / sha1[:2] / sha1


def collect(qdir: Path, include_orphans: bool) -> list[Resource]:
    res: list[Resource] = []
    edir = qdir / "Entries"
    if edir.is_dir():
        for p in sorted(edir.iterdir()):
            if not p.is_file():
                continue
            try:
                res.extend(parse_entry(p))
            except Exception as e:  # noqa: BLE001
                res.append(Resource(str(p), p.name, "", None, "?", "",
                                    note=f"entry parse error: {e}"))
    else:
        print(f"[!] {edir} missing - metadata unavailable", file=sys.stderr)

    referenced: set[str] = set()
    for r in res:
        if r.sha1:
            dp = resource_data_path(qdir, r.sha1)
            referenced.add(r.sha1)
            r.data_file = str(dp)
            r.content_present = dp.is_file()
            if not r.content_present:
                r.note = r.note or "ResourceData blob missing (restored/removed?)"

    if include_orphans and (qdir / "ResourceData").is_dir():
        for p in sorted((qdir / "ResourceData").rglob("*")):
            if p.is_file() and re.fullmatch(r"[0-9A-Fa-f]{40}", p.name) \
                    and p.name.upper() not in referenced:
                res.append(Resource("", "", "", None, "orphan", "", p.name.upper(),
                                    str(p), True, note="ResourceData with no Entries record"))
    return res


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_name(r: Resource) -> str:
    base = PureWindowsPath(r.original_path).name if r.original_path else ""
    base = _BAD.sub("_", base).strip(" .") or "unknown"
    return f"{(r.sha1 or 'nohash')[:12]}_{base}"[:200]


class Sink:
    def __init__(self, outdir: Path, fmt: str, password: str):
        self.fmt = fmt
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "tar":
            self.path = outdir / f"quarantine_{stamp}.tar"
            self.tar = tarfile.open(self.path, "w")
        elif fmt == "zip":
            try:
                import pyzipper
            except ImportError:
                sys.exit("[-] --format zip needs `pip install pyzipper` (AES zip). Use tar or raw instead.")
            self.path = outdir / f"quarantine_{stamp}.zip"
            self.zip = pyzipper.AESZipFile(self.path, "w", compression=pyzipper.ZIP_DEFLATED,
                                           encryption=pyzipper.WZ_AES)
            self.zip.setpassword(password.encode())
        else:
            self.path = outdir / f"quarantine_{stamp}"
            self.path.mkdir()
        self.names: set[str] = set()

    def add(self, name: str, data: bytes, mtime: float) -> str:
        n, i = name, 1
        while n in self.names:
            n, i = f"{name}.{i}", i + 1
        self.names.add(n)
        if self.fmt == "tar":
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime, ti.mode = len(data), int(mtime), 0o400
            self.tar.addfile(ti, io.BytesIO(data))
            return f"{self.path.name}:{n}"
        if self.fmt == "zip":
            self.zip.writestr(n, data)
            return f"{self.path.name}:{n}"
        dst = self.path / (n + ".quarantined")
        dst.write_bytes(data)
        os.chmod(dst, 0o400)
        return str(dst)

    def close(self):
        if self.fmt == "tar":
            self.tar.close()
        elif self.fmt == "zip":
            self.zip.close()


def extract(res: list[Resource], outdir: Path, fmt: str, password: str) -> Path:
    sink = Sink(outdir, fmt, password)
    done: dict[str, str] = {}               # same blob referenced twice -> one copy
    try:
        for r in res:
            if not (r.content_present and r.data_file):
                continue
            if r.sha1 in done:
                r.extracted_as = done[r.sha1]
                continue
            try:
                data = decode_resource_data(Path(r.data_file).read_bytes())
            except Exception as e:  # noqa: BLE001
                r.note = (r.note + "; " if r.note else "") + f"decode failed: {e}"
                continue
            r.size = len(data)
            r.md5 = hashlib.md5(data).hexdigest()
            r.sha256 = hashlib.sha256(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest().upper()
            r.sha1_verified = (sha1 == r.sha1)
            if not r.sha1_verified:
                r.note = (r.note + "; " if r.note else "") + f"SHA1 mismatch (got {sha1})"
            mtime = time.time()
            if r.quarantined_utc:
                mtime = dt.datetime.fromisoformat(r.quarantined_utc).timestamp()
            r.extracted_as = sink.add(safe_name(r), data, mtime)
            done[r.sha1] = r.extracted_as
    finally:
        sink.close()
    return sink.path


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_table(res: list[Resource]) -> None:
    if not res:
        print("Quarantine is empty.")
        return
    w = min(max((len(r.detection) for r in res), default=9), 45)
    print(f"{'Quarantined (UTC)':<20} {'Type':<8} {'Detection':<{w}} {'Data':<4} Original path")
    print("-" * (40 + w + 40))
    for r in sorted(res, key=lambda x: x.quarantined_utc or ""):
        when = (r.quarantined_utc or "?")[:19].replace("T", " ")
        st = "yes" if r.content_present else ("-" if r.rtype == "file" or r.rtype == "orphan" else "n/a")
        print(f"{when:<20} {r.rtype[:8]:<8} {r.detection[:w]:<{w}} {st:<4} "
              f"{r.original_path or '<' + (r.sha1 or '') + '>'}")
        if r.sha1:
            line = f"    sha1={r.sha1}"
            if r.sha256:
                line += f" sha256={r.sha256} size={r.size}"
                line += "  [verified]" if r.sha1_verified else "  [MISMATCH]"
            print(line)
        if r.extracted_as:
            print(f"    -> {r.extracted_as}")
        if r.note:
            print(f"    ! {r.note}")
    files = [r for r in res if r.rtype in ("file", "orphan")]
    print(f"\n{len(res)} resources across {len({r.entry_guid for r in res if r.entry_guid})} entries; "
          f"{sum(r.content_present for r in files)}/{len(files)} file blobs present. RC4: {RC4_BACKEND}")


def write_reports(res: list[Resource], csv_path: Optional[str], json_path: Optional[str]) -> None:
    rows = [asdict(r) for r in res]
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            wr = csv.DictWriter(f, fieldnames=list(Resource.__dataclass_fields__))
            wr.writeheader()
            wr.writerows(rows)
        print(f"[+] CSV  -> {csv_path}")
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print(f"[+] JSON -> {json_path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="List and extract Microsoft Defender quarantine.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "extract"):
        sp = sub.add_parser(name)
        sp.add_argument("root", nargs="?", type=Path,
                        help="volume root, ProgramData, or Quarantine folder (default C:\\ on Windows)")
        sp.add_argument("--orphans", action="store_true",
                        help="also include ResourceData blobs with no Entries record")
        sp.add_argument("--csv")
        sp.add_argument("--json")
        if name == "extract":
            sp.add_argument("-o", "--outdir", type=Path, required=True)
            sp.add_argument("--format", choices=("tar", "zip", "raw"), default="tar")
            sp.add_argument("--password", default="infected", help="zip password (default: infected)")
    a = ap.parse_args()

    root = a.root or (Path("C:\\") if os.name == "nt" else None)
    if root is None:
        ap.error("ROOT is required on non-Windows systems")
    try:
        qdir = find_quarantine(root)
    except (FileNotFoundError, PermissionError) as e:
        print(f"[-] {e}", file=sys.stderr)
        return 1
    print(f"[*] Quarantine folder: {qdir}")

    res = collect(qdir, a.orphans)
    if a.cmd == "extract":
        out = extract(res, a.outdir, a.format, a.password)
        print(f"[+] Extracted to {out}" + (f" (password: {a.password})" if a.format == "zip" else ""))
    print_table(res)
    write_reports(res, a.csv, a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
