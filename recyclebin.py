#!/usr/bin/env python3
"""
recyclebin.py - list, decode and extract Windows Recycle Bin contents.

Supports:
  * Vista/7/8   $Recycle.Bin  $I files, version 1 (fixed 544 bytes)
  * Win10/11    $Recycle.Bin  $I files, version 2 (variable length)
  * XP/2003     RECYCLER      INFO2 index + Dc<n>.<ext> content files

Works on a live Windows box (run elevated to see other users' SIDs) or
against a mounted image / exported folder on any OS.

Usage:
  python recyclebin.py list    [ROOT ...] [--csv out.csv] [--json out.json]
  python recyclebin.py extract [ROOT ...] -o OUTDIR [--flat] [--no-hash]

ROOT can be a volume root (E:\\ or /mnt/img), a $Recycle.Bin folder,
or a single SID folder. On Windows with no ROOT, every drive is scanned.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath
from typing import Iterator, Optional

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
BIN_DIR_NAMES = {"$recycle.bin", "recycler", "recycled"}


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #
def filetime_to_iso(ft: int) -> Optional[str]:
    if ft <= 0:
        return None
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=ft // 10)).isoformat()
    except OverflowError:
        return None


@dataclass
class Entry:
    format: str                    # "$I v1", "$I v2", "INFO2", "orphan $R"
    sid: str                       # owning SID folder name
    index_file: Optional[str]      # $I file or INFO2 path
    content_path: Optional[str]    # $R / Dc file path
    original_path: str
    size: Optional[int]            # size recorded in metadata
    deleted_utc: Optional[str]
    is_dir: bool = False
    content_present: bool = False
    sha256: Optional[str] = None
    extracted_to: Optional[str] = None
    note: str = ""


def parse_i_file(path: Path) -> tuple[str, int, Optional[str], str]:
    """Return (format, size, deleted_iso, original_path) for a $I file."""
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"too short ({len(data)} bytes)")
    version, size, ft = struct.unpack_from("<qqq", data, 0)
    if version == 1:
        raw = data[24:24 + 520]                       # 260 UTF-16 chars
    elif version == 2:
        if len(data) < 28:
            raise ValueError("v2 header truncated")
        (nchars,) = struct.unpack_from("<i", data, 24)  # includes NUL
        raw = data[28:28 + max(nchars, 0) * 2]
    else:
        raise ValueError(f"unknown $I version {version}")
    name = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    return f"$I v{version}", size, filetime_to_iso(ft), name


def parse_info2(path: Path) -> Iterator[dict]:
    """Yield records from an XP-era INFO2 file."""
    data = path.read_bytes()
    if len(data) < 20:
        return
    rec_size = struct.unpack_from("<I", data, 12)[0] or 800
    ansi_codec = "mbcs" if os.name == "nt" else "cp1252"
    off = 20
    while off + rec_size <= len(data):
        rec = data[off:off + rec_size]
        ansi_raw = rec[0:260]
        idx, drive = struct.unpack_from("<II", rec, 260)
        ft, size = struct.unpack_from("<qI", rec, 268)
        uni = ""
        if rec_size >= 800:
            uni = rec[280:800].decode("utf-16-le", "replace").split("\x00", 1)[0]
        ansi = ansi_raw.split(b"\x00", 1)[0].decode(ansi_codec, "replace")
        # When restored/purged, Windows zeroes the first ANSI byte.
        removed = ansi_raw[:1] == b"\x00"
        name = uni or ansi
        if removed and not uni:
            name = "?" + ansi_raw[1:].split(b"\x00", 1)[0].decode(ansi_codec, "replace")
        yield {
            "index": idx, "drive": drive, "name": name,
            "deleted": filetime_to_iso(ft), "size": size, "removed": removed,
        }
        off += rec_size


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def default_roots() -> list[Path]:
    if os.name != "nt":
        return []
    roots = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for d in ("$Recycle.Bin", "RECYCLER"):
            p = Path(f"{letter}:\\{d}")
            try:
                if p.is_dir():
                    roots.append(p)
            except OSError:
                pass
    return roots


def iter_bin_dirs(root: Path) -> Iterator[Path]:
    """Yield every directory that may directly contain $I / INFO2 files."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Never descend into $R folders (deleted directories) or Dc folders.
        dirnames[:] = [
            d for d in dirnames
            if not d.upper().startswith("$R") and not re.match(r"^D[a-z]\d+", d, re.I)
        ]
        lower = {f.lower() for f in filenames}
        if any(f.startswith("$i") for f in lower) or "info2" in lower \
                or any(d.upper().startswith("$R") for d in os.listdir(dirpath)):
            yield Path(dirpath)


def scan_dir(d: Path) -> Iterator[Entry]:
    sid = d.name
    try:
        names = os.listdir(d)
    except OSError as e:
        print(f"[!] cannot list {d}: {e}", file=sys.stderr)
        return
    by_lower = {n.lower(): n for n in names}
    claimed: set[str] = set()

    # Vista+ $I / $R pairs
    for n in sorted(names):
        if not n.upper().startswith("$I"):
            continue
        ipath = d / n
        if ipath.is_dir():
            continue
        r_name = by_lower.get(("$r" + n[2:]).lower())
        rpath = d / r_name if r_name else None
        if r_name:
            claimed.add(r_name)
        try:
            fmt, size, deleted, orig = parse_i_file(ipath)
            note = ""
        except Exception as e:  # noqa: BLE001 - keep going on corrupt files
            fmt, size, deleted, orig, note = "$I ?", None, None, "", f"parse error: {e}"
        e = Entry(fmt, sid, str(ipath), str(rpath) if rpath else None, orig,
                  size, deleted, note=note)
        if rpath and rpath.exists():
            e.content_present = True
            e.is_dir = rpath.is_dir()
        elif not note:
            e.note = "content ($R) missing - emptied or partially purged"
        yield e

    # $R with no $I
    for n in sorted(names):
        if n.upper().startswith("$R") and n not in claimed:
            rpath = d / n
            yield Entry("orphan $R", sid, None, str(rpath), "", None, None,
                        is_dir=rpath.is_dir(), content_present=True,
                        note="no $I metadata")

    # XP INFO2
    info2 = by_lower.get("info2")
    if info2:
        for r in parse_info2(d / info2):
            ext = PureWindowsPath(r["name"]).suffix
            cname = f"D{chr(ord('a') + r['drive'])}{r['index']}{ext}"
            real = by_lower.get(cname.lower())
            cpath = d / real if real else None
            e = Entry("INFO2", sid, str(d / info2), str(cpath) if cpath else None,
                      r["name"], r["size"], r["deleted"])
            if cpath and cpath.exists():
                e.content_present = True
                e.is_dir = cpath.is_dir()
            if r["removed"]:
                e.note = "record marked removed (restored or purged)"
            elif not e.content_present:
                e.note = "content file missing"
            yield e


def collect(roots: list[Path]) -> list[Entry]:
    seen: set[str] = set()
    out: list[Entry] = []
    for root in roots:
        if not root.exists():
            print(f"[!] {root} does not exist", file=sys.stderr)
            continue
        # If given a volume root, prefer its bin folders.
        start = [root]
        if root.name.lower() not in BIN_DIR_NAMES:
            kids = [c for c in root.iterdir() if c.name.lower() in BIN_DIR_NAMES] \
                if root.is_dir() else []
            start = kids or [root]
        for s in start:
            for d in iter_bin_dirs(s):
                key = str(d.resolve())
                if key in seen:
                    continue
                seen.add(key)
                out.extend(scan_dir(d))
    return out


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_rel_from_windows(original: str) -> Path:
    """Turn C:\\Users\\x\\a.txt into C/Users/x/a.txt, stripping traversal."""
    p = PureWindowsPath(original)
    parts = []
    if p.drive:
        drv = p.drive
        if drv.startswith(("\\\\", "//")):          # \\server\share -> UNC/server/share
            parts.append("UNC")
            parts.extend(_BAD.sub("_", x) for x in re.split(r"[\\/]+", drv) if x)
        else:
            parts.append(_BAD.sub("_", drv.rstrip(":\\/")) or "_")
    for part in p.parts[1 if p.anchor else 0:]:
        part = _BAD.sub("_", part).strip(" .")
        if part and part not in (".", ".."):
            parts.append(part)
    return Path(*parts) if parts else Path("_unknown")


def unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suf, n = path.stem, path.suffix, 1
    while True:
        cand = path.with_name(f"{stem} ({n}){suf}")
        if not cand.exists():
            return cand
        n += 1


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract(entries: list[Entry], outdir: Path, flat: bool, do_hash: bool) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for e in entries:
        if not e.content_present or not e.content_path:
            continue
        src = Path(e.content_path)
        if flat or not e.original_path:
            base = PureWindowsPath(e.original_path).name if e.original_path else ""
            name = f"{src.name}__{_BAD.sub('_', base)}" if base else src.name
            dst = outdir / e.sid / name
        else:
            dst = outdir / e.sid / safe_rel_from_windows(e.original_path)
        dst = unique(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            if src.is_dir():
                shutil.copytree(src, dst, copy_function=shutil.copy2)
            else:
                shutil.copy2(src, dst)
                if do_hash:
                    e.sha256 = sha256_file(src)
            e.extracted_to = str(dst)
        except OSError as err:
            e.note = (e.note + "; " if e.note else "") + f"extract failed: {err}"
            print(f"[!] {src}: {err}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def human(n: Optional[int]) -> str:
    if n is None:
        return "?"
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def print_table(entries: list[Entry]) -> None:
    if not entries:
        print("No Recycle Bin entries found.")
        return
    print(f"{'Deleted (UTC)':<20} {'Size':>7} {'Fmt':<9} {'St':<3} {'SID':<14} Original path")
    print("-" * 110)
    for e in sorted(entries, key=lambda x: x.deleted_utc or ""):
        when = (e.deleted_utc or "?")[:19].replace("T", " ")
        st = ("D" if e.is_dir else "F") if e.content_present else "-"
        sid = e.sid if len(e.sid) <= 14 else "…" + e.sid[-13:]
        orig = e.original_path or f"<{Path(e.content_path or '').name}>"
        print(f"{when:<20} {human(e.size):>7} {e.format:<9} {st:<3} {sid:<14} {orig}")
        if e.note:
            print(f"{'':<56}  ↳ {e.note}")
        if e.extracted_to:
            print(f"{'':<56}  → {e.extracted_to}" + (f"  sha256={e.sha256}" if e.sha256 else ""))
    present = sum(e.content_present for e in entries)
    print(f"\n{len(entries)} entries, {present} with recoverable content. "
          "St: F=file D=directory -=content missing")


def write_reports(entries: list[Entry], csv_path: Optional[str], json_path: Optional[str]) -> None:
    rows = [asdict(e) for e in entries]
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(Entry.__dataclass_fields__))
            w.writeheader()
            w.writerows(rows)
        print(f"[+] CSV written to {csv_path}")
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print(f"[+] JSON written to {json_path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="List, decode and extract Windows Recycle Bin contents.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "extract"):
        sp = sub.add_parser(name)
        sp.add_argument("roots", nargs="*", type=Path,
                        help="volume root, $Recycle.Bin, or SID folder (default: all local drives on Windows)")
        sp.add_argument("--sid", help="only this SID folder")
        sp.add_argument("--csv", help="write report as CSV")
        sp.add_argument("--json", help="write report as JSON")
        if name == "extract":
            sp.add_argument("-o", "--outdir", type=Path, required=True)
            sp.add_argument("--flat", action="store_true",
                            help="don't rebuild original folder tree; name files $Rxxxx__original.ext")
            sp.add_argument("--no-hash", action="store_true", help="skip SHA-256 hashing")
    a = ap.parse_args()

    roots = a.roots or default_roots()
    if not roots:
        ap.error("no ROOT given and no local Recycle Bin found")

    entries = collect(roots)
    if a.sid:
        entries = [e for e in entries if e.sid.lower() == a.sid.lower()]

    if a.cmd == "extract":
        extract(entries, a.outdir, a.flat, not a.no_hash)

    print_table(entries)
    write_reports(entries, a.csv, a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
