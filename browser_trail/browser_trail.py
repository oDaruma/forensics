#!/usr/bin/env python3
"""
browser_trail.py - Reconstruct HOW a browser arrived at a given URL.

Digital forensics helper. For every visit to the target URL found in Chrome,
Edge (any Chromium profile) and Firefox history, it walks the referrer chain
backwards (link -> redirect -> search results -> typed URL ...) and prints a
table with timestamps, transition types and any search keywords involved.

Forensic handling
  * Original databases are NEVER opened. Each DB (plus -wal/-journal/-shm) is
    copied to a temp dir and the copy is queried.
  * SHA-256, size and mtime of every original file are recorded in an evidence
    manifest (printed, and embedded in JSON output).
  * Every hop is labelled with how it was linked:
      from_visit   - browser-recorded referrer (Chromium visits.from_visit /
                     Firefox moz_historyvisits.from_visit)
      opener       - Chromium opener_visit (link opened in new tab/window)
      INFERRED     - heuristic only (--infer): previous visit in same profile
                     within N seconds. Treat as a lead, NOT as evidence.

Usage
  python browser_trail.py "https://example.com/page"
  python browser_trail.py example.com --match contains --infer 120
  python browser_trail.py URL --home /mnt/image/Users/alice --os windows
  python browser_trail.py URL --db chromium:/case/History --db firefox:/case/places.sqlite
  python browser_trail.py URL --csv out.csv --json out.json

Standard library only (Python 3.8+). `rich`, if installed, is used for nicer tables.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus, urlsplit, urlunsplit

UTC = dt.timezone.utc
WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)
UNIX_EPOCH = dt.datetime(1970, 1, 1, tzinfo=UTC)

# --------------------------------------------------------------------------- #
# Transition / visit-type decoding
# --------------------------------------------------------------------------- #
CHROME_CORE = {
    0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME", 5: "GENERATED", 6: "AUTO_TOPLEVEL",
    7: "FORM_SUBMIT", 8: "RELOAD", 9: "KEYWORD", 10: "KEYWORD_GENERATED",
}
CHROME_QUALIFIERS = [
    (0x01000000, "FWD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"),
    (0x04000000, "HOME_PAGE"), (0x08000000, "FROM_API"),
    (0x10000000, "CHAIN_START"), (0x20000000, "CHAIN_END"),
    (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT"),
]
CHROME_USER_START = {1, 2, 5, 9, 10}  # typed, bookmark, omnibox-generated, keyword

FIREFOX_TYPES = {
    1: "LINK", 2: "TYPED", 3: "BOOKMARK", 4: "EMBED", 5: "REDIRECT_PERMANENT",
    6: "REDIRECT_TEMPORARY", 7: "DOWNLOAD", 8: "FRAMED_LINK", 9: "RELOAD",
}
FIREFOX_USER_START = {2, 3}
FIREFOX_REDIRECTS = {5, 6}


def chrome_transition(t: int) -> Tuple[str, bool, bool]:
    """Return (label, is_redirect, is_user_start)."""
    t &= 0xFFFFFFFF
    core = t & 0xFF
    quals = [name for bit, name in CHROME_QUALIFIERS if t & bit]
    label = CHROME_CORE.get(core, f"UNKNOWN({core})")
    if quals:
        label += "|" + "|".join(quals)
    is_redirect = bool(t & 0xC0000000)
    is_start = core in CHROME_USER_START or bool(t & 0x02000000)
    return label, is_redirect, is_start


def firefox_transition(t: int) -> Tuple[str, bool, bool]:
    return (FIREFOX_TYPES.get(t, f"UNKNOWN({t})"),
            t in FIREFOX_REDIRECTS, t in FIREFOX_USER_START)


def webkit_to_dt(us: Optional[int]) -> Optional[dt.datetime]:
    return WEBKIT_EPOCH + dt.timedelta(microseconds=us) if us else None


def prtime_to_dt(us: Optional[int]) -> Optional[dt.datetime]:
    return UNIX_EPOCH + dt.timedelta(microseconds=us) if us else None


# --------------------------------------------------------------------------- #
# Search keyword extraction from URLs (fallback when the browser didn't store it)
# --------------------------------------------------------------------------- #
SEARCH_ENGINES = [
    ("google.", ["q", "as_q"]), ("bing.com", ["q"]), ("duckduckgo.", ["q"]),
    ("search.yahoo.", ["p"]), ("baidu.", ["wd", "word"]), ("yandex.", ["text"]),
    ("youtube.", ["search_query"]), ("ecosia.", ["q"]), ("startpage.", ["query", "q"]),
    ("search.brave.", ["q"]), ("ask.com", ["q"]), ("qwant.", ["q"]),
    ("amazon.", ["k", "field-keywords"]), ("github.com", ["q"]),
]


def extract_search_terms(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = parts.netloc.lower()
    # google.com/url?q=<destination> is a redirector, not a search
    if "google." in host and parts.path.startswith("/url"):
        return ""
    for needle, keys in SEARCH_ENGINES:
        if needle in host:
            for source in (parts.query, parts.fragment):
                qs = parse_qs(source)
                for k in keys:
                    if qs.get(k) and qs[k][0].strip():
                        return unquote_plus(qs[k][0]).strip()
    return ""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Visit:
    browser: str
    profile: str
    visit_id: int
    url: str
    title: str
    time: Optional[dt.datetime]
    transition: str
    is_redirect: bool
    is_user_start: bool
    from_visit: int = 0
    opener_visit: int = 0
    search_terms: str = ""
    typed_input: str = ""          # Firefox moz_inputhistory (address-bar text)
    external_referrer: str = ""    # Chromium visits.external_referrer_url
    link: str = ""                 # how this hop was linked to the next one


@dataclass
class Evidence:
    browser: str
    profile: str
    path: str
    sha256: str
    size: int
    mtime_utc: str


# --------------------------------------------------------------------------- #
# Profile discovery
# --------------------------------------------------------------------------- #
def detect_os() -> str:
    s = platform.system().lower()
    return "windows" if s.startswith("win") else "macos" if s == "darwin" else "linux"


def candidate_roots(home: Path, os_name: str) -> List[Tuple[str, str, Path, str]]:
    """(browser, engine, root_dir, db_glob)"""
    if os_name == "windows":
        local = home / "AppData" / "Local"
        roaming = home / "AppData" / "Roaming"
        return [
            ("Chrome", "chromium", local / "Google/Chrome/User Data", "*/History"),
            ("Edge", "chromium", local / "Microsoft/Edge/User Data", "*/History"),
            ("Firefox", "firefox", roaming / "Mozilla/Firefox/Profiles", "*/places.sqlite"),
        ]
    if os_name == "macos":
        sup = home / "Library/Application Support"
        return [
            ("Chrome", "chromium", sup / "Google/Chrome", "*/History"),
            ("Edge", "chromium", sup / "Microsoft Edge", "*/History"),
            ("Firefox", "firefox", sup / "Firefox/Profiles", "*/places.sqlite"),
        ]
    return [
        ("Chrome", "chromium", home / ".config/google-chrome", "*/History"),
        ("Chromium", "chromium", home / ".config/chromium", "*/History"),
        ("Edge", "chromium", home / ".config/microsoft-edge", "*/History"),
        ("Firefox", "firefox", home / ".mozilla/firefox", "*/places.sqlite"),
        ("Firefox", "firefox", home / "snap/firefox/common/.mozilla/firefox", "*/places.sqlite"),
    ]


def discover(home: Path, os_name: str) -> List[Tuple[str, str, str, Path]]:
    found = []
    for browser, engine, root, pattern in candidate_roots(home, os_name):
        if root.is_dir():
            for db in sorted(root.glob(pattern)):
                if db.is_file():
                    found.append((browser, engine, db.parent.name, db))
    return found


# --------------------------------------------------------------------------- #
# Forensically safe copy
# --------------------------------------------------------------------------- #
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_copy(db: Path, workdir: Path, browser: str, profile: str,
              evidence: List[Evidence]) -> Path:
    dest_dir = Path(tempfile.mkdtemp(dir=workdir))
    for suffix in ("", "-wal", "-journal", "-shm"):
        src = Path(str(db) + suffix)
        if src.is_file():
            st = src.stat()
            evidence.append(Evidence(
                browser, profile, str(src), sha256_file(src), st.st_size,
                dt.datetime.fromtimestamp(st.st_mtime, UTC).isoformat()))
            shutil.copy2(src, dest_dir / (db.name + suffix))
    return dest_dir / db.name


def table_columns(con: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #
def load_chromium(copy: Path, browser: str, profile: str) -> Dict[int, Visit]:
    con = sqlite3.connect(str(copy))
    try:
        vcols = table_columns(con, "visits")
        opener = "v.opener_visit" if "opener_visit" in vcols else "0"
        ext_ref = "v.external_referrer_url" if "external_referrer_url" in vcols else "''"

        terms_by_url: Dict[int, str] = {}
        if table_columns(con, "keyword_search_terms"):
            for url_id, term in con.execute(
                    "SELECT url_id, term FROM keyword_search_terms"):
                terms_by_url[url_id] = term

        terms_by_visit: Dict[int, str] = {}
        if "search_terms" in table_columns(con, "content_annotations"):
            for vid, term in con.execute(
                    "SELECT visit_id, search_terms FROM content_annotations "
                    "WHERE search_terms IS NOT NULL AND search_terms != ''"):
                terms_by_visit[vid] = term

        visits: Dict[int, Visit] = {}
        q = (f"SELECT v.id, v.url, v.visit_time, v.from_visit, v.transition, "
             f"{opener}, {ext_ref}, u.url, u.title "
             f"FROM visits v JOIN urls u ON u.id = v.url")
        for vid, url_id, vtime, from_v, trans, op, ref, url, title in con.execute(q):
            label, redir, start = chrome_transition(trans or 0)
            terms = (terms_by_visit.get(vid) or terms_by_url.get(url_id)
                     or extract_search_terms(url or ""))
            visits[vid] = Visit(
                browser, profile, vid, url or "", title or "", webkit_to_dt(vtime),
                label, redir, start, from_v or 0, op or 0, terms or "",
                external_referrer=ref or "")
        return visits
    finally:
        con.close()


def load_firefox(copy: Path, browser: str, profile: str) -> Dict[int, Visit]:
    con = sqlite3.connect(str(copy))
    try:
        typed: Dict[int, str] = {}
        if table_columns(con, "moz_inputhistory"):
            for place_id, inp in con.execute(
                    "SELECT place_id, input FROM moz_inputhistory ORDER BY use_count"):
                typed[place_id] = inp  # highest use_count wins

        visits: Dict[int, Visit] = {}
        q = ("SELECT h.id, h.place_id, h.visit_date, h.from_visit, h.visit_type, "
             "p.url, p.title FROM moz_historyvisits h "
             "JOIN moz_places p ON p.id = h.place_id")
        for vid, pid, vdate, from_v, vtype, url, title in con.execute(q):
            label, redir, start = firefox_transition(vtype or 0)
            visits[vid] = Visit(
                browser, profile, vid, url or "", title or "", prtime_to_dt(vdate),
                label, redir, start, from_v or 0, 0, extract_search_terms(url or ""),
                typed_input=typed.get(pid, ""))
        return visits
    finally:
        con.close()


# --------------------------------------------------------------------------- #
# URL matching & chain reconstruction
# --------------------------------------------------------------------------- #
def normalize(url: str) -> str:
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    p = urlsplit(u)
    host = p.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = p.path.rstrip("/") or ""
    return urlunsplit(("", host, path, p.query, "")).lstrip("/")


def matches(url: str, target_norm: str, mode: str) -> bool:
    n = normalize(url)
    if mode == "exact":
        return n == target_norm
    if mode == "prefix":
        return n.startswith(target_norm)
    return target_norm in n


def build_chain(target: Visit, visits: Dict[int, Visit], ordered: List[Visit],
                max_depth: int, infer_gap: int) -> List[Visit]:
    chain = [target]
    seen = {target.visit_id}
    cur = target
    while len(chain) < max_depth:
        parent, link = None, ""
        if cur.from_visit and cur.from_visit in visits:
            parent, link = visits[cur.from_visit], "from_visit"
        elif cur.opener_visit and cur.opener_visit in visits:
            parent, link = visits[cur.opener_visit], "opener"
        elif infer_gap and not cur.is_user_start and cur.time:
            # heuristic: most recent earlier visit in same profile within gap
            for v in reversed(ordered):
                if v.time and v.time < cur.time and v.visit_id not in seen:
                    if (cur.time - v.time).total_seconds() <= infer_gap:
                        parent, link = v, "INFERRED"
                    break
        if parent is None or parent.visit_id in seen:
            break
        cur.link = link
        chain.append(parent)
        seen.add(parent.visit_id)
        cur = parent
    chain.reverse()
    return chain


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def fmt_time(t: Optional[dt.datetime], local: bool) -> str:
    if not t:
        return ""
    t = t.astimezone() if local else t
    return t.strftime("%Y-%m-%d %H:%M:%S") + ("" if local else "Z")


def trunc(s: str, n: int) -> str:
    return s if n <= 0 or len(s) <= n else s[: n - 1] + "\u2026"


def chain_rows(chain: List[Visit], local: bool) -> List[dict]:
    rows = []
    for i, v in enumerate(chain, 1):
        kw = v.search_terms or (f"[typed] {v.typed_input}" if v.typed_input else "")
        if i == 1 and v.external_referrer:
            kw = (kw + " " if kw else "") + f"[ext-referrer] {v.external_referrer}"
        rows.append({
            "step": i,
            "time": fmt_time(v.time, local),
            "transition": v.transition,
            "linked_by": ("ORIGIN" if i == 1 else (v.link or "?"))
                         + (" [TARGET]" if i == len(chain) else ""),
            "search_keywords": kw,
            "url": v.url,
            "title": v.title,
            "visit_id": v.visit_id,
        })
    return rows


def print_table(title: str, rows: List[dict], width: int) -> None:
    cols = ["step", "time", "transition", "linked_by", "search_keywords", "url", "title"]
    try:
        from rich.console import Console
        from rich.table import Table
        t = Table(title=title, show_lines=False, expand=False)
        for c in cols:
            t.add_column(c, overflow="fold" if c == "url" and width <= 0 else "ellipsis")
        for r in rows:
            t.add_row(*[trunc(str(r[c]), width if c in ("url", "title") else 0) for c in cols])
        Console().print(t)
        return
    except ImportError:
        pass
    data = [[trunc(str(r[c]), width if c in ("url", "title", "search_keywords") else 0)
             for c in cols] for r in rows]
    widths = [max(len(c), *(len(d[i]) for d in data)) for i, c in enumerate(cols)]
    line = "+".join("-" * (w + 2) for w in widths)
    print(f"\n{title}\n+{line}+")
    print("| " + " | ".join(c.ljust(w) for c, w in zip(cols, widths)) + " |")
    print(f"+{line}+")
    for d in data:
        print("| " + " | ".join(x.ljust(w) for x, w in zip(d, widths)) + " |")
    print(f"+{line}+")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Reconstruct the browsing path (referrers, redirects, search "
                    "keywords) that led to a URL, across Chrome, Edge and Firefox.")
    ap.add_argument("url", help="Target URL (scheme optional)")
    ap.add_argument("--match", choices=["exact", "prefix", "contains"], default="exact",
                    help="How to match the target URL (default: exact, ignoring "
                         "scheme, www., trailing slash and #fragment)")
    ap.add_argument("--home", type=Path, default=Path.home(),
                    help="User home to scan (e.g. a mounted image's Users/<name>)")
    ap.add_argument("--os", choices=["windows", "macos", "linux"], default=detect_os(),
                    help="Profile layout of --home (default: this machine)")
    ap.add_argument("--db", action="append", default=[], metavar="ENGINE:PATH",
                    help="Extra history DB, e.g. chromium:/case/History or "
                         "firefox:/case/places.sqlite (repeatable)")
    ap.add_argument("--browsers", default="chrome,edge,chromium,firefox",
                    help="Comma list to include (default: all)")
    ap.add_argument("--depth", type=int, default=25, help="Max hops per chain")
    ap.add_argument("--limit", type=int, default=10,
                    help="Most recent target visits to trace (0 = all)")
    ap.add_argument("--infer", type=int, default=0, metavar="SECONDS",
                    help="When the browser recorded no referrer, link to the previous "
                         "visit within N seconds (heuristic, flagged INFERRED)")
    ap.add_argument("--include-redirect-targets", action="store_true",
                    help="Also trace target visits that were themselves redirect hops")
    ap.add_argument("--width", type=int, default=90,
                    help="Truncate url/title columns (0 = never)")
    ap.add_argument("--localtime", action="store_true", help="Show local time, not UTC")
    ap.add_argument("--csv", type=Path, help="Write all chains to CSV")
    ap.add_argument("--json", type=Path, help="Write chains + evidence manifest to JSON")
    args = ap.parse_args()

    wanted = {b.strip().lower() for b in args.browsers.split(",")}
    sources = [s for s in discover(args.home, args.os) if s[0].lower() in wanted]
    for spec in args.db:
        engine, _, path = spec.partition(":")
        engine = engine.lower()
        if engine not in ("chromium", "firefox") or not path:
            ap.error(f"--db must be chromium:PATH or firefox:PATH (got {spec!r})")
        p = Path(path)
        sources.append(("Chromium" if engine == "chromium" else "Firefox",
                        engine, f"manual:{p.parent.name}", p))

    if not sources:
        print("No browser history databases found. Use --home/--os or --db.",
              file=sys.stderr)
        return 2

    target_norm = normalize(args.url)
    evidence: List[Evidence] = []
    results = []  # (title, rows, browser, profile)
    errors = []

    with tempfile.TemporaryDirectory(prefix="browser_trail_") as tmp:
        for browser, engine, profile, db in sources:
            try:
                copy = safe_copy(db, Path(tmp), browser, profile, evidence)
                loader = load_chromium if engine == "chromium" else load_firefox
                visits = loader(copy, browser, profile)
            except (sqlite3.Error, OSError) as e:
                errors.append(f"{browser}/{profile}: {db}: {e}")
                continue

            ordered = sorted((v for v in visits.values() if v.time),
                             key=lambda v: v.time)
            targets = [v for v in ordered if matches(v.url, target_norm, args.match)
                       and (args.include_redirect_targets or not v.is_redirect
                            or args.match != "exact")]
            targets.sort(key=lambda v: v.time, reverse=True)
            for tv in targets:
                prior = [v for v in ordered if v.time and v.time < tv.time]
                chain = build_chain(tv, visits, prior, args.depth, args.infer)
                rows = chain_rows(chain, args.localtime)
                title = (f"{browser} [{profile}]  target visit #{tv.visit_id} at "
                         f"{fmt_time(tv.time, args.localtime)}  ({len(chain)} hops)")
                results.append((tv.time, title, rows, browser, profile))
                for v in chain:  # reset per-chain link labels
                    v.link = ""

    results.sort(key=lambda r: r[0], reverse=True)
    if args.limit:
        results = results[: args.limit]

    print(f"Target: {args.url}   (normalized: {target_norm}, match={args.match})")
    print(f"Sources scanned: {len(sources)}   Chains found: {len(results)}")
    for e in errors:
        print(f"  ! {e}", file=sys.stderr)

    for _, title, rows, _, _ in results:
        print_table(title, rows, args.width)

    print("\nEvidence manifest (originals were copied, not opened):")
    for ev in evidence:
        print(f"  {ev.sha256}  {ev.size:>10}  {ev.mtime_utc}  {ev.browser}/{ev.profile}  {ev.path}")
    if any(r["linked_by"] == "INFERRED" for _, _, rows, _, _ in results for r in rows):
        print("\nNOTE: hops marked INFERRED are time-proximity guesses, not browser-recorded.")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["chain", "browser", "profile", "step", "time", "transition",
                        "linked_by", "search_keywords", "url", "title", "visit_id"])
            for n, (_, _, rows, b, p) in enumerate(results, 1):
                for r in rows:
                    w.writerow([n, b, p, r["step"], r["time"], r["transition"],
                                r["linked_by"], r["search_keywords"], r["url"],
                                r["title"], r["visit_id"]])
        print(f"\nCSV written: {args.csv}")

    if args.json:
        out = {
            "target": args.url, "normalized": target_norm, "match": args.match,
            "generated_utc": dt.datetime.now(UTC).isoformat(),
            "host": platform.node(),
            "evidence": [asdict(e) for e in evidence],
            "errors": errors,
            "chains": [{"browser": b, "profile": p, "hops": rows}
                       for _, _, rows, b, p in results],
        }
        args.json.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        print(f"JSON written: {args.json}")

    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
