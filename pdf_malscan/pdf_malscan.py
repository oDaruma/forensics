#!/usr/bin/env python3
"""
pdf_malscan.py - Static triage of PDF files for malicious indicators.

Pure standard library (Python 3.8+). Never renders or executes the PDF.
Optional: `pip install yara-python` and pass --yara rules.yar for extra matching.

What it checks
  * Structural keywords (pdfid-style), incl. #xx hex-obfuscated names (/J#61vaScript)
  * Auto-execution triggers: /OpenAction, /AA, /Launch, /JavaScript, /JS
  * Embedded files, /RichMedia (Flash), /XFA forms, /SubmitForm, /GoToR, /GoToE
  * Decompresses FlateDecode / ASCIIHex / ASCII85 streams and scans for:
      - JavaScript obfuscation & exploit primitives (eval, unescape, fromCharCode,
        util.printf, Collab.getIcon, heap-spray NOP sleds, etc.)
      - Embedded PE/ELF/Mach-O/OLE/ZIP payloads
      - Shell / PowerShell / LOLBin command lines in /Launch actions
  * URIs (flags IP-literal hosts, suspicious TLDs, URL shorteners, credential-phishing words)
  * Embedded file names with dangerous extensions
  * File-level anomalies: header offset, data after final %%EOF, polyglots,
    malformed xref, encryption, object streams hiding objects, high entropy
  * Hashes (MD5/SHA1/SHA256) for IOC lookup

Usage
  python3 pdf_malscan.py suspicious.pdf
  python3 pdf_malscan.py *.pdf --json > report.json
  python3 pdf_malscan.py file.pdf --dump-js ./js_out    # write extracted JS for review
  python3 pdf_malscan.py file.pdf --yara rules.yar

Exit codes (for SOAR / pipeline use)
  0 = clean (score < 3)   1 = suspicious (3-6)   2 = likely malicious (>= 7)   3 = error

Limitations (read these)
  * Static heuristics only: an encrypted PDF (/Encrypt with a user password) hides
    stream contents; only the structure is checked.
  * Does not decode LZW, RunLength, CCITT, JBIG2, DCT, or chained exotic filters.
  * Objects inside /ObjStm are decompressed and scanned as text, but not re-parsed as
    full objects. A clean result is NOT proof of safety - detonate in a sandbox
    if the source is untrusted.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys
import zlib
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import List, Optional

MAX_FILE_SIZE = 200 * 1024 * 1024        # refuse files > 200 MB
MAX_DECOMPRESSED = 50 * 1024 * 1024      # zip-bomb guard per stream
MAX_STREAMS = 5000

# --------------------------------------------------------------------------- #
# Indicator definitions
# --------------------------------------------------------------------------- #

# keyword -> (weight, description)
KEYWORDS = {
    "/JS":            (3, "JavaScript action"),
    "/JavaScript":    (3, "JavaScript name tree / action"),
    "/OpenAction":    (2, "Action executed when document opens"),
    "/AA":            (2, "Additional (event-triggered) actions"),
    "/Launch":        (5, "Launch action - can execute programs/files"),
    "/EmbeddedFile":  (2, "Embedded file"),
    "/RichMedia":     (3, "Rich media (Flash/video) - historic exploit vector"),
    "/XFA":           (2, "XFA form (scriptable, historic exploit vector)"),
    "/AcroForm":      (1, "Interactive form"),
    "/SubmitForm":    (2, "Form submits data to remote server"),
    "/ImportData":    (2, "Imports external data"),
    "/GoToR":         (2, "Remote GoTo - opens another (possibly remote) file"),
    "/GoToE":         (2, "GoTo embedded document"),
    "/URI":           (0, "URI action (analysed separately)"),
    "/JBIG2Decode":   (2, "JBIG2 filter - CVE-2009-0658 and FORCEDENTRY-class bugs"),
    "/Encrypt":       (1, "Encrypted - stream contents may be hidden from analysis"),
    "/ObjStm":        (1, "Object streams - can hide objects from naive parsers"),
    "/Sound":         (1, "Sound object"),
    "/Movie":         (1, "Movie object"),
    "/Rendition":     (2, "Rendition action - can trigger JS/media"),
}

JS_PATTERNS = [
    # (regex, weight, description)
    (r"\beval\s*\(", 3, "eval() - dynamic code execution"),
    (r"\bunescape\s*\(", 3, "unescape() - common shellcode decoder"),
    (r"String\.fromCharCode", 2, "String.fromCharCode - string obfuscation"),
    (r"%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}", 4, "%uXXXX unicode-encoded shellcode"),
    (r"(?:%u0c0c|%u9090|\\x0c\\x0c|\\x90\\x90|0x0c0c0c0c)", 4, "Heap-spray / NOP-sled pattern"),
    (r"util\.printf", 4, "util.printf (CVE-2008-2992)"),
    (r"Collab\.(?:getIcon|collectEmailInfo)", 4, "Collab API (CVE-2009-0927 / CVE-2007-5659)"),
    (r"\.spell\.customDictionaryOpen", 4, "spell.customDictionaryOpen (CVE-2009-1493)"),
    (r"media\.newPlayer", 4, "media.newPlayer (CVE-2009-4324)"),
    (r"getAnnots\s*\(", 2, "getAnnots() - often used to stash payloads"),
    (r"this\.exportDataObject", 3, "exportDataObject - drops embedded file to disk"),
    (r"app\.launchURL", 2, "app.launchURL - opens URL"),
    (r"(?:submitForm|app\.openDoc|this\.mailDoc|app\.mailMsg)", 2, "Data exfil / doc open API"),
    (r"\.substr\s*\(.*\.substr\s*\(", 1, "Chained substr - string obfuscation"),
    (r"new\s+Array\s*\(\s*\d{3,}", 2, "Large array allocation (heap grooming)"),
    (r"while\s*\(.*\.length\s*<\s*0x[0-9a-fA-F]{5,}", 3, "Spray loop to large length"),
    (r"ArrayBuffer|DataView|Uint32Array", 2, "Typed arrays (modern memory-corruption primitive)"),
]

LAUNCH_PATTERNS = [
    (r"cmd(?:\.exe)?\s*/[ck]", 5, "cmd.exe command execution"),
    (r"powershell|pwsh", 5, "PowerShell"),
    (r"mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec", 5, "Windows LOLBin"),
    (r"/bin/(?:ba)?sh|curl\s+|wget\s+", 4, "Unix shell / downloader"),
    (r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}", 5, "Encoded PowerShell command"),
]

MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE executable", 6, lambda d, i: d[i:i+2] == b"MZ" and b"This program" in d[i:i+200]),
    (b"\x7fELF", "ELF executable", 6, None),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable", 6, None),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (Office 97-2003) document", 3, None),
    (b"PK\x03\x04", "ZIP / OOXML / JAR archive", 2, None),
    (b"Rar!\x1a\x07", "RAR archive", 2, None),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", 2, None),
    (b"{\\rtf", "RTF document", 2, None),
    (b"CWS", "Compressed Flash (SWF)", 3, lambda d, i: i == 0),
    (b"FWS", "Flash (SWF)", 3, lambda d, i: i == 0),
]

DANGEROUS_EXT = re.compile(
    rb"\.(exe|dll|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|jar|"
    rb"docm|xlsm|pptm|iso|img|vhd|vhdx|one|chm|reg|sh|apk|dmg|pkg|zip|rar|7z)\b",
    re.I,
)

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml",
                   "cf", "ga", "work", "rest", "support", "cam", "icu", "lol"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"}
PHISH_WORDS = re.compile(r"login|signin|verify|account|secure|update|password|wallet|"
                         r"office365|microsoft|docusign|sharepoint|onedrive|invoice", re.I)

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    severity: str          # info | low | medium | high
    weight: int
    category: str
    detail: str
    evidence: Optional[str] = None


@dataclass
class Report:
    file: str
    size: int
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    pdf_version: Optional[str] = None
    keyword_counts: dict = field(default_factory=dict)
    objects: int = 0
    streams: int = 0
    streams_decoded: int = 0
    uris: List[str] = field(default_factory=list)
    embedded_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"

    def add(self, weight: int, category: str, detail: str, evidence: Optional[str] = None):
        sev = "info" if weight <= 0 else "low" if weight <= 1 else "medium" if weight <= 3 else "high"
        # de-duplicate identical findings
        for f in self.findings:
            if f.category == category and f.detail == detail:
                return
        self.findings.append(Finding(sev, weight, category, detail, evidence))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

NAME_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")


def normalise_names(data: bytes) -> tuple[bytes, int]:
    """Decode #xx escapes inside PDF names (/J#61vaScript -> /JavaScript)."""
    count = 0

    def fix_name(m: re.Match) -> bytes:
        nonlocal count
        name = m.group(0)
        if b"#" not in name:
            return name
        new = NAME_HEX.sub(lambda h: bytes([int(h.group(1), 16)]), name)
        if new != name:
            count += 1
        return new

    return re.sub(rb"/[^\s/<>\[\]()%{}]+", fix_name, data), count


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def safe_inflate(raw: bytes) -> Optional[bytes]:
    """zlib decompress with a size cap; tolerant of truncated streams."""
    for wbits in (15, -15):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(raw, MAX_DECOMPRESSED)
            if out:
                return out
        except zlib.error:
            continue
    return None


def ascii_hex_decode(raw: bytes) -> Optional[bytes]:
    s = re.sub(rb"\s", b"", raw).rstrip(b">")
    if len(s) % 2:
        s += b"0"
    try:
        return binascii.unhexlify(s)
    except (binascii.Error, ValueError):
        return None


def ascii85_decode(raw: bytes) -> Optional[bytes]:
    s = raw.strip()
    if s.startswith(b"<~"):
        s = s[2:]
    if not s.endswith(b"~>"):
        s += b"~>"
    try:
        return base64.a85decode(b"<~" + s, adobe=True)
    except Exception:
        return None


STREAM_RE = re.compile(rb"(<<(?:(?!>>\s*stream).){0,4096}?>>)\s*stream\r?\n(.*?)\r?\n?endstream",
                       re.S)


def iter_streams(data: bytes):
    """Yield (dict_bytes, decoded_bytes_or_raw, decoded_ok)."""
    for i, m in enumerate(STREAM_RE.finditer(data)):
        if i >= MAX_STREAMS:
            break
        sdict, raw = m.group(1), m.group(2)
        filters = re.findall(rb"/(FlateDecode|Fl|ASCIIHexDecode|AHx|ASCII85Decode|A85|"
                             rb"LZWDecode|LZW|RunLengthDecode|RL|DCTDecode|JBIG2Decode|"
                             rb"CCITTFaxDecode|JPXDecode|Crypt)\b", sdict)
        out, ok = raw, True
        # Filters are applied in array order
        for f in filters:
            if f in (b"FlateDecode", b"Fl"):
                r = safe_inflate(out)
            elif f in (b"ASCIIHexDecode", b"AHx"):
                r = ascii_hex_decode(out)
            elif f in (b"ASCII85Decode", b"A85"):
                r = ascii85_decode(out)
            else:
                r = None  # image / unsupported filter: stop decoding
            if r is None:
                ok = False
                break
            out = r
        yield sdict, out, ok and bool(filters)


def text_view(b: bytes, limit: int = 160) -> str:
    s = b.decode("latin-1", "replace")
    s = re.sub(r"[^\x20-\x7e]", ".", s)
    return s[:limit] + ("..." if len(s) > limit else "")


def decode_pdf_string(s: bytes) -> str:
    """Decode a literal (..) or hex <..> PDF string."""
    s = s.strip()
    if s.startswith(b"<") and not s.startswith(b"<<"):
        d = ascii_hex_decode(s[1:])
        s = d if d is not None else s
    elif s.startswith(b"(") and s.endswith(b")"):
        s = s[1:-1]
        s = re.sub(rb"\\([nrtbf()\\])",
                   lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
                              b"f": b"\f"}.get(m.group(1), m.group(1)), s)
        s = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), s)
    if s.startswith(b"\xfe\xff"):
        return s[2:].decode("utf-16-be", "replace")
    return s.decode("latin-1", "replace")


PDF_STR = rb"(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)"

# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def analyse(path: str, dump_js: Optional[str] = None, yara_rules=None) -> Report:
    size = os.path.getsize(path)
    rep = Report(file=path, size=size)
    if size > MAX_FILE_SIZE:
        rep.add(1, "file", f"File larger than {MAX_FILE_SIZE // 1048576} MB - skipped deep scan")
        return finalise(rep)

    with open(path, "rb") as fh:
        raw = fh.read()

    rep.md5 = hashlib.md5(raw).hexdigest()
    rep.sha1 = hashlib.sha1(raw).hexdigest()
    rep.sha256 = hashlib.sha256(raw).hexdigest()

    # ---- header / trailer anomalies -------------------------------------- #
    hdr = raw.find(b"%PDF-")
    if hdr == -1:
        rep.add(3, "structure", "No %PDF- header found - not a PDF or heavily malformed")
    else:
        m = re.match(rb"%PDF-(\d\.\d)", raw[hdr:hdr + 8])
        rep.pdf_version = m.group(1).decode() if m else None
        if hdr > 0:
            w = 3 if hdr > 1024 else 2
            rep.add(w, "structure", f"%PDF header at offset {hdr} (not 0) - possible polyglot/evasion",
                    text_view(raw[:min(hdr, 64)]))
        for sig, desc, w, check in MAGIC_SIGNATURES:
            if raw.startswith(sig) and (check is None or check(raw, 0)):
                rep.add(w + 1, "polyglot", f"File starts with {desc} magic but contains a PDF")

    last_eof = raw.rfind(b"%%EOF")
    if last_eof == -1:
        rep.add(1, "structure", "No %%EOF marker")
    else:
        tail = raw[last_eof + 5:].strip(b"\r\n\x00 \t")
        if len(tail) > 32:
            rep.add(3, "structure", f"{len(tail)} bytes of data after final %%EOF",
                    text_view(tail, 80))
    eofs = raw.count(b"%%EOF")
    if eofs > 1:
        rep.add(0, "structure", f"{eofs} %%EOF markers (incremental updates)")
    if b"xref" not in raw and b"/XRef" not in raw:
        rep.add(1, "structure", "No xref table or xref stream - malformed")

    # ---- keyword counts (raw + after #xx normalisation) ------------------- #
    norm, obf = normalise_names(raw)
    if obf:
        rep.add(4, "obfuscation", f"{obf} PDF name(s) obfuscated with #xx hex escapes")

    rep.objects = len(re.findall(rb"\d+\s+\d+\s+obj\b", norm))
    rep.streams = len(re.findall(rb"\bstream\r?\n", norm))

    # Also gather all decoded stream content (object streams hide dictionaries)
    decoded_blobs: List[bytes] = []
    for sdict, body, decoded in iter_streams(norm):
        if decoded:
            rep.streams_decoded += 1
            decoded_blobs.append(body)
        # embedded payload magic in any stream content
        scan_payload(rep, body, sdict)

    hay = norm + b"\n".join(normalise_names(b)[0] for b in decoded_blobs)

    for kw, (w, desc) in KEYWORDS.items():
        n = len(re.findall(re.escape(kw.encode()) + rb"(?![A-Za-z0-9])", hay))
        if n:
            rep.keyword_counts[kw] = n
            if w:
                rep.add(w, "keyword", f"{kw} x{n}: {desc}")

    has_auto = "/OpenAction" in rep.keyword_counts or "/AA" in rep.keyword_counts
    has_js = "/JS" in rep.keyword_counts or "/JavaScript" in rep.keyword_counts
    if has_auto and has_js:
        rep.add(3, "combo", "Auto-execute trigger combined with JavaScript")
    if has_auto and "/Launch" in rep.keyword_counts:
        rep.add(4, "combo", "Auto-execute trigger combined with /Launch")
    if has_auto and "/EmbeddedFile" in rep.keyword_counts and has_js:
        rep.add(3, "combo", "Auto-execute + JS + embedded file (classic dropper chain)")
    if rep.pdf_version and rep.objects and rep.objects < 4 and has_js:
        rep.add(1, "structure", "Very few objects but contains JavaScript (minimal dropper shape)")

    # ---- JavaScript extraction ------------------------------------------- #
    js_chunks = extract_js(hay, norm, decoded_blobs)
    for i, js in enumerate(js_chunks):
        scan_js(rep, js)
        if dump_js:
            os.makedirs(dump_js, exist_ok=True)
            base = os.path.basename(path)
            with open(os.path.join(dump_js, f"{base}.js{i}.txt"), "w", encoding="utf-8",
                      errors="replace") as fh:
                fh.write(js)

    # ---- Launch actions --------------------------------------------------- #
    for m in re.finditer(rb"/Launch.{0,600}", hay, re.S):
        blob = m.group(0).decode("latin-1", "replace")
        for pat, w, desc in LAUNCH_PATTERNS:
            if re.search(pat, blob, re.I):
                rep.add(w, "launch", f"/Launch action references {desc}",
                        re.sub(r"\s+", " ", blob.split("endobj")[0])[:200])

    # ---- URIs ------------------------------------------------------------- #
    for m in re.finditer(rb"/URI\s*" + PDF_STR, hay):
        uri = decode_pdf_string(m.group(1)).strip()
        if uri and uri not in rep.uris:
            rep.uris.append(uri)
    for uri in rep.uris:
        assess_uri(rep, uri)
    if len(rep.uris) > 50:
        rep.add(1, "uri", f"{len(rep.uris)} distinct URIs")

    # ---- Embedded files --------------------------------------------------- #
    for m in re.finditer(rb"/(?:UF|F)\s*" + PDF_STR, hay):
        name = decode_pdf_string(m.group(1))
        if name and name not in rep.embedded_files and len(name) < 260:
            if "/EmbeddedFile" in rep.keyword_counts or "/Launch" in rep.keyword_counts \
                    or DANGEROUS_EXT.search(name.encode("latin-1", "replace")):
                rep.embedded_files.append(name)
    for name in rep.embedded_files:
        if DANGEROUS_EXT.search(name.encode("latin-1", "replace")):
            rep.add(4, "embedded", f"Embedded/referenced file with risky extension: {name}")
        if re.search(r"\.(pdf|docx?|txt|jpg|png)\s*\.\w{2,4}$", name, re.I):
            rep.add(3, "embedded", f"Double extension: {name}")

    # ---- Entropy ---------------------------------------------------------- #
    for blob in decoded_blobs:
        if len(blob) > 4096 and entropy(blob) > 7.6 and not blob.startswith((b"\xff\xd8", b"\x89PNG")):
            rep.add(1, "entropy", f"Decoded stream ({len(blob)} B) has very high entropy "
                                  f"({entropy(blob):.2f}) - packed/encrypted payload?")
            break

    # ---- YARA ------------------------------------------------------------- #
    if yara_rules is not None:
        targets = [raw] + decoded_blobs
        hits = set()
        for t in targets:
            for mt in yara_rules.match(data=t):
                hits.add(mt.rule)
        for h in sorted(hits):
            rep.add(5, "yara", f"YARA rule matched: {h}")

    return finalise(rep)


def scan_payload(rep: Report, body: bytes, sdict: bytes):
    for sig, desc, w, check in MAGIC_SIGNATURES:
        idx = body.find(sig)
        if idx == -1 or idx > 1024:
            continue
        if check is not None and not check(body, idx):
            continue
        if sig == b"PK\x03\x04" and b"/EmbeddedFile" not in sdict:
            continue
        rep.add(w, "payload", f"Stream contains {desc} at offset {idx}",
                text_view(sdict[sdict.rfind(b"obj") + 3:] if b"obj" in sdict else sdict, 120).strip(". "))


def extract_js(hay: bytes, norm: bytes, blobs: List[bytes]) -> List[str]:
    out: List[str] = []
    # inline /JS (...) or /JS <hex>
    for m in re.finditer(rb"/JS\s*" + PDF_STR, hay, re.S):
        out.append(decode_pdf_string(m.group(1)))
    # /JS n 0 R -> look up referenced object's stream
    for m in re.finditer(rb"/JS\s+(\d+)\s+(\d+)\s+R", hay):
        oid, gen = m.group(1), m.group(2)
        om = re.search(rb"(?<!\d)" + oid + rb"\s+" + gen + rb"\s+obj\b(.*?)endobj", norm, re.S)
        if om:
            for _, body, _ in iter_streams(om.group(1)):
                out.append(body.decode("latin-1", "replace"))
    # any decoded stream that looks like JS
    for b in blobs:
        if re.search(rb"\b(?:function|var|eval|app\.|this\.|unescape)\b", b) and \
                not re.search(rb"\b(?:BT|ET|Tf|Tj|re f)\b", b[:500]):
            out.append(b.decode("latin-1", "replace"))
    # de-dup
    seen, uniq = set(), []
    for s in out:
        h = hashlib.md5(s.encode("utf-8", "replace")).hexdigest()
        if h not in seen and s.strip():
            seen.add(h)
            uniq.append(s)
    return uniq


def scan_js(rep: Report, js: str):
    for pat, w, desc in JS_PATTERNS:
        m = re.search(pat, js, re.I | re.S)
        if m:
            s = max(m.start() - 30, 0)
            rep.add(w, "javascript", desc, js[s:m.end() + 50].replace("\n", " "))
    long_str = re.search(r"[\"'][A-Za-z0-9+/%\\x]{800,}[\"']", js)
    if long_str:
        rep.add(2, "javascript", f"Very long encoded string literal ({len(long_str.group(0))} chars)")
    if js and len(js) > 2000:
        ident_ratio = len(re.findall(r"\b[a-zA-Z_$][\w$]{12,}\b", js)) / max(len(js) / 100, 1)
        if ident_ratio > 3:
            rep.add(1, "javascript", "Dense long/random identifiers - likely obfuscated")


IP_HOST = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def assess_uri(rep: Report, uri: str):
    low = uri.lower()
    if low.startswith(("file:", "smb:", "\\\\")):
        rep.add(4, "uri", "URI uses file:/SMB/UNC scheme (NTLM hash leak / local exec)", uri)
        return
    if low.startswith(("javascript:", "vbscript:", "data:")):
        rep.add(4, "uri", "Script / data scheme URI", uri[:200])
        return
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", low)
    if not m:
        return
    host = m.group(1)
    if "@" in low.split("//", 1)[-1].split("/", 1)[0]:
        rep.add(2, "uri", "URI contains userinfo '@' (deceptive host)", uri)
    if IP_HOST.match(host):
        rep.add(2, "uri", "URI points to raw IP address", uri)
    if host.startswith("xn--") or ".xn--" in host:
        rep.add(2, "uri", "Punycode (IDN) host - possible homoglyph", uri)
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        rep.add(1, "uri", f"Suspicious TLD .{host.rsplit('.', 1)[-1]}", uri)
    if host in SHORTENERS:
        rep.add(1, "uri", "URL shortener", uri)
    if PHISH_WORDS.search(uri) and not re.search(r"(?:^|\.)(microsoft|office|live|"
                                                 r"docusign|sharepoint)\.(com|net)$", host):
        rep.add(1, "uri", "Credential/brand lure keyword in URI", uri)
    if re.search(r"\.(exe|scr|hta|js|vbs|ps1|bat|msi|iso|img|lnk|zip|rar)(?:$|\?)", low):
        rep.add(3, "uri", "URI links directly to executable/archive", uri)


def finalise(rep: Report) -> Report:
    rep.score = sum(max(f.weight, 0) for f in rep.findings)
    rep.verdict = "likely malicious" if rep.score >= 7 else "suspicious" if rep.score >= 3 else "clean"
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rep.findings.sort(key=lambda f: (order[f.severity], -f.weight))
    return rep

# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m",
          "reset": "\033[0m", "bold": "\033[1m"}


def print_report(rep: Report, color: bool):
    c = COLORS if color else {k: "" for k in COLORS}
    vcol = c["high"] if rep.score >= 7 else c["medium"] if rep.score >= 3 else "\033[92m" if color else ""
    print(f"{c['bold']}=== {rep.file} ==={c['reset']}")
    print(f"  Size     : {rep.size:,} bytes   PDF version: {rep.pdf_version or '?'}")
    print(f"  SHA256   : {rep.sha256}")
    print(f"  MD5      : {rep.md5}")
    print(f"  Objects  : {rep.objects}   Streams: {rep.streams} ({rep.streams_decoded} decoded)")
    if rep.keyword_counts:
        kws = ", ".join(f"{k}={v}" for k, v in sorted(rep.keyword_counts.items()))
        print(f"  Keywords : {kws}")
    if rep.uris:
        print(f"  URIs ({len(rep.uris)}):")
        for u in rep.uris[:20]:
            print(f"     - {u}")
        if len(rep.uris) > 20:
            print(f"     ... {len(rep.uris) - 20} more")
    if rep.embedded_files:
        print(f"  Embedded : {', '.join(rep.embedded_files)}")
    print(f"  Findings :")
    if not rep.findings:
        print("     (none)")
    for f in rep.findings:
        print(f"     {c[f.severity]}[{f.severity.upper():6}]{c['reset']} (+{f.weight}) "
              f"{f.category}: {f.detail}")
        if f.evidence:
            print(f"              evidence: {f.evidence[:160]}")
    print(f"  {c['bold']}Score: {rep.score}   Verdict: {vcol}{rep.verdict.upper()}{c['reset']}\n")


def main():
    ap = argparse.ArgumentParser(description="Static malicious-content triage for PDF files.")
    ap.add_argument("files", nargs="+", help="PDF file(s) to scan")
    ap.add_argument("--json", action="store_true", help="Emit JSON (one array) instead of text")
    ap.add_argument("--dump-js", metavar="DIR", help="Write extracted JavaScript to DIR")
    ap.add_argument("--yara", metavar="RULES", help="YARA rules file (requires yara-python)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    rules = None
    if args.yara:
        try:
            import yara  # type: ignore
            rules = yara.compile(filepath=args.yara)
        except ImportError:
            print("yara-python not installed; --yara ignored", file=sys.stderr)
        except Exception as e:
            print(f"YARA compile error: {e}", file=sys.stderr)
            return 3

    reports, worst, errored = [], 0, False
    for p in args.files:
        try:
            rep = analyse(p, args.dump_js, rules)
        except (OSError, MemoryError) as e:
            print(f"[!] {p}: {e}", file=sys.stderr)
            errored = True
            continue
        reports.append(rep)
        worst = max(worst, 2 if rep.score >= 7 else 1 if rep.score >= 3 else 0)
        if not args.json:
            print_report(rep, color=sys.stdout.isatty() and not args.no_color)

    if args.json:
        print(json.dumps([asdict(r) for r in reports], indent=2))
    if errored and not reports:
        return 3
    return worst


if __name__ == "__main__":
    sys.exit(main())
