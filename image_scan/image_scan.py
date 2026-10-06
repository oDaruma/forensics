#!/usr/bin/env python3
"""
forensic_scan.py - Forensically-style image forensics from the command line.

Analyses a JPEG / PNG / GIF / PDF (plus anything else Pillow opens) and writes
an image with suspected modified or overlaid regions marked, a contact sheet
of the individual analyses, and a JSON + text report.

Re-implements the toolset of https://29a.ch/photo-forensics/ :
  magnifier, clone, ela, noise, levels (level sweep), gradient (luminance
  gradient), pca, meta, geo, thumbnail, jpeg, strings
plus `scan`, which runs everything and fuses the results into a marked image.

USAGE
  python forensic_scan.py scan photo.jpg                # full scan (default)
  python forensic_scan.py photo.jpg -o out/             # same: 'scan' is implied
  python forensic_scan.py scan invoice.pdf --dpi 200 --pages 1-2
  python forensic_scan.py scan anim.gif --frames all
  Outputs (in -o, default ./forensics_out): <name>_marked.png, <name>_sheet.png,
  <name>_report.json, <name>_report.txt
  python forensic_scan.py ela photo.jpg --quality 90 --scale 30
  python forensic_scan.py clone photo.jpg --min-similarity 0.97 --min-cluster 40
  python forensic_scan.py magnifier photo.jpg --x 400 --y 300 --zoom 6 --enhance histeq
  python forensic_scan.py levels photo.jpg --animate
  python forensic_scan.py meta photo.jpg --json
  python forensic_scan.py <tool> -h                     # every tool's options

REQUIREMENTS
  pip install pillow numpy            (required)
  pip install pymupdf                 (only for PDF input)
  exiftool on PATH                    (optional, `meta --exiftool`)

LIMITATIONS - read before relying on a result
  Every detector here is a heuristic. A marked region is a lead to examine,
  not proof of tampering, and an unmarked image is not proof of authenticity.
  * ELA is only meaningful for JPEGs (or images that were once JPEGs). High
    contrast edges and fine texture light up naturally; the scan normalises
    by local detail to reduce this, but does not remove it.
  * Noise analysis flags regions whose noise level differs from the rest of
    the image; flat skies, bokeh and heavy denoising cause false positives.
  * Clone detection finds copy-move within the same image (exact or near
    exact copies). It does not detect content pasted from another image,
    and repetitive texture (bricks, tiles, text) or two identical shapes
    (icons, logos, flat-coloured objects) can produce matches.
  * Small "?" regions in the marked image are medium confidence (often edges
    or saturated colour); large solid boxes are the stronger leads.
  * Re-saved, resized or screenshotted images lose most forensic traces.
  * PDF: rendered pages get paint-order overlay checks only (shapes/images
    drawn over text, text drawn over images, annotations, incremental
    saves); pixel tests run on each embedded image, where camera/scan traces
    live. Legitimate forms, watermarks and stamps can trigger overlay checks.
"""
from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, deque
from dataclasses import dataclass, field

try:
    import numpy as np
    from numpy.lib.stride_tricks import sliding_window_view
    from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps, ExifTags
except ImportError as e:  # pragma: no cover
    sys.exit(f"Missing dependency ({e}). Install with: pip install pillow numpy")

Image.MAX_IMAGE_PIXELS = 300_000_000

# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


@dataclass
class Item:
    """One analysable picture (a file, a GIF frame, a PDF page or embedded image)."""
    name: str
    img: Image.Image                     # RGB
    raw: bytes | None = None             # original encoded bytes when available
    fmt: str = ""
    source_img: Image.Image | None = None  # un-converted PIL image (for EXIF/info)
    overlays: list = field(default_factory=list)   # PDF overlay findings
    notes: list = field(default_factory=list)


def parse_range(spec: str | None, n: int) -> list[int]:
    """'1,3-5' -> [0,2,3,4] (1-based in, 0-based out)."""
    if not spec or spec == "all":
        return list(range(n))
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out += range(int(a) - 1, min(int(b), n))
        elif part:
            out.append(int(part) - 1)
    return [i for i in out if 0 <= i < n]


def load_items(path: str, args) -> tuple[list[Item], dict]:
    """Return analysable items and document-level info."""
    with open(path, "rb") as fh:
        raw = fh.read()
    root, ext = os.path.splitext(os.path.basename(path))
    stem = f"{root}_{ext.lstrip('.').lower()}" if ext else root   # photo_jpg, photo_png: no collisions
    doc_info: dict = {"file": os.path.abspath(path), "bytes": len(raw)}

    if raw[:5] == b"%PDF-":
        return load_pdf(path, raw, stem, args, doc_info)

    im = Image.open(io.BytesIO(raw))
    im.load()
    doc_info["format"] = im.format
    items: list[Item] = []
    n_frames = getattr(im, "n_frames", 1)
    if n_frames > 1:
        doc_info["frames"] = n_frames
        frames = parse_range(getattr(args, "frames", "1") or "1", n_frames)
        for f in frames:
            im.seek(f)
            fr = im.convert("RGB")
            items.append(Item(f"{stem}_f{f + 1}", fr, raw if f == frames[0] else None,
                              im.format, im if f == frames[0] else None))
        return items, doc_info
    items.append(Item(stem, im.convert("RGB"), raw, im.format or "", im))
    return items, doc_info


def _pymupdf():
    try:
        import pymupdf  # type: ignore
        return pymupdf
    except ImportError:
        try:
            import fitz  # type: ignore
            return fitz
        except ImportError:
            return None


def load_pdf(path, raw, stem, args, doc_info):
    doc_info["format"] = "PDF"
    eofs = raw.count(b"%%EOF")
    doc_info["incremental_updates"] = max(0, eofs - 1)
    pm = _pymupdf()
    if pm is None:
        doc_info["error"] = "PDF input needs PyMuPDF: pip install pymupdf"
        print("! " + doc_info["error"], file=sys.stderr)
        return [], doc_info
    doc = pm.open(stream=raw, filetype="pdf")
    meta = {k: v for k, v in (doc.metadata or {}).items() if v}
    doc_info["pdf_metadata"] = meta
    doc_info["pages"] = doc.page_count
    flags = []
    if doc_info["incremental_updates"]:
        flags.append(f"File was saved incrementally {doc_info['incremental_updates']} time(s) "
                     "after creation (content may have been changed after the original save).")
    if meta.get("creationDate") and meta.get("modDate") and meta["creationDate"] != meta["modDate"]:
        flags.append(f"Modified ({meta['modDate']}) after creation ({meta['creationDate']}).")
    if meta.get("creator") and meta.get("producer") and meta["creator"] != meta["producer"]:
        flags.append(f"Creator '{meta['creator']}' differs from producer '{meta['producer']}'.")
    doc_info["flags"] = flags

    items: list[Item] = []
    zoom = args.dpi / 72.0
    seen_xrefs = set()
    for pno in parse_range(args.pages, doc.page_count):
        page = doc[pno]
        pix = page.get_pixmap(matrix=pm.Matrix(zoom, zoom), alpha=False)
        img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        it = Item(f"{stem}_p{pno + 1}", img, None, "PDF-page")
        it.overlays = pdf_overlays(page, zoom, pm)
        items.append(it)
        if not args.no_embedded:
            for k, info in enumerate(page.get_images(full=True)):
                xref = info[0]
                if xref in seen_xrefs:
                    continue
                seen_xrefs.add(xref)
                try:
                    ex = doc.extract_image(xref)
                    eimg = Image.open(io.BytesIO(ex["image"]))
                    eimg.load()
                except Exception:
                    continue
                if eimg.width < 64 or eimg.height < 64:
                    continue
                items.append(Item(f"{stem}_p{pno + 1}_img{k + 1}", eimg.convert("RGB"),
                                  ex["image"], (eimg.format or ex.get("ext", "")).upper(), eimg))
    return items, doc_info


def pdf_overlays(page, zoom, pm) -> list[dict]:
    """Inspect paint order for things drawn on top of text, and text on top of images."""
    out = []
    try:
        log = page.get_bboxlog()
    except Exception:
        log = []
    painted_text, painted_images = [], []
    for kind, rect in log:
        r = pm.Rect(rect)
        if r.is_empty or r.is_infinite:
            continue
        if kind in ("fill-text", "stroke-text"):
            # text drawn over an earlier image
            for ir in painted_images:
                inter = r & ir
                if not inter.is_empty and inter.get_area() > 0.8 * r.get_area():
                    out.append({"type": "text_over_image", "rect": r, "severity": "medium",
                                "label": "TEXT ON IMAGE"})
                    break
            painted_text.append(r)
        elif kind in ("fill-image", "fill-imgmask", "fill-path", "fill-shade"):
            covered = 0
            for tr in painted_text:
                inter = r & tr
                if not inter.is_empty and inter.get_area() > 0.3 * tr.get_area():
                    covered += 1
            if covered:
                what = "image" if "im" in kind else "shape"
                out.append({"type": f"{what}_over_text", "rect": r, "severity": "high",
                            "label": f"{what.upper()} COVERS TEXT", "texts_covered": covered})
            if kind in ("fill-image", "fill-imgmask"):
                painted_images.append(r)
    for a in page.annots() or []:
        out.append({"type": "annotation", "rect": a.rect, "severity": "medium",
                    "label": f"ANNOT {a.type[1].upper()}"})
    # merge text_over_image boxes per line-ish group to avoid hundreds of boxes
    out = _merge_pdf_boxes(out, pm)
    for o in out:
        r = o.pop("rect")
        o["box"] = [int(r.x0 * zoom), int(r.y0 * zoom), int(r.x1 * zoom), int(r.y1 * zoom)]
    return out


def _merge_pdf_boxes(found, pm):
    merged = []
    for f in found:
        for m in merged:
            if m["type"] == f["type"] and not (m["rect"] & (f["rect"] + (-4, -4, 4, 4))).is_empty:
                m["rect"] |= f["rect"]
                m["count"] = m.get("count", 1) + 1
                break
        else:
            merged.append(dict(f))
    return merged


# --------------------------------------------------------------------------
# Pixel helpers
# --------------------------------------------------------------------------


def to_gray(img: Image.Image) -> np.ndarray:
    a = np.asarray(img, dtype=np.float32)
    return a[..., 0] * 0.299 + a[..., 1] * 0.587 + a[..., 2] * 0.114


def to_img(a: np.ndarray) -> Image.Image:
    return Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))


def enhance(img: Image.Image, mode: str) -> Image.Image:
    mode = (mode or "none").lower()
    if mode in ("histeq", "equalize", "histogram"):
        return ImageOps.equalize(img)
    if mode in ("autocontrast", "contrast"):
        return ImageOps.autocontrast(img, cutoff=1)
    if mode in ("autocontrast-channel", "channel", "autolevels"):
        return Image.merge(img.mode, [ImageOps.autocontrast(c, cutoff=1) for c in img.split()])
    return img


def sobel(g: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    p = np.pad(g, 1, mode="edge")
    gx = (p[:-2, 2:] + 2 * p[1:-1, 2:] + p[2:, 2:]) - (p[:-2, :-2] + 2 * p[1:-1, :-2] + p[2:, :-2])
    gy = (p[2:, :-2] + 2 * p[2:, 1:-1] + p[2:, 2:]) - (p[:-2, :-2] + 2 * p[:-2, 1:-1] + p[:-2, 2:])
    return gx, gy


def block_reduce(a: np.ndarray, b: int, fn=np.mean) -> np.ndarray:
    h, w = a.shape[0] // b * b, a.shape[1] // b * b
    v = a[:h, :w].reshape(h // b, b, w // b, b)
    return fn(v, axis=(1, 3))


def detail_residual_z(value: np.ndarray, detail: np.ndarray) -> np.ndarray:
    """Robust z-score of log(value) after regressing out log(detail).

    Edges and texture raise both ELA and noise naturally; fitting the expected
    level for each block's detail and scoring the residual keeps the map from
    simply lighting up every edge."""
    x, y = np.log1p(detail).ravel(), np.log1p(value).ravel()
    keep = np.ones_like(x, bool)
    coef = np.array([0.0, float(np.median(y))])
    for _ in range(3):
        if keep.sum() < 10 or np.ptp(x[keep]) < 1e-6:
            break
        coef = np.polyfit(x[keep], y[keep], 1)
        r = y - np.polyval(coef, x)
        mad = np.median(np.abs(r[keep] - np.median(r[keep]))) * 1.4826 + 1e-6
        keep = np.abs(r - np.median(r[keep])) < 3 * mad
    return robust_z((y - np.polyval(coef, x)).reshape(value.shape))


def robust_z(x: np.ndarray) -> np.ndarray:
    med = np.median(x)
    mad = np.median(np.abs(x - med)) * 1.4826 + 1e-6
    return (x - med) / mad


def fit(img: Image.Image, max_dim: int) -> tuple[Image.Image, float]:
    s = min(1.0, max_dim / max(img.size))
    if s < 1.0:
        img = img.resize((max(1, round(img.width * s)), max(1, round(img.height * s))), Image.LANCZOS)
    return img, s


# --------------------------------------------------------------------------
# The twelve tools
# --------------------------------------------------------------------------


def tool_magnifier(img, x=None, y=None, radius=40, zoom=4, enhance_mode="histeq"):
    x = img.width // 2 if x is None else x
    y = img.height // 2 if y is None else y
    box = (max(0, x - radius), max(0, y - radius), min(img.width, x + radius), min(img.height, y + radius))
    crop = enhance(img.crop(box), enhance_mode)
    return crop.resize((crop.width * zoom, crop.height * zoom), Image.NEAREST)


def tool_ela(img, quality=75, scale=20.0):
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    re_img = Image.open(buf).convert("RGB")
    diff = np.abs(np.asarray(img, np.float32) - np.asarray(re_img, np.float32))
    err = diff.max(axis=2)
    return to_img(diff * scale), err


def tool_noise(img, amplitude=10.0, equalize=False, radius=3):
    med = img.filter(ImageFilter.MedianFilter(radius))
    res = np.abs(np.asarray(img, np.float32) - np.asarray(med, np.float32))
    vis = to_img(res * amplitude)
    if equalize:
        vis = ImageOps.equalize(vis)
    return vis, res.mean(axis=2)


def tool_levels(img, sweep=128, width=32, intensity=1.0):
    a = np.asarray(img, np.float32)
    lo = sweep - width / 2.0
    out = (a - lo) / max(width, 1) * 255.0 * intensity
    return to_img(out)


def tool_gradient(img, intensity=1.0):
    gx, gy = sobel(to_gray(img))
    k = intensity / 8.0
    mag = np.hypot(gx, gy)
    out = np.dstack([128 + gx * k, 128 + gy * k, mag * k])
    return to_img(out)


def tool_pca(img, component=1, mode="projection", linear=False, invert=False, enhance_mode="none"):
    a = np.asarray(img, np.float32)
    X = a.reshape(-1, 3)
    mu = X.mean(0)
    C = np.cov((X - mu).T)
    vals, vecs = np.linalg.eigh(C)
    vecs = vecs[:, ::-1]
    v = vecs[:, component - 1]
    p = (X - mu) @ v
    if mode == "projection":
        out = p
    elif mode == "difference":
        recon = np.outer(p, v)
        out = np.abs((X - mu) - recon).sum(1)
    else:  # distance
        recon = np.outer(p, v)
        out = np.linalg.norm((X - mu) - recon, axis=1)
    if linear:
        out = (out + 128.0) if mode == "projection" else out
    else:
        lo, hi = np.percentile(out, [0.5, 99.5])
        out = (out - lo) / max(hi - lo, 1e-6) * 255.0
    if invert:
        out = 255.0 - out
    res = to_img(out.reshape(a.shape[:2])).convert("RGB")
    return enhance(res, enhance_mode)


def tool_clone(img, block=8, min_similarity=0.985, max_diff=6.0, min_detail=4.0,
               min_distance=None, min_cluster=25, max_size=512, neighbors=10, step=1):
    """Copy-move detection by sorted block matching. Returns (clusters, scale)."""
    if block % 4:
        raise ValueError("--block must be a multiple of 4")
    small, s = fit(img, max_size)
    g = to_gray(small)
    if g.shape[0] < block * 2 or g.shape[1] < block * 2:
        return [], s
    win = sliding_window_view(g, (block, block))[::step, ::step]
    gh, gw = win.shape[:2]
    blocks = win.reshape(gh * gw, block * block).astype(np.float32)
    ys, xs = np.mgrid[0:gh, 0:gw]
    ys, xs = (ys.ravel() * step).astype(np.int32), (xs.ravel() * step).astype(np.int32)
    # remove each block's best-fit plane so smooth gradients (which correlate
    # with every other gradient) don't count as detail or as matches
    yy, xx = np.mgrid[0:block, 0:block]
    A = np.stack([np.ones(block * block), xx.ravel(), yy.ravel()], 1).astype(np.float32)
    proj = A @ np.linalg.pinv(A)
    resid = blocks - blocks @ proj
    std = resid.std(1)
    keep = std >= min_detail
    blocks, resid, ys, xs = blocks[keep], resid[keep], ys[keep], xs[keep]
    if len(blocks) < 2:
        return [], s
    p = block // 4
    feat = blocks.reshape(-1, 4, p, 4, p).mean(axis=(2, 4)).reshape(-1, 16)
    fq = np.round(feat / 4.0).astype(np.int16)
    order = np.lexsort(fq.T[::-1])
    c = resid / (np.linalg.norm(resid, axis=1, keepdims=True) + 1e-6)
    min_distance = min_distance or block * 2
    pairs = []
    for k in range(1, neighbors + 1):
        i, j = order[:-k], order[k:]
        dx, dy = xs[j] - xs[i], ys[j] - ys[i]
        far = (dx * dx + dy * dy) >= min_distance * min_distance
        i, j, dx, dy = i[far], j[far], dx[far], dy[far]
        if not len(i):
            continue
        ncc = np.einsum("ij,ij->i", c[i], c[j])
        mad = np.abs(blocks[i] - blocks[j]).mean(1)
        ok = (ncc >= min_similarity) & (mad <= max_diff)
        i, j, dx, dy = i[ok], j[ok], dx[ok], dy[ok]
        flip = (dy < 0) | ((dy == 0) & (dx < 0))
        i2, j2 = np.where(flip, j, i), np.where(flip, i, j)
        pairs.append(np.stack([i2, j2, np.where(flip, -dx, dx), np.where(flip, -dy, dy)], 1))
    if not pairs:
        return [], s
    P = np.unique(np.concatenate(pairs), axis=0)
    shifts = Counter(map(tuple, P[:, 2:4]))
    # merge shifts within +-1 px into the most populous one
    groups: dict = {}
    for sh, n in shifts.most_common():
        for g0 in groups:
            if abs(g0[0] - sh[0]) <= 1 and abs(g0[1] - sh[1]) <= 1:
                groups[g0].append(sh)
                break
        else:
            groups[sh] = [sh]
    clusters = []
    for g0, members in groups.items():
        mset = set(members)
        sel = np.array([tuple(r) in mset for r in P[:, 2:4]])
        if sel.sum() < min_cluster:
            continue
        src = np.stack([xs[P[sel, 0]], ys[P[sel, 0]]], 1)
        dst = np.stack([xs[P[sel, 1]], ys[P[sel, 1]]], 1)
        # a real copied region has 2-D extent; matches strung along a single
        # straight edge (common at boundaries and in text) are discarded
        iqr = np.percentile(src, 75, axis=0) - np.percentile(src, 25, axis=0)
        if iqr.min() < block:
            continue
        inv = 1.0 / s
        clusters.append({
            "shift": [int(g0[0] * inv), int(g0[1] * inv)],
            "blocks": int(sel.sum()),
            "src": (src * inv).astype(int).tolist(),
            "dst": (dst * inv).astype(int).tolist(),
            "block_px": int(math.ceil(block * inv)),
        })
    clusters.sort(key=lambda c_: -c_["blocks"])
    return clusters, s


def bbox_of(points, bpx):
    """Bounding box of matched blocks, ignoring the outermost 3% (stray matches)."""
    a = np.asarray(points, float)
    lo = np.percentile(a, 3, axis=0) if len(a) > 30 else a.min(0)
    hi = np.percentile(a, 97, axis=0) if len(a) > 30 else a.max(0)
    return [int(lo[0]), int(lo[1]), int(hi[0] + bpx), int(hi[1] + bpx)]


def draw_clone(img, clusters, max_lines=150):
    out = img.copy().convert("RGB")
    d = ImageDraw.Draw(out, "RGBA")
    palette = [(255, 60, 60), (60, 200, 255), (255, 200, 0), (180, 90, 255), (60, 255, 120)]
    for n, cl in enumerate(clusters):
        col = palette[n % len(palette)]
        b = cl["block_px"]
        for (sx, sy), (tx, ty) in zip(cl["src"], cl["dst"]):
            d.rectangle([sx, sy, sx + b, sy + b], fill=col + (60,))
            d.rectangle([tx, ty, tx + b, ty + b], fill=col + (60,))
        stride = max(1, len(cl["src"]) // max_lines)
        for (sx, sy), (tx, ty) in list(zip(cl["src"], cl["dst"]))[::stride]:
            d.line([sx + b / 2, sy + b / 2, tx + b / 2, ty + b / 2], fill=col + (160,), width=1)
    return out


TAGS = ExifTags.TAGS
GPSTAGS = ExifTags.GPSTAGS
EDITORS = ("photoshop", "gimp", "lightroom", "affinity", "pixelmator", "snapseed", "paint.net",
           "picsart", "canva", "facetune", "fotor", "illustrator", "acrobat", "inkscape")


def _clean(v):
    if isinstance(v, bytes):
        t = v.rstrip(b"\x00")
        try:
            s = t.decode("utf-8")
            return s if s.isprintable() else f"<{len(v)} bytes>"
        except UnicodeDecodeError:
            return f"<{len(v)} bytes>"
    if isinstance(v, tuple):
        return [_clean(x) for x in v]
    if isinstance(v, (int, str, float)) or v is None:
        return v
    try:
        return float(v)
    except Exception:
        return str(v)


def tool_meta(item: Item, use_exiftool=False, path=None):
    src = item.source_img
    out: dict = {"format": item.fmt, "size": list(item.img.size)}
    flags = []
    if src is not None:
        out["mode"] = src.mode
        out["info"] = {k: _clean(v) for k, v in src.info.items()
                       if k not in ("exif", "icc_profile", "xmp", "XML:com.adobe.xmp")}
        if "icc_profile" in src.info:
            icc = src.info["icc_profile"]
            out["icc_profile_bytes"] = len(icc)
            m = re.search(rb"desc.{8}(.{4,64}?)\x00", icc, re.S)
            if m:
                out["icc_desc"] = _clean(m.group(1))
        try:
            ex = src.getexif()
        except Exception:
            ex = {}
        if ex:
            out["exif"] = {TAGS.get(k, hex(k)): _clean(v) for k, v in ex.items() if k not in (0x8769, 0x8825, 0xA005)}
            for ifd, name, tagmap in ((0x8769, "exif_ifd", TAGS), (0x8825, "gps", GPSTAGS), (0xA005, "interop", TAGS)):
                try:
                    sub = ex.get_ifd(ifd)
                except Exception:
                    sub = {}
                if sub:
                    out[name] = {tagmap.get(k, hex(k)): _clean(v) for k, v in sub.items() if k != 0x927C}
    if item.raw:
        m = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", item.raw, re.S)
        if m:
            xmp = m.group(0).decode("utf-8", "replace")
            out["xmp_bytes"] = len(xmp)
            hist = re.findall(r'stEvt:softwareAgent="([^"]+)"', xmp) + re.findall(r"<xmp:CreatorTool>([^<]+)<", xmp)
            if hist:
                out["xmp_software"] = sorted(set(hist))
            if "photoshop:" in xmp or "stEvt:action" in xmp:
                flags.append("XMP contains an editing history.")
    sw = " ".join(str(x) for x in [out.get("exif", {}).get("Software", ""), *out.get("xmp_software", [])]).lower()
    for e in EDITORS:
        if e in sw:
            flags.append(f"Edited with / saved by editing software: '{e}'.")
            break
    dt = out.get("exif", {}).get("DateTime")
    dto = out.get("exif_ifd", {}).get("DateTimeOriginal")
    if dt and dto and dt != dto:
        flags.append(f"DateTime ({dt}) differs from DateTimeOriginal ({dto}): file was re-saved after capture.")
    if src is not None and item.fmt == "JPEG" and "exif" not in out:
        flags.append("No EXIF data (stripped, screenshot, or exported by an app/website).")
    if use_exiftool and path and shutil.which("exiftool"):
        try:
            r = subprocess.run(["exiftool", "-j", "-G", path], capture_output=True, text=True, timeout=60)
            out["exiftool"] = json.loads(r.stdout)[0]
        except Exception as e:
            out["exiftool_error"] = str(e)
    out["flags"] = flags
    return out


def _dms(v, ref):
    try:
        d, m, s = (float(x) for x in v)
    except Exception:
        return None
    dec = d + m / 60 + s / 3600
    return -dec if str(ref).upper() in ("S", "W") else dec


def tool_geo(meta: dict):
    g = meta.get("gps") or {}
    lat = _dms(g.get("GPSLatitude"), g.get("GPSLatitudeRef", "N")) if g.get("GPSLatitude") else None
    lon = _dms(g.get("GPSLongitude"), g.get("GPSLongitudeRef", "E")) if g.get("GPSLongitude") else None
    if lat is None or lon is None:
        return {"present": False}
    return {"present": True, "lat": round(lat, 6), "lon": round(lon, 6),
            "altitude": g.get("GPSAltitude"), "timestamp": g.get("GPSDateStamp"),
            "map": f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"}


def exif_thumbnail_bytes(item: Item) -> bytes | None:
    tiff = None
    if item.source_img is not None and item.source_img.info.get("exif"):
        tiff = item.source_img.info["exif"]
    elif item.raw:
        i = item.raw.find(b"Exif\x00\x00")
        if i >= 0:
            tiff = item.raw[i:]
    if not tiff:
        return None
    if tiff[:6] == b"Exif\x00\x00":
        tiff = tiff[6:]
    try:
        bo = "<" if tiff[:2] == b"II" else ">"
        off = struct.unpack(bo + "I", tiff[4:8])[0]
        n = struct.unpack(bo + "H", tiff[off:off + 2])[0]
        nxt = struct.unpack(bo + "I", tiff[off + 2 + 12 * n: off + 6 + 12 * n])[0]
        if not nxt:
            return None
        n1 = struct.unpack(bo + "H", tiff[nxt:nxt + 2])[0]
        tags = {}
        for e in range(n1):
            p = nxt + 2 + 12 * e
            tag, typ, cnt = struct.unpack(bo + "HHI", tiff[p:p + 8])
            val = struct.unpack(bo + ("H" if typ == 3 else "I"), tiff[p + 8:p + (10 if typ == 3 else 12)])[0]
            tags[tag] = val
        if 0x0201 in tags and 0x0202 in tags:
            data = tiff[tags[0x0201]: tags[0x0201] + tags[0x0202]]
            return data if data[:2] == b"\xff\xd8" else None
    except Exception:
        return None
    return None


def tool_thumbnail(item: Item, threshold=12.0):
    data = exif_thumbnail_bytes(item)
    if not data:
        return {"present": False}, None, None
    th = Image.open(io.BytesIO(data)).convert("RGB")
    main_ar, th_ar = item.img.width / item.img.height, th.width / th.height
    res = {"present": True, "size": list(th.size), "aspect_main": round(main_ar, 3), "aspect_thumb": round(th_ar, 3)}
    ref = item.img.resize(th.size, Image.LANCZOS)
    diff = np.abs(np.asarray(ref, np.float32) - np.asarray(th, np.float32))
    res["mean_diff"] = round(float(diff.mean()), 2)
    flags = []
    if abs(main_ar - th_ar) > 0.02:
        flags.append("Embedded thumbnail has a different aspect ratio: image was cropped after the thumbnail was made.")
    if res["mean_diff"] > threshold:
        flags.append(f"Embedded thumbnail differs from the image (mean diff {res['mean_diff']}): image content changed after capture.")
    res["flags"] = flags
    dimg = to_img(diff * 4).resize((th.width * 3, th.height * 3), Image.NEAREST)
    return res, th, dimg


ZZ = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
      35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
STD_LUM = np.array([16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
                    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
                    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99], float)
STD_CHR = np.full(64, 99.0)
STD_CHR[[0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 24, 25]] = [17, 18, 24, 47, 18, 21, 26, 66, 24, 26, 56, 47, 66]


def _std_table(base, q):
    s = 5000 / q if q < 50 else 200 - 2 * q
    return np.clip(np.floor((base * s + 50) / 100), 1, 255)


def estimate_quality(table: np.ndarray, base: np.ndarray):
    ratio = (table * 100.0 / base).mean()
    q = (200 - ratio) / 2 if ratio <= 100 else 5000 / ratio
    q = int(round(min(100, max(1, q))))
    exact = bool(np.array_equal(_std_table(base, q), table))
    return q, exact


def tool_jpeg(raw: bytes | None, show_tables=False):
    if not raw or raw[:2] != b"\xff\xd8":
        return {"is_jpeg": False}
    i, out = 2, {"is_jpeg": True, "segments": [], "quant_tables": {}, "flags": []}
    tables = {}
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            break
        m = raw[i + 1]
        i += 2
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7 or m == 0xFF:
            if m == 0xFF:
                i -= 1
            continue
        if m == 0xD9:
            break
        L = struct.unpack(">H", raw[i:i + 2])[0]
        seg = raw[i + 2:i + L]
        name = f"0x{m:02X}"
        if m == 0xDB:
            name, j = "DQT", 0
            while j < len(seg):
                pq, tq = seg[j] >> 4, seg[j] & 15
                j += 1
                n = 128 if pq else 64
                vals = np.frombuffer(seg[j:j + n], ">u2" if pq else "u1").astype(float)
                j += n
                nat = np.zeros(64)
                nat[ZZ] = vals
                tables[tq] = nat
        elif m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            name = "SOF%d" % (m - 0xC0)
            out["progressive"] = m in (0xC2, 0xC6, 0xCA, 0xCE)
            _, h, w, nc = struct.unpack(">BHHB", seg[:6])
            comps = [(seg[6 + 3 * k], seg[7 + 3 * k] >> 4, seg[7 + 3 * k] & 15, seg[8 + 3 * k]) for k in range(nc)]
            out["dimensions"] = [w, h]
            out["components"] = nc
            if nc == 3:
                (_, yh, yv, _), (_, ch, cv, _) = comps[0], comps[1]
                out["subsampling"] = {(1, 1): "4:4:4", (2, 1): "4:2:2", (2, 2): "4:2:0", (1, 2): "4:4:0"}.get(
                    (yh // ch, yv // cv), f"{yh}x{yv}/{ch}x{cv}")
        elif m == 0xC4:
            name = "DHT"
        elif m == 0xFE:
            name = "COM"
            out.setdefault("comments", []).append(_clean(seg))
        elif 0xE0 <= m <= 0xEF:
            ident = seg.split(b"\x00", 1)[0][:24]
            name = f"APP{m - 0xE0}:{_clean(ident)}"
        elif m == 0xDA:
            out["segments"].append("SOS")
            break
        out["segments"].append(name)
        i += L
    eoi = raw.rfind(b"\xff\xd9")
    out["scans"] = raw.count(b"\xff\xda")
    trailing = len(raw) - eoi - 2 if eoi > 0 else 0
    out["trailing_bytes_after_eoi"] = trailing
    if trailing > 16:
        out["flags"].append(f"{trailing} bytes of data after the end-of-image marker (appended/hidden data).")
    for tq, t in sorted(tables.items()):
        base = STD_LUM if tq == 0 else STD_CHR
        q, exact = estimate_quality(t, base)
        entry = {"estimated_quality": q, "standard_libjpeg_table": exact}
        if show_tables:
            entry["table"] = t.reshape(8, 8).astype(int).tolist()
        out["quant_tables"][str(tq)] = entry
    if "0" in out["quant_tables"]:
        out["estimated_quality"] = out["quant_tables"]["0"]["estimated_quality"]
        if not out["quant_tables"]["0"]["standard_libjpeg_table"]:
            out["notes"] = "Custom quantisation tables (camera firmware or editors such as Photoshop use these)."
    if any(s.startswith("APP13") for s in out["segments"]):
        out["flags"].append("APP13 Photoshop segment present.")
    return out


def tool_strings(raw: bytes, min_len=6, encoding="ascii", grep=None, limit=None):
    pats = []
    if encoding in ("ascii", "both"):
        pats.append(("ascii", re.compile(rb"[\x20-\x7e]{%d,}" % min_len)))
    if encoding in ("utf16", "both"):
        pats.append(("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)))
    rg = re.compile(grep, re.I) if grep else None
    res = []
    for enc, p in pats:
        for m in p.finditer(raw):
            s = m.group(0).decode("utf-16le" if enc == "utf16le" else "ascii", "replace")
            if rg and not rg.search(s):
                continue
            res.append({"offset": m.start(), "enc": enc, "text": s})
    res.sort(key=lambda r: r["offset"])
    return res[:limit] if limit else res


# --------------------------------------------------------------------------
# Fusion scan
# --------------------------------------------------------------------------


def components(mask: np.ndarray) -> list[list[tuple[int, int]]]:
    seen = np.zeros_like(mask, bool)
    comps = []
    H, W = mask.shape
    for y0, x0 in zip(*np.nonzero(mask)):
        if seen[y0, x0]:
            continue
        q, comp = deque([(y0, x0)]), []
        seen[y0, x0] = True
        while q:
            y, x = q.popleft()
            comp.append((y, x))
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    ny, nx = y + dy, x + dx
                    if 0 <= ny < H and 0 <= nx < W and mask[ny, nx] and not seen[ny, nx]:
                        seen[ny, nx] = True
                        q.append((ny, nx))
        comps.append(comp)
    return comps


def get_font(size):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def scan_item(item: Item, args, path: str) -> dict:
    img_full = item.img
    work, s = fit(img_full, args.max_dim)
    inv = 1.0 / s
    B = args.block
    is_jpeg = (item.fmt or "").upper() in ("JPEG", "JPG", "MPO")
    report: dict = {"name": item.name, "format": item.fmt, "size": list(img_full.size), "regions": [], "flags": []}
    pixel = not (item.fmt == "PDF-page" and not args.pixel_pages)
    if not pixel:
        report["flags"].append("Rendered PDF page: pixel tests skipped (vector text/graphics have no camera traces); "
                               "embedded images are analysed separately. Use --pixel-pages to force.")

    # detail = strongest per-channel gradient, so saturated colour edges with
    # little luminance change (which ELA shows strongly) count as detail too
    wa = np.asarray(work, np.float32)
    grad = np.max([np.hypot(*sobel(wa[..., ch])) for ch in range(3)], axis=0)
    detail = block_reduce(grad, B)

    ela_vis, err = tool_ela(work, args.quality, args.ela_scale)
    ela_b = block_reduce(err, B)
    z_ela = detail_residual_z(ela_b, detail)

    noise_vis, res = tool_noise(work, args.noise_amp, True)
    noise_b = block_reduce(res, B, np.mean)
    z_noise = detail_residual_z(noise_b, detail)
    textured = detail > np.percentile(detail, 25)

    w_ela = 1.0 if (is_jpeg or args.force_ela) else 0.35
    if pixel and not (is_jpeg or args.force_ela):
        report["flags"].append("Not a JPEG: ELA weighted down (only meaningful if the image was once a JPEG).")
    score = np.maximum(w_ela * z_ela, 0) + 0.7 * np.maximum(np.abs(z_noise) * textured, 0)
    ela_mask = (w_ela * z_ela) > args.threshold
    noise_mask = (np.abs(z_noise) > args.threshold + 1) & textured
    if not pixel:
        score[:] = 0
        ela_mask[:] = False
        noise_mask[:] = False
    min_blocks = args.min_region

    def add_regions(mask, kind, zmap):
        for comp in components(mask):
            if len(comp) < min_blocks:
                continue
            ys_, xs_ = zip(*comp)
            box = [int(min(xs_) * B * inv), int(min(ys_) * B * inv),
                   int((max(xs_) + 1) * B * inv), int((max(ys_) + 1) * B * inv)]
            zs = [abs(zmap[y, x]) for y, x in comp]
            peak, mean = float(max(zs)), float(np.mean(zs))
            # small isolated hot-spots are usually edges/texture; large coherent
            # regions with a high mean score are the stronger lead
            conf = "high" if (len(comp) >= 8 and mean > args.threshold * 1.25) else "medium"
            report["regions"].append({"type": kind, "box": box, "blocks": len(comp), "score": round(mean, 1),
                                      "peak": round(peak, 1), "confidence": conf})
    add_regions(ela_mask, "ela", z_ela)
    add_regions(noise_mask, "noise", z_noise)

    clusters = []
    if pixel and not args.no_clone:
        clusters, _ = tool_clone(img_full, block=args.clone_block, min_similarity=args.min_similarity,
                                 min_cluster=args.min_cluster, max_size=args.clone_max_size)
        for n, cl in enumerate(clusters):
            report["regions"].append({"type": "clone_source", "box": bbox_of(cl["src"], cl["block_px"]),
                                      "blocks": cl["blocks"], "cluster": n + 1, "shift": cl["shift"], "confidence": "high"})
            report["regions"].append({"type": "clone_copy", "box": bbox_of(cl["dst"], cl["block_px"]),
                                      "blocks": cl["blocks"], "cluster": n + 1, "shift": cl["shift"], "confidence": "high"})

    for o in item.overlays:
        report["regions"].append({"type": "pdf_" + o["type"], "box": o["box"], "confidence": o["severity"],
                                  "label": o["label"], **({"count": o["count"]} if "count" in o else {})})

    meta = tool_meta(item, False, path)
    jpeg = tool_jpeg(item.raw) if item.raw else {"is_jpeg": False}
    thumb, th_img, th_diff = tool_thumbnail(item)
    report["metadata_flags"] = meta.get("flags", [])
    report["jpeg"] = {k: jpeg[k] for k in ("estimated_quality", "subsampling", "progressive", "trailing_bytes_after_eoi", "segments") if k in jpeg}
    report["flags"] += meta.get("flags", []) + jpeg.get("flags", []) + thumb.get("flags", [])
    report["geo"] = tool_geo(meta)
    report["thumbnail"] = thumb

    # ---- marked image
    marked = img_full.copy()
    heat = np.clip(score / (args.threshold * 2), 0, 1)
    heat_img = Image.fromarray((heat * 255).astype(np.uint8)).resize(img_full.size, Image.BILINEAR)
    red = Image.new("RGB", img_full.size, (255, 0, 0))
    marked = Image.composite(red, marked, heat_img.point(lambda v: int(v * 0.45)))
    d = ImageDraw.Draw(marked)
    lw = max(2, round(max(img_full.size) / 500))
    font = get_font(max(12, round(max(img_full.size) / 70)))
    colours = {"ela": (255, 40, 40), "noise": (255, 160, 0), "clone_source": (0, 200, 255),
               "clone_copy": (0, 120, 255), "pdf": (200, 0, 255)}
    for r in report["regions"]:
        col = colours.get(r["type"], colours["pdf"] if r["type"].startswith("pdf_") else (255, 255, 0))
        label = r.get("label") or {
            "ela": "ELA", "noise": "NOISE", "clone_source": f"CLONE {r.get('cluster')} SRC",
            "clone_copy": f"CLONE {r.get('cluster')} COPY"}.get(r["type"], r["type"].upper())
        x0, y0, x1, y1 = r["box"]
        d.rectangle([x0, y0, x1, y1], outline=col, width=lw if r.get("confidence") == "high" else max(1, lw // 2))
        if r.get("confidence") != "high":
            label += "?"
        tb = d.textbbox((x0, y0), label, font=font)
        ty = y0 - (tb[3] - tb[1]) - 4 if y0 > (tb[3] - tb[1]) + 4 else y1 + 2
        d.rectangle([x0, ty, x0 + tb[2] - tb[0] + 6, ty + tb[3] - tb[1] + 4], fill=col)
        d.text((x0 + 3, ty), label, fill=(0, 0, 0), font=font)
    for cl in clusters[:5]:
        b = cl["block_px"]
        sb, db = bbox_of(cl["src"], b), bbox_of(cl["dst"], b)
        d.line([(sb[0] + sb[2]) / 2, (sb[1] + sb[3]) / 2, (db[0] + db[2]) / 2, (db[1] + db[3]) / 2],
               fill=(0, 200, 255), width=lw)

    n_reg = len(report["regions"])
    hi = sum(1 for r in report["regions"] if r.get("confidence") == "high")
    verdict = ("No strong pixel-level indicators found" if n_reg == 0 else
               f"{n_reg} suspicious region(s), {hi} high-confidence")
    report["verdict"] = verdict
    banner_h = font.size + 14 if hasattr(font, "size") else 26
    canvas = Image.new("RGB", (marked.width, marked.height + banner_h), (20, 20, 24))
    canvas.paste(marked, (0, banner_h))
    ImageDraw.Draw(canvas).text((8, 6), f"{item.name}: {verdict}. Heuristic leads only, verify manually.",
                                fill=(255, 255, 255), font=font)

    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, item.name)
    canvas.save(base + "_marked.png")
    report["outputs"] = {"marked": base + "_marked.png"}

    # ---- contact sheet
    if not args.no_sheet:
        tiles = [("Original", work), ("Marked", canvas.resize(work.size)),
                 (f"ELA q{args.quality}", ela_vis), ("Noise", noise_vis),
                 ("Luminance gradient", tool_gradient(work)), ("PCA 2nd component", tool_pca(work, 2)),
                 ("Clone detection", draw_clone(work, [_scale_cluster(c, s) for c in clusters])),
                 ("Level sweep 128", tool_levels(work))]
        if th_img is not None:
            tiles.append(("EXIF thumbnail diff", th_diff))
        sheet = contact_sheet(tiles)
        sheet.save(base + "_sheet.png")
        report["outputs"]["sheet"] = base + "_sheet.png"
    return report


def _scale_cluster(c, s):
    return {**c, "src": [[int(x * s), int(y * s)] for x, y in c["src"]],
            "dst": [[int(x * s), int(y * s)] for x, y in c["dst"]], "block_px": max(1, int(c["block_px"] * s))}


def contact_sheet(tiles, tile_w=480, cols=3):
    font = get_font(16)
    cells = []
    for title, im in tiles:
        im = im.convert("RGB")
        r = tile_w / im.width
        cells.append((title, im.resize((tile_w, max(1, int(im.height * r))), Image.LANCZOS)))
    rows = [cells[i:i + cols] for i in range(0, len(cells), cols)]
    heights = [max(c[1].height for c in row) + 28 for row in rows]
    sheet = Image.new("RGB", (cols * (tile_w + 8) + 8, sum(heights) + 8), (24, 24, 28))
    d = ImageDraw.Draw(sheet)
    y = 8
    for row, h in zip(rows, heights):
        for k, (title, im) in enumerate(row):
            x = 8 + k * (tile_w + 8)
            d.text((x, y + 4), title, fill=(230, 230, 230), font=font)
            sheet.paste(im, (x, y + 26))
        y += h
    return sheet


def text_report(doc_info, reports) -> str:
    L = [f"Forensic scan: {doc_info.get('file')}", f"Format: {doc_info.get('format')}  Size: {doc_info.get('bytes')} bytes", ""]
    for f in doc_info.get("flags", []):
        L.append(f"  [document] {f}")
    if doc_info.get("error"):
        L.append(f"  ERROR: {doc_info['error']}")
    for r in reports:
        L += ["", f"== {r['name']} ({r['format']}, {r['size'][0]}x{r['size'][1]}) ==", f"Verdict: {r['verdict']}"]
        if r.get("jpeg"):
            j = r["jpeg"]
            L.append(f"JPEG: quality~{j.get('estimated_quality')} subsampling={j.get('subsampling')} "
                     f"progressive={j.get('progressive')} trailing={j.get('trailing_bytes_after_eoi')}")
        if r["geo"].get("present"):
            L.append(f"GPS: {r['geo']['lat']}, {r['geo']['lon']}  {r['geo']['map']}")
        for f in r["flags"]:
            L.append(f"  ! {f}")
        for g in r["regions"]:
            extra = f" shift={g['shift']}" if "shift" in g else ""
            L.append(f"  - {g['type']:<22} box={g['box']} confidence={g.get('confidence')}{extra}")
        for k, v in r.get("outputs", {}).items():
            L.append(f"  -> {k}: {v}")
    L += ["", "All findings are heuristic leads, not proof. See the script header for limitations."]
    return "\n".join(L)


def _jsonable(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

TOOLS = ("scan", "magnifier", "clone", "ela", "noise", "levels", "gradient", "pca",
         "meta", "geo", "thumbnail", "jpeg", "strings")


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("input", help="image or PDF file")
    common.add_argument("-o", "--outdir", default="forensics_out", help="output directory (default: forensics_out)")
    common.add_argument("--pages", default="all", help="PDF pages, e.g. '1,3-5' (default: all)")
    common.add_argument("--dpi", type=int, default=150, help="PDF render resolution (default: 150)")
    common.add_argument("--no-embedded", action="store_true", help="PDF: do not analyse embedded images separately")
    common.add_argument("--frames", default="1", help="GIF/animated frames to analyse, e.g. '1-3' or 'all' (default: 1)")

    p = argparse.ArgumentParser(description="Forensically-style image forensics.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("USAGE")[1].split("REQUIREMENTS")[0])
    sub = p.add_subparsers(dest="tool")

    s = sub.add_parser("scan", parents=[common], help="run everything and write a marked image + report")
    s.add_argument("--max-dim", type=int, default=2048, help="analyse at most this many px on the long side (default 2048)")
    s.add_argument("--block", type=int, default=16, help="block size for ELA/noise maps (default 16)")
    s.add_argument("--threshold", type=float, default=4.0, help="robust z-score to flag a block (default 4.0; lower = more sensitive)")
    s.add_argument("--min-region", type=int, default=4, help="min connected blocks for a region (default 4)")
    s.add_argument("--quality", type=int, default=90, help="ELA re-save quality (default 90)")
    s.add_argument("--ela-scale", type=float, default=20, help="ELA visual amplification (default 20)")
    s.add_argument("--force-ela", action="store_true", help="give ELA full weight even for non-JPEG input")
    s.add_argument("--noise-amp", type=float, default=10, help="noise visual amplification (default 10)")
    s.add_argument("--no-clone", action="store_true", help="skip clone detection (fastest)")
    s.add_argument("--clone-block", type=int, default=8)
    s.add_argument("--clone-max-size", type=int, default=512)
    s.add_argument("--min-similarity", type=float, default=0.985)
    s.add_argument("--min-cluster", type=int, default=25)
    s.add_argument("--no-sheet", action="store_true", help="skip the contact sheet")
    s.add_argument("--pixel-pages", action="store_true", help="PDF: also run pixel tests on rendered pages")

    m = sub.add_parser("magnifier", parents=[common], help="zoom into a region with enhancement")
    m.add_argument("--x", type=int); m.add_argument("--y", type=int)
    m.add_argument("--radius", type=int, default=40, help="half-size of the crop in px (default 40)")
    m.add_argument("--zoom", type=int, default=4, help="magnification (default 4)")
    m.add_argument("--enhance", default="histeq", choices=["none", "histeq", "autocontrast", "autocontrast-channel"])

    c = sub.add_parser("clone", parents=[common], help="copy-move (clone) detection")
    c.add_argument("--block", type=int, default=8, help="block size, multiple of 4 (default 8)")
    c.add_argument("--min-similarity", type=float, default=0.985, help="normalised correlation 0-1 (default 0.985)")
    c.add_argument("--max-diff", type=float, default=6.0, help="max mean abs pixel difference (default 6)")
    c.add_argument("--min-detail", type=float, default=4.0, help="ignore blocks with less texture than this (std-dev after removing gradients, default 4)")
    c.add_argument("--min-distance", type=int, help="min px between source and copy (default 2x block)")
    c.add_argument("--min-cluster", type=int, default=25, help="min matching blocks per shift (default 25)")
    c.add_argument("--max-size", type=int, default=512, help="downscale long side to this (default 512)")

    e = sub.add_parser("ela", parents=[common], help="error level analysis")
    e.add_argument("--quality", type=int, default=75, help="JPEG re-save quality (default 75)")
    e.add_argument("--scale", type=float, default=20, help="error amplification (default 20)")
    e.add_argument("--opacity", type=float, default=1.0, help="blend over the original, 0-1 (default 1 = ELA only)")

    n = sub.add_parser("noise", parents=[common], help="noise analysis (median-filter residual)")
    n.add_argument("--amplitude", type=float, default=10)
    n.add_argument("--radius", type=int, default=3, choices=[3, 5, 7])
    n.add_argument("--equalize", action="store_true", help="histogram-equalise the result")

    lv = sub.add_parser("levels", parents=[common], help="level sweep")
    lv.add_argument("--sweep", type=int, default=128, help="centre level 0-255 (default 128)")
    lv.add_argument("--width", type=int, default=32, help="band width (default 32)")
    lv.add_argument("--intensity", type=float, default=1.0)
    lv.add_argument("--animate", action="store_true", help="write an animated GIF sweeping 0-255")

    gr = sub.add_parser("gradient", parents=[common], help="luminance gradient")
    gr.add_argument("--intensity", type=float, default=1.0)

    pc = sub.add_parser("pca", parents=[common], help="principal component analysis")
    pc.add_argument("--component", type=int, default=1, choices=[1, 2, 3])
    pc.add_argument("--mode", default="projection", choices=["projection", "difference", "distance"])
    pc.add_argument("--linear", action="store_true")
    pc.add_argument("--invert", action="store_true")
    pc.add_argument("--enhance", default="none", choices=["none", "histeq", "autocontrast", "autocontrast-channel"])
    pc.add_argument("--all", action="store_true", help="write all 3 components x 3 modes")

    for name, hlp in (("meta", "EXIF / XMP / ICC metadata"), ("geo", "GPS geotags"),
                      ("thumbnail", "compare embedded EXIF thumbnail"), ("jpeg", "JPEG structure and quality")):
        t = sub.add_parser(name, parents=[common], help=hlp)
        t.add_argument("--json", action="store_true", help="print JSON")
        if name == "meta":
            t.add_argument("--exiftool", action="store_true", help="also include exiftool output if installed")
        if name == "jpeg":
            t.add_argument("--tables", action="store_true", help="print quantisation tables")
        if name == "thumbnail":
            t.add_argument("--threshold", type=float, default=12.0)

    st = sub.add_parser("strings", parents=[common], help="extract printable strings")
    st.add_argument("--min-length", type=int, default=6)
    st.add_argument("--encoding", default="ascii", choices=["ascii", "utf16", "both"])
    st.add_argument("--grep", help="only strings matching this regex")
    st.add_argument("--limit", type=int)
    st.add_argument("--json", action="store_true")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in TOOLS and argv[0] not in ("-h", "--help"):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    if not args.tool:
        build_parser().print_help()
        return 1
    if not os.path.isfile(args.input):
        print(f"No such file: {args.input}", file=sys.stderr)
        return 1
    items, doc_info = load_items(args.input, args)
    os.makedirs(args.outdir, exist_ok=True)

    if args.tool == "scan":
        reports = []
        for it in items:
            print(f"[*] analysing {it.name} ({it.img.width}x{it.img.height}, {it.fmt})", file=sys.stderr)
            reports.append(scan_item(it, args, args.input))
        r0, e0 = os.path.splitext(os.path.basename(args.input))
        stem = f"{r0}_{e0.lstrip('.').lower()}" if e0 else r0
        rj = os.path.join(args.outdir, f"{stem}_report.json")
        with open(rj, "w") as fh:
            json.dump({"document": doc_info, "items": reports}, fh, indent=2, default=_jsonable)
        txt = text_report(doc_info, reports)
        with open(os.path.join(args.outdir, f"{stem}_report.txt"), "w") as fh:
            fh.write(txt)
        print(txt)
        return 0

    if args.tool == "strings":
        with open(args.input, "rb") as fh:
            raw = fh.read()
        res = tool_strings(raw, args.min_length, args.encoding, args.grep, args.limit)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            for r in res:
                print(f"{r['offset']:>10x}  {r['text']}")
        return 0

    if not items:
        return 1
    it = items[0]
    base = os.path.join(args.outdir, it.name)
    t = args.tool

    def save(im, suffix):
        p = f"{base}_{suffix}.png"
        im.save(p)
        print(p)

    if t == "magnifier":
        save(tool_magnifier(it.img, args.x, args.y, args.radius, args.zoom, args.enhance), "magnifier")
    elif t == "clone":
        cl, s = tool_clone(it.img, args.block, args.min_similarity, args.max_diff, args.min_detail,
                           args.min_distance, args.min_cluster, args.max_size)
        for k, c_ in enumerate(cl, 1):
            print(f"cluster {k}: shift={c_['shift']} blocks={c_['blocks']} "
                  f"src={bbox_of(c_['src'], c_['block_px'])} copy={bbox_of(c_['dst'], c_['block_px'])}")
        if not cl:
            print("no clone clusters found")
        save(draw_clone(it.img, cl), "clone")
    elif t == "ela":
        vis, _ = tool_ela(it.img, args.quality, args.scale)
        if args.opacity < 1:
            vis = Image.blend(it.img.convert("L").convert("RGB"), vis, args.opacity)
        save(vis, f"ela_q{args.quality}")
    elif t == "noise":
        save(tool_noise(it.img, args.amplitude, args.equalize, args.radius)[0], "noise")
    elif t == "levels":
        if args.animate:
            frames = [tool_levels(it.img, sw, args.width, args.intensity) for sw in range(0, 256, 8)]
            frames = [fit(f, 800)[0] for f in frames]
            p = f"{base}_levels.gif"
            frames[0].save(p, save_all=True, append_images=frames[1:], duration=120, loop=0)
            print(p)
        else:
            save(tool_levels(it.img, args.sweep, args.width, args.intensity), f"levels_{args.sweep}")
    elif t == "gradient":
        save(tool_gradient(it.img, args.intensity), "gradient")
    elif t == "pca":
        combos = [(c_, m_) for c_ in (1, 2, 3) for m_ in ("projection", "difference", "distance")] if args.all \
            else [(args.component, args.mode)]
        for c_, m_ in combos:
            save(tool_pca(it.img, c_, m_, args.linear, args.invert, args.enhance), f"pca{c_}_{m_}")
    elif t in ("meta", "geo", "thumbnail", "jpeg"):
        if t == "meta":
            res = tool_meta(it, args.exiftool, args.input)
        elif t == "geo":
            res = tool_geo(tool_meta(it))
        elif t == "jpeg":
            res = tool_jpeg(it.raw, args.tables)
        else:
            res, th, dimg = tool_thumbnail(it, args.threshold)
            if th is not None:
                save(th, "thumbnail")
                save(dimg, "thumbnail_diff")
        if getattr(args, "json", False):
            print(json.dumps(res, indent=2, default=_jsonable))
        else:
            _pretty(res)
    return 0


def _pretty(d, indent=0):
    pad = "  " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            print(f"{pad}{k}:")
            _pretty(v, indent + 1)
        elif isinstance(v, list) and v and isinstance(v[0], (dict, list)):
            print(f"{pad}{k}:")
            for x in v:
                print(f"{pad}  - {x}")
        else:
            print(f"{pad}{k}: {v}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. piped into `head`
        sys.exit(0)
