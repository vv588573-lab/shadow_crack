#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.protector
6-stage protection pipeline:
  01 VERIFY → 02 CLEAN → 03 HARDEN → 04 ALIGN → 05 SIGN → 06 SEAL
"""

from __future__ import annotations

import os
import re
import time
import zipfile
import shutil

from .utils import (
    fmt_size, sha256_file, ts_short, load_settings, save_settings,
    resolve_output_dir, next_version_path, append_history, BACKUP_DIR,
    ensure_home, warn, ok, fail, info, paint, C,
)
from . import analyzer, signer, aligner

JUNK_BASENAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
JUNK_SUFFIXES = (".bak", ".orig", ".rej", ".swp", ".tmp")
SIG_SUFFIXES = (".RSA", ".DSA", ".EC", ".SF", ".MF")


class Stage:
    def __init__(self, num: str, name: str):
        self.num = num
        self.name = name
        self.status = "PENDING"   # OK / WARN / SKIP / FAIL
        self.detail = ""
        self.secs = 0.0


def _stage_line(st: Stage) -> None:
    colors = {"OK": C.GRN, "DONE": C.GRN, "WARN": C.YEL, "SKIP": C.GRY,
              "FAIL": C.RED, "PENDING": C.GRY}
    col = colors.get(st.status, C.WHT)
    dots = "." * max(2, 30 - len(st.name))
    print(f"  {paint('[' + st.num + ']', C.MAG)} {st.name} {paint(dots, C.GRY)} "
          f"{paint(st.status, col + C.B)} {paint(f'({st.secs:.1f}s)', C.GRY)}")
    if st.detail:
        print(f"        {paint(st.detail, C.GRY)}")


# ─────────────────────── stage implementations ───────────────────────
def _stage_verify(apk: str, st: Stage) -> bool:
    if not os.path.isfile(apk):
        st.status, st.detail = "FAIL", "file not found"
        return False
    if not zipfile.is_zipfile(apk):
        st.status, st.detail = "FAIL", "valid ZIP/APK nahi hai"
        return False
    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            bad = zf.testzip()
            if bad:
                st.status, st.detail = "FAIL", f"corrupt entry: {bad}"
                return False
            need = []
            if "AndroidManifest.xml" not in names:
                need.append("AndroidManifest.xml")
            if not any(re.match(r"classes\d*\.dex$", os.path.basename(n)) for n in names) \
               and "resources.arsc" not in names:
                need.append("classes.dex / resources.arsc")
            if need:
                st.status, st.detail = "FAIL", f"missing: {', '.join(need)}"
                return False
    except Exception as e:
        st.status, st.detail = "FAIL", str(e)[:80]
        return False
    st.status = "OK"
    st.detail = f"{os.path.basename(apk)} · {fmt_size(os.path.getsize(apk))} · integrity pass"
    return True


def _stage_clean(src: str, work: str, st: Stage) -> str:
    """Remove junk entries. Returns path to cleaned apk (or src if nothing)."""
    removed = []
    try:
        with zipfile.ZipFile(src) as zin:
            infos = zin.infolist()
            keep = []
            for zi in infos:
                base = os.path.basename(zi.filename)
                if base in JUNK_BASENAMES or "__MACOSX" in zi.filename.split("/") \
                   or base.lower().endswith(JUNK_SUFFIXES):
                    removed.append(zi.filename)
                    continue
                keep.append(zi)
            if not removed:
                st.status, st.detail = "OK", "no junk found — archive already clean"
                return src
            out = work + ".clean.apk"
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
                for zi in keep:
                    data = zin.read(zi.filename)
                    new = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                    new.create_system = zi.create_system
                    new.external_attr = zi.external_attr
                    new.compress_type = zi.compress_type
                    new._compresslevel = 9 if zi.compress_type == zipfile.ZIP_DEFLATED else None
                    zout.writestr(new, data)
        st.status = "OK"
        st.detail = f"{len(removed)} junk removed: " + ", ".join(
            os.path.basename(r) for r in removed[:3]) + ("..." if len(removed) > 3 else "")
        return out
    except Exception as e:
        st.status, st.detail = "WARN", f"clean skipped: {e}"
        return src


def _stage_harden(src: str, work: str, st: Stage) -> str:
    """Recompress compressed entries at max level + report hardening stats."""
    try:
        with zipfile.ZipFile(src) as zin:
            infos = zin.infolist()
            before = sum(i.compress_size for i in infos)
            recompressed = 0
            out = work + ".hard.apk"
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
                for zi in infos:
                    data = zin.read(zi.filename)
                    new = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                    new.create_system = zi.create_system
                    new.external_attr = zi.external_attr
                    if zi.compress_type == zipfile.ZIP_STORED:
                        new.compress_type = zipfile.ZIP_STORED
                        zout.writestr(new, data)
                    else:
                        new.compress_type = zipfile.ZIP_DEFLATED
                        new._compresslevel = 9
                        zout.writestr(new, data)
                        recompressed += 1
            after = sum(i.compress_size for i in zipfile.ZipFile(out).infolist())
        saved = before - after
        pct = (saved / before * 100) if before else 0
        st.status = "OK"
        st.detail = (f"{recompressed} entries recompressed@9 · "
                     f"{'-' if saved >= 0 else '+'}{fmt_size(abs(saved))} ({pct:.1f}%)")
        return out
    except Exception as e:
        st.status, st.detail = "WARN", f"harden skipped: {e}"
        return src


def _stage_align(src: str, work: str, st: Stage) -> str:
    out = work + ".aligned.apk"
    okk, msg, cnt = aligner.zipalign_apk(src, out, page_so=True)
    if okk and os.path.isfile(out):
        good, bad, total = aligner.check_align(out)
        st.status = "OK" if good else "WARN"
        detail = msg if cnt < 0 else f"python engine · {msg}"
        if total >= 0:
            detail += f" · {total - bad}/{total} stored entries aligned"
        st.detail = detail
        return out
    st.status, st.detail = "WARN", f"align failed: {msg} (signing ke bina bhi chalega)"
    return src


def _stage_sign(src: str, work: str, st: Stage, settings: dict, do_sign: bool) -> str:
    if not do_sign:
        st.status, st.detail = "SKIP", "signing disabled by user"
        return src
    out = work + ".signed.apk"
    success, msg = signer.sign_apk(src, out, settings)
    if success:
        st.status, st.detail = "OK", msg
        return out
    st.status, st.detail = "WARN", msg
    return src


def _stage_seal(apk: str, st: Stage, settings: dict) -> dict:
    status, detail = signer.verify_sign(apk)
    digest = sha256_file(apk)
    if status == "ok":
        st.status = "OK"
        st.detail = f"signature verified · SHA-256 {digest[:24]}..."
    elif status == "unsigned":
        st.status = "WARN"
        st.detail = f"APK unsigned · SHA-256 {digest[:24]}..."
    elif status == "bad":
        st.status = "FAIL"
        st.detail = f"signature INVALID: {detail}"
    else:
        st.status = "WARN"
        st.detail = f"verify skipped ({detail}) · SHA-256 {digest[:24]}..."
    return {"sha256": digest, "sig_status": status, "sig_detail": detail}


# ─────────────────────── main entry ───────────────────────
def protect(apk_path: str, options: dict | None = None, quiet: bool = False) -> dict:
    """
    Run full pipeline.
    options: {sign: bool, backup: bool, out_dir: str|None}
    Returns report dict.
    """
    t0 = time.time()
    settings = load_settings()
    opts = {"sign": settings.get("auto_sign", True),
            "backup": settings.get("backup", True),
            "out_dir": None}
    if options:
        opts.update(options)

    apk = os.path.abspath(os.path.expanduser(apk_path))
    report = {"input": apk, "stages": [], "ok": False}

    if not quiet:
        print()
        print(f"  {paint('▸ PROTECTION PIPELINE', C.CYA + C.B)}  {paint(os.path.basename(apk), C.WHT)}")
        print()

    stages = [Stage("01", "Verify APK"),
              Stage("02", "Clean Archive"),
              Stage("03", "Resource Harden"),
              Stage("04", "Zip Align"),
              Stage("05", "Sign Engine"),
              Stage("06", "Seal + Verify")]

    ensure_home()

    # 01 VERIFY
    t = time.time()
    if not _stage_verify(apk, stages[0]):
        stages[0].secs = time.time() - t
        if not quiet:
            _stage_line(stages[0])
        report["stages"] = [s.__dict__ for s in stages]
        append_history({"action": "protect", "input": os.path.basename(apk),
                        "status": "FAIL", "detail": stages[0].detail})
        return report

    # optional backup
    if opts["backup"]:
        try:
            shutil.copy2(apk, os.path.join(BACKUP_DIR, os.path.basename(apk)))
        except Exception:
            pass

    def _cleanup(old: str, new: str) -> None:
        """Remove intermediate temp file only if stage produced a new one."""
        if old != apk and new != old and os.path.exists(old):
            try:
                os.remove(old)
            except Exception:
                pass

    # 02 CLEAN
    t = time.time()
    cur = _stage_clean(apk, apk, stages[1])
    stages[1].secs = time.time() - t

    # 03 HARDEN
    t = time.time()
    nxt = _stage_harden(cur, apk, stages[2])
    _cleanup(cur, nxt)
    cur = nxt
    stages[2].secs = time.time() - t

    # 04 ALIGN
    t = time.time()
    nxt = _stage_align(cur, apk, stages[3])
    _cleanup(cur, nxt)
    cur = nxt
    stages[3].secs = time.time() - t

    # 05 SIGN
    t = time.time()
    nxt = _stage_sign(cur, apk, stages[4], settings, opts["sign"])
    _cleanup(cur, nxt)
    cur = nxt
    stages[4].secs = time.time() - t

    # warn if old signature will be stale
    if stages[4].status == "SKIP":
        try:
            with zipfile.ZipFile(apk) as zf:
                if any(n.startswith("META-INF/") and n.endswith(SIG_SUFFIXES)
                       for n in zf.namelist()):
                    stages[4].detail += " · ⚠ purana signature invalid ho jayega"
        except Exception:
            pass

    # 06 SEAL
    t = time.time()
    seal = _stage_seal(cur, stages[5], settings)
    stages[5].secs = time.time() - t

    if not quiet:
        for s in stages:
            _stage_line(s)
        print()

    # output naming with versioning
    out_dir = opts["out_dir"] or resolve_output_dir(settings)
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(apk))[0]
    final_path = next_version_path(out_dir, f"{stem}_SHADOWCRACK")
    shutil.move(cur, final_path) if cur != apk else shutil.copy2(apk, final_path)
    if cur != apk and os.path.exists(cur):
        try:
            os.remove(cur)
        except Exception:
            pass

    out_size = os.path.getsize(final_path)
    in_size = os.path.getsize(apk)
    delta = out_size - in_size

    all_ok = all(s.status in ("OK", "SKIP", "WARN") for s in stages)
    any_fail = any(s.status == "FAIL" for s in stages)
    report.update({
        "ok": all_ok and not any_fail,
        "output": final_path,
        "size_in": in_size,
        "size_out": out_size,
        "delta": delta,
        "sha256": seal["sha256"],
        "sig_status": seal["sig_status"],
        "stages": [s.__dict__ for s in stages],
        "elapsed": time.time() - t0,
        "status": "FAIL" if any_fail else ("PARTIAL" if
                  any(s.status == "WARN" for s in stages) else "OK"),
    })

    append_history({
        "action": "protect",
        "input": os.path.basename(apk),
        "output": os.path.basename(final_path),
        "status": report["status"],
        "size_in": in_size,
        "size_out": out_size,
        "sha256": seal["sha256"],
        "sig": seal["sig_status"],
        "elapsed": round(report["elapsed"], 1),
    })

    return report


def print_result(rep: dict) -> None:
    from .utils import bx_top, bx_bot, bx_mid, bx_row, bx_center
    if not rep.get("output"):
        return
    st_col = {"OK": C.GRN, "PARTIAL": C.YEL, "FAIL": C.RED}.get(rep["status"], C.WHT)
    bx_top()
    bx_center(paint(" SHIELD COMPLETE ", C.GRN + C.B))
    bx_mid()
    bx_row(paint("  Status", C.GRY), paint(rep["status"], st_col + C.B))
    bx_row(paint("  Output", C.GRY), paint(os.path.basename(rep["output"]), C.WHT))
    bx_row(paint("  Path", C.GRY), paint(rep["output"], C.CYA))
    d = rep["delta"]
    sign = "-" if d <= 0 else "+"
    bx_row(paint("  Size", C.GRY),
           paint(f"{fmt_size(rep['size_in'])} → {fmt_size(rep['size_out'])} ", C.WHT) +
           paint(f"({sign}{fmt_size(abs(d))})", C.GRN if d <= 0 else C.YEL))
    bx_row(paint("  SHA-256", C.GRY), paint(rep["sha256"][:40] + "...", C.GRY))
    bx_row(paint("  Time", C.GRY), paint(f"{rep['elapsed']:.1f}s", C.WHT))
    bx_bot()
    print()
    print(f"  {paint('★ Install tip (Android 11+):', C.YEL)} Play Protect off → "
          f"Unknown sources ON → file manager se install karo")
    print(f"  {paint('★ Output folder:', C.GRY)} {os.path.dirname(rep['output'])}")
    print()
