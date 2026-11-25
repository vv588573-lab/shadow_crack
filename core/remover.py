#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.remover
Remove Protection — apne APK se purana signature + junk hatao,
re-align + re-sign karke DOWNLOAD folder me save karo.

Scope (own-APK only):
  • META-INF signature files (v1) auto-remove ✓
  • junk entries (.DS_Store, Thumbs.db, .bak…) ✓
  • zipalign (pure-Python) ✓
  • re-sign with shadow_crack keystore (agar tool ho) ✓
  • packer .so / manifest flags → auto nahi (source rebuild se) — batate hain
"""

from __future__ import annotations

import os
import shutil
import zipfile

from .utils import (
    paint, C, ok, info, warn, fail,
    bx_top, bx_bot, bx_mid, bx_empty, bx_row, bx_center,
    fmt_size, sha256_file, load_settings, next_version_path,
    append_history, BACKUP_DIR, ensure_home, which,
)
from . import signer, aligner, analyzer, scanner

SIG_SUFFIXES = (".RSA", ".DSA", ".EC", ".SF", ".MF")
JUNK_BASENAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
JUNK_SUFFIXES = (".bak", ".orig", ".rej", ".swp", ".tmp")


def download_dir() -> str:
    """Android Download folder dhoondo (Termux ke liye fallback ke saath)."""
    candidates = [
        "/storage/emulated/0/Download",
        "/sdcard/Download",
        os.path.expanduser("~/storage/downloads"),
        "/storage/emulated/0",
        os.path.expanduser("~"),
    ]
    for p in candidates:
        try:
            if os.path.isdir(p) and os.access(p, os.W_OK):
                return p
        except Exception:
            continue
    return os.path.expanduser("~")


def _is_sig_entry(name: str) -> bool:
    """META-INF ke signature files (2-level: META-INF/CERT.RSA ...)."""
    if not name.startswith("META-INF/"):
        return False
    parts = name.split("/")
    if len(parts) != 2:
        return False          # META-INF/com/..., META-INF/proguard/... → keep
    base = parts[1]
    return base == "MANIFEST.MF" or base.upper().endswith(SIG_SUFFIXES)


def _is_junk(name: str) -> bool:
    base = os.path.basename(name)
    return (base in JUNK_BASENAMES or "__MACOSX" in name.split("/")
            or base.lower().endswith(JUNK_SUFFIXES))


def remove_protection(apk_path: str, options: dict | None = None,
                      quiet: bool = False) -> dict:
    opts = {"sign": True, "backup": True}
    if options:
        opts.update(options)

    def log(msg):
        if not quiet:
            info(msg)

    rep: dict = {"ok": False, "input": apk_path, "errors": [],
                 "sig_removed": [], "junk_removed": [], "warnings": []}

    if not os.path.isfile(apk_path) or not zipfile.is_zipfile(apk_path):
        rep["errors"].append("Valid APK/ZIP nahi hai")
        return rep

    ensure_home()
    rep["size_in"] = os.path.getsize(apk_path)
    rep["sha_in"] = sha256_file(apk_path)

    # ── stage 0: backup (original safe rakho) ──
    if opts["backup"]:
        try:
            dst_bk = os.path.join(BACKUP_DIR, os.path.basename(apk_path))
            if os.path.abspath(apk_path) != os.path.abspath(dst_bk):
                shutil.copy2(apk_path, dst_bk)
            rep["backup"] = dst_bk
        except Exception as e:
            rep["warnings"].append(f"backup fail: {e}")

    # ── stage 1: strip signature + junk ──
    log("stripping signature + junk entries ...")
    work1 = apk_path + ".unpro.strip.apk"
    try:
        with zipfile.ZipFile(apk_path) as zin:
            with zipfile.ZipFile(work1, "w", zipfile.ZIP_DEFLATED) as zout:
                for zi in zin.infolist():
                    if _is_sig_entry(zi.filename):
                        rep["sig_removed"].append(zi.filename)
                        continue
                    if _is_junk(zi.filename):
                        rep["junk_removed"].append(zi.filename)
                        continue
                    data = zin.read(zi.filename)
                    new = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                    new.create_system = zi.create_system
                    new.external_attr = zi.external_attr
                    new.internal_attr = zi.internal_attr
                    new.comment = zi.comment
                    new.flag_bits = zi.flag_bits & ~0x08
                    new.compress_type = zi.compress_type
                    new._compresslevel = (9 if zi.compress_type
                                          == zipfile.ZIP_DEFLATED else None)
                    zout.writestr(new, data)
    except Exception as e:
        rep["errors"].append(f"strip fail: {e}")
        _cleanup(work1)
        return rep

    # ── stage 2: re-align (pure Python) ──
    log("re-aligning ...")
    work2 = apk_path + ".unpro.align.apk"
    aok, amsg, _ = aligner.py_align(work1, work2)
    rep["align"] = amsg if aok else "align skip (ok)"
    _cleanup(work1)

    # ── stage 3: re-sign with own keystore ──
    final = work2
    rep["signed"] = False
    if opts["sign"]:
        log("re-signing with shadow_crack keystore ...")
        work3 = apk_path + ".unpro.sign.apk"
        sok, smsg = signer.sign_apk(work2, work3, load_settings())
        rep["sign_msg"] = smsg
        if sok:
            rep["signed"] = True
            final = work3
            _cleanup(work2)
        else:
            _cleanup(work3)
            rep["warnings"].append(
                f"unsigned output: {smsg} — install ke liye "
                "pkg install openjdk-17 apksigner chalao phir se")

    # ── stage 4: notes — kya AUTO nahi hat sakta ──
    try:
        srep = scanner.scan(apk_path)
        for n, st, extra in (srep.get("dex_status") or []):
            if st != "OK":
                rep["warnings"].append(
                    f"{os.path.basename(n)} = {st} ({extra.strip()}) — "
                    "stub/encrypted DEX protection hai; ye zip-tool se "
                    "nahi khulta (original APK ya source rebuild)")
        if srep.get("packers"):
            names = ", ".join(p[0] for p in srep["packers"][:4])
            rep["warnings"].append(
                f"packer/protection .so mile ({names}) — ye auto-remove "
                "nahi hote (APK crash ho jayega); sirf ORIGINAL source "
                "build se hat-te hain")
        if srep.get("debuggable") or srep.get("testOnly"):
            rep["warnings"].append(
                "debuggable/testOnly flag — binary manifest hai, auto "
                "nahi badalta; apni build me false karke rebuild karo")
    except Exception:
        pass

    # ── stage 5: save to DOWNLOAD folder ──
    out_dir = download_dir()
    base = os.path.splitext(os.path.basename(apk_path))[0] + "_UNPROTECTED"
    out_path = next_version_path(out_dir, base, ".apk")
    try:
        shutil.move(final, out_path)
    except Exception:
        try:
            shutil.copy2(final, out_path)
            _cleanup(final)
        except Exception as e:
            rep["errors"].append(f"download folder save fail: {e}")
            _cleanup(work2)
            return rep

    # output DEX integrity (proof: output kharab nahi hai)
    try:
        with zipfile.ZipFile(out_path) as z:
            rep["dex_status"] = scanner.dex_check(
                z, [n for n in z.namelist() if n.endswith(".dex")])
    except Exception:
        rep["dex_status"] = []

    rep["ok"] = True
    rep["output"] = out_path
    rep["size_out"] = os.path.getsize(out_path)
    rep["sha_out"] = sha256_file(out_path)
    append_history({"action": "remove", "input": os.path.basename(apk_path),
                    "status": "OK" if rep["signed"] else "UNSIGNED",
                    "detail": f"{len(rep['sig_removed'])} sig + "
                              f"{len(rep['junk_removed'])} junk removed → "
                              f"{os.path.basename(out_path)}"})
    if not quiet:
        ok(f"saved → {out_path}")
    return rep


def _cleanup(*paths: str) -> None:
    for p in paths:
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except Exception:
            pass


def print_result(rep: dict) -> None:
    if not rep.get("ok"):
        for e in rep.get("errors", ["remove fail"]):
            fail(e)
        return

    bx_top()
    bx_center(paint(" PROTECTION REMOVED ", C.GRN + C.B))
    bx_mid()
    bx_row(paint("  Input", C.GRY), paint(os.path.basename(rep["input"]),
                                          C.WHT)[:44])
    bx_row(paint("  Size", C.GRY),
           paint(f"{fmt_size(rep['size_in'])} → {fmt_size(rep['size_out'])}",
                 C.CYA))
    bx_mid()
    bx_center(paint("  Kya hata", C.CYA + C.B))
    sig = rep["sig_removed"]
    if sig:
        shown = ", ".join(os.path.basename(s) for s in sig[:4])
        bx_row(paint("  Signature (v1)", C.GRY),
               paint(f"{len(sig)} files: {shown}"
                     + ("..." if len(sig) > 4 else ""), C.GRN))
    else:
        bx_row(paint("  Signature (v1)", C.GRY), paint("koi nahi mila", C.GRY))
    if rep["junk_removed"]:
        bx_row(paint("  Junk", C.GRY),
               paint(f"{len(rep['junk_removed'])} entries", C.GRN))
    bx_row(paint("  Zipalign", C.GRY), paint(rep.get("align", "-"), C.GRN))
    if rep["signed"]:
        bx_row(paint("  Re-sign", C.GRY),
               paint(f"✅ {rep.get('sign_msg', 'signed')}", C.GRN))
    else:
        bx_row(paint("  Re-sign", C.GRY),
               paint("⚠ unsigned (dekho upar warning)", C.YEL))
    ds = rep.get("dex_status") or []
    if ds:
        bad = [d for d in ds if d[1] != "OK"]
        if not bad:
            bx_row(paint("  DEX check", C.GRY),
                   paint(f"{len(ds)} dex OK ✅ (output intact)", C.GRN))
        else:
            for n, st, extra in bad:
                bx_row(paint(f"  ⚠ {os.path.basename(n)}"[:40], C.YEL),
                       paint(f"{st}"[:24], C.YEL + C.B))
    bx_mid()
    bx_center(paint("  OUTPUT (Download folder)", C.MAG + C.B))
    bx_row(paint("  File", C.GRY), paint(os.path.basename(rep["output"]),
                                         C.WHT)[:44])
    bx_row(paint("  Path", C.GRY), paint(rep["output"], C.CYA)[:44])
    bx_row(paint("  SHA-256", C.GRY), paint(rep["sha_out"][:32] + "...",
                                            C.GRY))
    if rep["warnings"]:
        bx_mid()
        bx_center(paint("  NOTE — ye AUTO nahi hata", C.YEL + C.B))
        for w in rep["warnings"]:
            words, line, lines = w.split(), "", []
            for wd in words:
                if len(line) + len(wd) + 1 > 46:
                    lines.append(line)
                    line = wd
                else:
                    line = (line + " " + wd).strip()
            if line:
                lines.append(line)
            bx_row(paint(f"    • {lines[0]}", C.YEL), "")
            for cont in lines[1:]:
                bx_row(paint(f"       {cont}", C.YEL), "")
    bx_mid()
    bx_center(paint("⚠ Sirf apne APK par chalao — dusre ke app ki", C.RED))
    bx_center(paint("  protection hatana illegal hai.", C.RED))
    bx_bot()
    print()
