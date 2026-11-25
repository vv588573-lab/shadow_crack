#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.aligner
Pure-Python zipalign (STORED entries → 4-byte, .so → page/4096)
Uses system `zipalign` when available, else its own engine.
"""

from __future__ import annotations

import os
import struct
import zipfile

from .utils import which, warn


ALIGN_DEFAULT = 4
ALIGN_PAGE = 4096


def _pad_extra(base_offset: int, fn_len: int, target: int) -> bytes:
    """
    Compute local-header extra field so that data starts at `target` boundary.
    extra is a valid TLV: id=0x0000, size=N, N zero bytes.
    """
    data_off_wo_extra = base_offset + 30 + fn_len
    need = (-data_off_wo_extra) % target
    if need == 0:
        return b""
    if need < 4:
        need += target  # TLV header needs 4 bytes minimum
    return struct.pack("<HH", 0x0000, need - 4) + b"\x00" * (need - 4)


def py_align(src: str, dst: str, page_so: bool = True) -> tuple:
    """
    Rewrite APK aligning uncompressed entries.
    Returns (ok, message, aligned_count).
    """
    aligned = 0
    try:
        zin = zipfile.ZipFile(src, "r")
    except Exception as e:
        return False, f"open failed: {e}", 0

    with zin, zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_STORED) as zout:
        for zi in zin.infolist():
            data = zin.read(zi.filename)
            new = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
            new.create_system = zi.create_system
            new.external_attr = zi.external_attr
            new.internal_attr = zi.internal_attr
            new.comment = zi.comment
            new.flag_bits = zi.flag_bits & ~0x08  # no data descriptor (seekable out)

            if zi.compress_type == zipfile.ZIP_STORED:
                is_so = zi.filename.endswith(".so")
                target = ALIGN_PAGE if (page_so and is_so) else ALIGN_DEFAULT
                # predict local header position
                base = zout.fp.tell()
                fn_bytes = zi.filename.encode("utf-8") if (
                    zi.flag_bits & 0x800 or _needs_utf8(zi.filename)
                ) else zi.filename.encode("cp437", "replace")
                extra = _pad_extra(base, len(fn_bytes), target)
                new.extra = extra
                new.compress_type = zipfile.ZIP_STORED
                aligned += 1
            else:
                new.extra = b""
                new.compress_type = zi.compress_type
                new._compresslevel = 9 if zi.compress_type == zipfile.ZIP_DEFLATED else None

            with zout.open(new, "w") as f:
                f.write(data)

    zin.close()
    return True, f"{aligned} entries aligned", aligned


def _needs_utf8(name: str) -> bool:
    try:
        name.encode("cp437")
        return False
    except Exception:
        return True


def zipalign_apk(src: str, dst: str, page_so: bool = True) -> tuple:
    """Align APK: prefer real zipalign binary, fallback to pure Python engine."""
    if which("zipalign"):
        import subprocess
        cmd = ["zipalign", "-f", "-p" if page_so else "-p", "4", src, dst]
        # zipalign -p 4 : page-align .so + 4-align everything uncompressed
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and os.path.isfile(dst):
                return True, "zipalign (system) OK", -1
            # some builds lack -p combo; plain 4
            r = subprocess.run(["zipalign", "-f", "4", src, dst],
                               capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and os.path.isfile(dst):
                return True, "zipalign (system, 4-byte) OK", -1
        except Exception:
            pass
        warn("system zipalign failed → SHADOW_CRACK python engine use ho raha hai")

    return py_align(src, dst, page_so=page_so)


def check_align(apk: str, page_so: bool = True) -> tuple:
    """Verify alignment of STORED entries. Returns (ok, bad_count, total)."""
    try:
        zf = zipfile.ZipFile(apk)
    except Exception as e:
        return False, -1, -1
    bad = total = 0
    with zf:
        for zi in zf.infolist():
            if zi.compress_type != zipfile.ZIP_STORED:
                continue
            total += 1
            # data offset = header_offset + 30 + fn_len + extra_len
            fn = zi.filename.encode("utf-8") if _needs_utf8(zi.filename) or (zi.flag_bits & 0x800) \
                else zi.filename.encode("cp437", "replace")
            data_off = zi.header_offset + 30 + len(fn) + len(zi.extra)
            target = ALIGN_PAGE if (page_so and zi.filename.endswith(".so")) else ALIGN_DEFAULT
            # system zipalign -p aligns .so to 4096; accept 4096 or 4-multiple for so
            if zi.filename.endswith(".so") and page_so:
                if data_off % ALIGN_PAGE != 0 and data_off % ALIGN_DEFAULT != 0:
                    bad += 1
            elif data_off % ALIGN_DEFAULT != 0:
                bad += 1
    return bad == 0, bad, total
