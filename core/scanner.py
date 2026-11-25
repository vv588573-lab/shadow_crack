#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.scanner
Protection Scanner — APK me kaun-kaun si protection hai, ye dikhata hai.
Saath me Remove/Restore guide (sirf APNE APK ke liye).
"""

from __future__ import annotations

import os
import re
import struct
import zipfile

from .utils import paint, C, fmt_size, sha256_file, which
from . import aligner, analyzer

SIGN_MAGIC = b"APK Sig Block 42"

# ── known packer / protection .so markers (public research knowledge) ──
CERTAIN_SO = [
    (r"libjiagu", "Bangcle / Jiagu (加固)"),
    (r"libsecexe|libsecmain", "Bangcle (older)"),
    (r"libprotectClass|libijiami", "ijiami (爱加密)"),
    (r"libsgmain|libsgsecuritybody", "Alibaba Shentu (阿里加固)"),
    (r"libtersafe|libtp2?-", "Tencent Tersafe / TP (乐固)"),
    (r"libnqshield", "Netqin Shield (网秦)"),
    (r"libbaiduprotect", "Baidu Protect (百度加固)"),
    (r"libDexHelper", "Dex helper packer"),
    (r"libshella", "Shell / Legu-style"),
    (r"libchaosvmp|libexecmain", "VMP / exec protection"),
    (r"libapkprotect", "APKProtect"),
    (r"libNEProtect|libnesec", "NetEase protection"),
    (r"libtosviolation|libtp2", "Tencent protection"),
]
SOFT_SO = re.compile(
    r"protect|shield|guard|hard|jiagu|legu|shell|secmain|dexhelper|vmp|antihook|integrity",
    re.I,
)


DEX_MAGICS = (b"dex\n035", b"dex\n037", b"dex\n038", b"dex\n039",
              b"cdex001")


def dex_check(zf: zipfile.ZipFile, names: list) -> list:
    """Har DEX ki integrity: magic + header file_size vs actual size.
    STUB = header bada hai actual se → ye protection/protector marker hai."""
    out = []
    for n in sorted(names):
        if not n.endswith(".dex"):
            continue
        try:
            zi = zf.getinfo(n)
            with zf.open(n) as f:
                hdr = f.read(0x70)
            if len(hdr) < 0x70:
                out.append((n, "TOO_SHORT", f" sirf {len(hdr)}B"))
                continue
            if not any(hdr.startswith(m) for m in DEX_MAGICS):
                out.append((n, "BAD_MAGIC", ""))
                continue
            declared = struct.unpack_from("<I", hdr, 32)[0]
            if declared != zi.file_size:
                out.append((n, "STUB",
                            f"header {declared} ≠ actual {zi.file_size}"))
            else:
                out.append((n, "OK", str(zi.file_size)))
        except Exception as e:
            out.append((n, "ERR", str(e)[:24]))
    return out


def has_signing_block(path: str) -> bool:
    """APK Signing Block (v2/v3) magic dhoondho — last1MB me."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - 1024 * 1024))
            data = f.read()
        return SIGN_MAGIC in data
    except Exception:
        return False


def scan(path: str) -> dict:
    rep: dict = {"path": path, "ok": False, "errors": [], "findings": [],
                 "remove_steps": []}
    if not os.path.isfile(path) or not zipfile.is_zipfile(path):
        rep["errors"].append("Valid APK/ZIP nahi hai")
        return rep

    rep["size"] = os.path.getsize(path)
    rep["size_h"] = fmt_size(rep["size"])
    rep["sha256"] = sha256_file(path)

    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        rep["errors"].append(str(e))
        return rep

    with zf:
        names = zf.namelist()
        rep["entries"] = len(names)

        # ── signature ──
        rep["v1"] = any(
            n.startswith("META-INF/") and
            (n.upper().endswith((".RSA", ".DSA", ".EC", ".SF")) or n.upper().endswith("/MANIFEST.MF"))
            for n in names
        )
        rep["v2_v3"] = has_signing_block(path)
        rep["v4"] = os.path.isfile(path + ".idsig")
        rep["cert"] = analyzer.cert_info(path)

        # ── zipalign ──
        good, bad, total = aligner.check_align(path)
        rep["aligned"] = good
        rep["align_bad"] = bad
        rep["align_total"] = total

        # ── manifest flags ──
        flags = {"debuggable": False, "testOnly": False,
                 "allowBackup": False, "netsec": False}
        if "AndroidManifest.xml" in names:
            try:
                strings = analyzer.extract_manifest_strings(
                    zf.read("AndroidManifest.xml"))
                flags["debuggable"] = any("debuggable" in s for s in strings)
                flags["testOnly"] = any(s.strip("\x00") == "android:testOnly"
                                        for s in strings)
                flags["allowBackup"] = any("allowBackup" in s for s in strings)
                flags["netsec"] = any("network_security_config" in s
                                      for s in strings)
            except Exception:
                pass
        rep.update(flags)

        # ── obfuscation hints ──
        rep["proguard_rules"] = any(
            n.startswith("META-INF/proguard/") or n.endswith(".mapping")
            for n in names
        )
        rep["dex"] = [n for n in names
                      if re.match(r"classes\d*\.dex$", os.path.basename(n))]
        rep["dex_status"] = dex_check(zf, [n for n in names
                                           if n.endswith(".dex")])
        rep["so"] = [n for n in names if n.endswith(".so")]

        # ── packer / protection .so ──
        hits = []
        for so in rep["so"]:
            base = os.path.basename(so)
            label = None
            for pat, name in CERTAIN_SO:
                if re.search(pat, base, re.I):
                    label = name
                    break
            if label is None and SOFT_SO.search(base):
                label = "possible protection module"
            if label:
                hits.append((base, label))
        rep["packers"] = hits

    # ── remove/restore steps (sirf apne APK ke liye) ──
    steps = []
    if rep["v1"] or rep["v2_v3"]:
        steps.append("Signature hata/replace karne → apne khud ke keystore se "
                     "dobara sign karo (apksigner sign ...)")
    if not rep["aligned"]:
        steps.append("Zipalign theek karne → zipalign -f -p 4 in.apk out.apk")
    if rep.get("debuggable"):
        steps.append("Debuggable band (apni build me) → android:debuggable="
                     "false + APK dobara build karo")
    if rep.get("testOnly"):
        steps.append("testOnly hata (apni build me) → android:testOnly=false "
                     "+ rebuild")
    if rep["packers"]:
        steps.append("Packer/protection .so → sabse safe tarika: apne app ka "
                     "ORIGINAL unpacked build install karo (source se rebuild)")
    if rep["proguard_rules"]:
        steps.append("Obfuscation → apne project me mapping.txt save rakho "
                     "(R8/ProGuard output)")
    steps.append("Sabse safe restore → apna original/backup APK install karo "
                 "(tool backups: ~/.shadow_crack/backups/)")
    rep["remove_steps"] = steps
    rep["ok"] = True
    return rep


def _yn(flag: bool) -> str:
    return paint("HAAN ⚠", C.YEL + C.B) if flag else paint("nahi", C.GRN)


def print_report(rep: dict) -> None:
    from .utils import bx_top, bx_bot, bx_mid, bx_row, bx_center

    if not rep.get("ok"):
        for e in rep.get("errors", ["scan fail"]):
            print(f"  {paint('[-]', C.RED)} {e}")
        return

    name = os.path.basename(rep["path"])
    bx_top()
    bx_center(paint(" PROTECTION REPORT ", C.MAG + C.B))
    bx_mid()
    bx_row(paint("  File", C.GRY), paint(name, C.WHT))
    bx_row(paint("  Size", C.GRY), paint(rep["size_h"], C.CYA))
    bx_row(paint("  SHA-256", C.GRY), paint(rep["sha256"][:32] + "...", C.GRY))
    bx_mid()
    bx_center(paint("  SIGNATURE", C.CYA + C.B))
    v1c = C.GRN if rep["v1"] else C.GRY
    v2c = C.GRN if rep["v2_v3"] else C.GRY
    bx_row(paint("  v1 (JAR signing)", C.GRY),
           paint("MILAA ✅" if rep["v1"] else "nahi", v1c + (C.B if rep["v1"] else "")))
    bx_row(paint("  v2/v3 (APK Sign Block)", C.GRY),
           paint("MILAA ✅" if rep["v2_v3"] else "nahi", v2c + (C.B if rep["v2_v3"] else "")))
    bx_row(paint("  v4 (.idsig)", C.GRY),
           paint("MILAA ✅" if rep["v4"] else "nahi", C.GRN if rep["v4"] else C.GRY))
    owner = rep.get("cert", {}).get("owner", "")
    if owner:
        bx_row(paint("  Cert", C.GRY), paint(owner[:36], C.YEL))
    bx_mid()
    bx_center(paint("  HARDENING / FLAGS", C.CYA + C.B))
    if rep["align_total"] > 0:
        okc = C.GRN if rep["aligned"] else C.YEL
        if rep["aligned"]:
            atxt = "✅ aligned"
        else:
            atxt = f"❌ {rep['align_bad']} bad entries"
        bx_row(paint("  Zipalign", C.GRY), paint(atxt, okc))
    else:
        bx_row(paint("  Zipalign", C.GRY), paint("koi STORED entry nahi", C.GRY))
    bx_row(paint("  debuggable", C.GRY), _yn(rep.get("debuggable")))
    bx_row(paint("  testOnly", C.GRY), _yn(rep.get("testOnly")))
    bx_row(paint("  allowBackup", C.GRY), _yn(rep.get("allowBackup")))
    bx_row(paint("  Network security cfg", C.GRY),
           paint("MILA" if rep.get("netsec") else "nahi", C.GRN if rep.get("netsec") else C.GRY))
    bx_row(paint("  ProGuard/R8 rules", C.GRY),
           paint("MILA (obfuscation hint)" if rep["proguard_rules"] else "nahi",
                 C.YEL if rep["proguard_rules"] else C.GRY))
    bx_row(paint("  DEX / native .so", C.GRY),
           paint(f"{len(rep['dex'])} / {len(rep['so'])}", C.WHT))
    ds = rep.get("dex_status") or []
    if ds:
        bad = [d for d in ds if d[1] != "OK"]
        if not bad:
            bx_row(paint("  DEX integrity", C.GRY),
                   paint(f"{len(ds)} dex OK ✅", C.GRN))
        else:
            for n, st, extra in bad:
                bx_row(paint(f"  ⚠ DEX {os.path.basename(n)}"[:40], C.YEL),
                       paint(f"{st} {extra}"[:22], C.YEL + C.B))
    bx_mid()
    bx_center(paint("  PACKER / PROTECTION .so", C.CYA + C.B))
    if rep["packers"]:
        for base, label in rep["packers"][:8]:
            bx_row(paint(f"    ⚠ {base}"[:40], C.YEL), paint(label, C.YEL))
    else:
        bx_center(paint("    koi known packer nahi mila", C.GRN))
    bx_mid()
    bx_center(paint("  REMOVE / RESTORE — sirf APNE APK ke liye", C.GRN + C.B))
    for i, s in enumerate(rep["remove_steps"], 1):
        # wrap long lines ~46
        words, line, lines = s.split(), "", []
        for w in words:
            if len(line) + len(w) + 1 > 46:
                lines.append(line)
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            lines.append(line)
        bx_row(paint(f"    {i}. {lines[0]}", C.GRY), "")
        for cont in lines[1:]:
            bx_row(paint(f"       {cont}", C.GRY), "")
    bx_mid()
    bx_center(paint("⚠ Dusre ke app ki protection hatana illegal hai —", C.RED))
    bx_center(paint("  sirf wo APK jispar tumhare paas haq ho.", C.RED))
    bx_bot()
    print()
