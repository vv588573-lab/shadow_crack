#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.analyzer
Deep APK inspection: structure, DEX, native libs, permissions, signature, risks
"""

from __future__ import annotations

import os
import re
import zipfile
import struct
import subprocess

from .utils import fmt_size, sha256_file, which, paint, C

JUNK_BASENAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}


# ─────────────────────── binary manifest string extraction ───────────────────────
def _strings_utf8(data: bytes) -> list:
    return [m.group().decode("ascii", "ignore")
            for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]


def _strings_utf16le(data: bytes) -> list:
    out = []
    # find runs of printable UTF-16LE
    i, n = 0, len(data)
    cur = []
    while i + 1 < n:
        ch = data[i] | (data[i + 1] << 8)
        if 0x20 <= ch < 0x7F and data[i + 1] == 0:
            cur.append(chr(ch))
            i += 2
        else:
            if len(cur) >= 4:
                out.append("".join(cur))
            cur = []
            i += 2 if data[i + 1] == 0 else 1
    if len(cur) >= 4:
        out.append("".join(cur))
    return out


def extract_manifest_strings(manifest: bytes) -> set:
    found = set()
    try:
        found.update(_strings_utf8(manifest))
        found.update(_strings_utf16le(manifest))
    except Exception:
        pass
    return found


def extract_permissions(strings: set) -> list:
    perms = set()
    pat = re.compile(r"^android\.permission\.[A-Z0-9_]+$")
    for s in strings:
        s = s.strip("\x00")
        if pat.match(s):
            perms.add(s)
    # custom permissions (app-defined)
    for s in strings:
        if s.startswith("permission.") and len(s) < 80:
            perms.add(s)
    return sorted(perms)


# ─────────────────────── aapt / keytool helpers ───────────────────────
def _run(cmd: list, timeout: int = 25) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def aapt_badging(apk: str) -> dict:
    """Best-effort package info via aapt / aapt2 if installed."""
    out = {}
    for tool in ("aapt", "aapt2"):
        if which(tool):
            txt = _run([tool, "dump", "badging", apk])
            if "package:" in txt:
                m = re.search(r"package:\s*name='([^']+)'", txt)
                if m:
                    out["package"] = m.group(1)
                m = re.search(r"versionCode='([^']+)'", txt)
                if m:
                    out["version_code"] = m.group(1)
                m = re.search(r"versionName='([^']+)'", txt)
                if m:
                    out["version_name"] = m.group(1)
                m = re.search(r"sdkVersion:'(\d+)'", txt)
                if m:
                    out["min_sdk"] = m.group(1)
                m = re.search(r"targetSdkVersion:'(\d+)'", txt)
                if m:
                    out["target_sdk"] = m.group(1)
                m = re.search(r"application-label:'([^']*)'", txt)
                if m:
                    out["label"] = m.group(1)
                perms = sorted(set(re.findall(r"uses-permission[^>]*name='([^']+)'", txt)))
                if perms:
                    out["permissions"] = perms
                break
    return out


def cert_info(apk: str) -> dict:
    """Print signing cert details via keytool (works on signed APKs)."""
    if not which("keytool"):
        return {}
    txt = _run(["keytool", "-printcert", "-jarfile", apk], timeout=30)
    if "Owner:" not in txt and "Signer" not in txt:
        return {}
    out = {}
    m = re.search(r"Owner:\s*(.+)", txt)
    if m:
        out["owner"] = m.group(1).strip()
    m = re.search(r"All name(s):\s*(.+)", txt)
    if m:
        out["issuer"] = m.group(1).strip()
    else:
        m = re.search(r"Issuer:\s*(.+)", txt)
        if m:
            out["issuer"] = m.group(1).strip()
    m = re.search(r"Valid from:\s*(.+?)\s+to:\s*(.+)", txt)
    if m:
        out["valid_from"] = m.group(1).strip()
        out["valid_to"] = m.group(2).strip()
    m = re.search(r"SHA1:\s*([0-9A-Fa-f:]+)", txt)
    if m:
        out["sha1"] = m.group(1).strip()
    m = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", txt)
    if m:
        out["sha256"] = m.group().split(":", 1)[1].strip() if False else m.group(1).strip()
    m = re.search(r"Signature algorithm name:\s*(\S+)", txt)
    if m:
        out["algo"] = m.group(1)
    return out


# ─────────────────────── main analysis ───────────────────────
def analyze(apk_path: str) -> dict:
    rep: dict = {
        "path": apk_path,
        "ok": False,
        "errors": [],
        "warnings": [],
    }
    if not os.path.isfile(apk_path):
        rep["errors"].append("File not found")
        return rep
    if not zipfile.is_zipfile(apk_path):
        rep["errors"].append("Not a valid ZIP/APK file")
        return rep

    size = os.path.getsize(apk_path)
    rep["size"] = size
    rep["size_h"] = fmt_size(size)
    rep["sha256"] = sha256_file(apk_path)

    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception as e:
        rep["errors"].append(f"Cannot open APK: {e}")
        return rep

    with zf:
        infos = zf.infolist()
        rep["entries"] = len(infos)
        rep["uncompressed"] = sum(i.file_size for i in infos)
        rep["compressed"] = sum(i.compress_size for i in infos)

        names = [i.filename for i in infos]
        rep["names"] = names

        # structure
        rep["has_manifest"] = "AndroidManifest.xml" in names
        rep["has_resources"] = "resources.arsc" in names
        rep["dex"] = sorted(n for n in names
                            if re.match(r"classes\d*\.dex$", os.path.basename(n)))
        rep["so"] = sorted(n for n in names if n.endswith(".so"))
        rep["abis"] = sorted({n.split("/")[1] for n in rep["so"]
                              if n.startswith("lib/") and n.count("/") >= 2})
        rep["assets"] = [n for n in names if n.startswith("assets/")]
        rep["res"] = [n for n in names if n.startswith("res/")]
        rep["meta"] = [n for n in names if n.startswith("META-INF/")]

        # v1 signature present?
        rep["signed_v1"] = any(
            n.startswith("META-INF/") and
            (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC") or n.endswith(".SF"))
            for n in names
        )

        # junk detection
        junk = []
        for n in names:
            base = os.path.basename(n)
            if base in JUNK_BASENAMES or "__MACOSX" in n.split("/") or \
               base.lower().endswith((".bak", ".orig", ".rej")):
                junk.append(n)
        rep["junk"] = junk

        # manifest deep read
        if rep["has_manifest"]:
            try:
                mdata = zf.read("AndroidManifest.xml")
                strings = extract_manifest_strings(mdata)
                rep["permissions"] = extract_permissions(strings)
                rep["debuggable"] = any("debuggable" in s for s in strings)
                rep["test_only"] = any(s.strip("\x00") == "android:testOnly" for s in strings)
                # package name best-effort from manifest strings
                pkg = [s for s in strings if s.count(".") >= 1 and s.replace(".", "")
                       .replace("_", "").isalnum() and not s.startswith("android.")]
                rep["_manifest_pkgs"] = sorted(pkg)[:5]
            except Exception as e:
                rep["warnings"].append(f"Manifest read failed: {e}")
                rep["permissions"] = []
        else:
            rep["errors"].append("AndroidManifest.xml missing")
            rep["permissions"] = []

        # zip integrity
        try:
            bad = zf.testzip()
            rep["corrupt"] = bad
            if bad:
                rep["errors"].append(f"Corrupt entry: {bad}")
        except Exception as e:
            rep["corrupt"] = True
            rep["errors"].append(f"Integrity check failed: {e}")

    # external tools
    badging = aapt_badging(apk_path)
    rep.update({k: v for k, v in badging.items() if v})
    rep["cert"] = cert_info(apk_path)

    # risk flags
    risks = []
    if rep.get("debuggable"):
        risks.append("debuggable=true (production me dangerous)")
    if rep.get("test_only"):
        risks.append("android:testOnly set (install fail on some devices)")
    if not rep["signed_v1"] and not rep["cert"]:
        risks.append("APK unsigned / signature nahi mila")
    if junk:
        risks.append(f"{len(junk)} junk file(s) present")
    if rep.get("min_sdk") and int(rep.get("min_sdk", "0")) < 21:
        risks.append("minSdk < 21 (old devices, weak crypto risk)")
    rep["risks"] = risks

    rep["ok"] = len([e for e in rep["errors"] if "manifest" not in e.lower()]) == 0
    return rep


def print_report(rep: dict) -> None:
    from .utils import bx_row, bx_top, bx_bot, bx_mid, bx_empty, bx_center, hr

    name = os.path.basename(rep["path"])
    bx_top()
    bx_center(paint(" APK ANALYSIS REPORT", C.MAG + C.B))
    bx_mid()
    bx_row(paint("  File", C.GRY), paint(name, C.WHT))
    bx_row(paint("  Size", C.GRY), paint(rep.get("size_h", "?"), C.CYA))
    bx_row(paint("  SHA-256", C.GRY), paint(rep.get("sha256", "?")[:32] + "...", C.GRY))
    bx_row(paint("  Entries", C.GRY), paint(str(rep.get("entries", 0)), C.WHT))
    bx_row(paint("  Package", C.GRY), paint(rep.get("package", "n/a (aapt not installed)"), C.GRN))
    if rep.get("version_name"):
        bx_row(paint("  Version", C.GRY),
               paint(f"{rep.get('version_name', '?')} (code {rep.get('version_code', '?')})", C.GRN))
    if rep.get("min_sdk"):
        bx_row(paint("  SDK", C.GRY),
               paint(f"min {rep.get('min_sdk')} → target {rep.get('target_sdk', '?')}", C.CYA))
    bx_mid()
    bx_row(paint("  DEX files", C.GRY), paint(", ".join(rep.get("dex", [])) or "none", C.WHT))
    bx_row(paint("  Native libs", C.GRY),
           paint(f"{len(rep.get('so', []))} files", C.WHT) + paint(
               f" [{', '.join(rep.get('abis', []))}]" if rep.get("abis") else "", C.GRY))
    bx_row(paint("  Assets / Res", C.GRY),
           paint(f"{len(rep.get('assets', []))} / {len(rep.get('res', []))}", C.WHT))
    bx_row(paint("  Signed (v1)", C.GRY),
           paint("YES" if rep.get("signed_v1") or rep.get("cert") else "NO",
                 C.GRN if (rep.get("signed_v1") or rep.get("cert")) else C.RED))
    if rep.get("cert", {}).get("owner"):
        bx_row(paint("  Cert", C.GRY), paint(rep["cert"]["owner"][:34], C.YEL))
    bx_mid()
    perms = rep.get("permissions", [])
    bx_row(paint("  Permissions", C.GRY), paint(f"{len(perms)} found", C.WHT))
    show = perms[:8]
    for p in show:
        bx_row(paint("    · ", C.GRY), paint(p, C.GRY))
    if len(perms) > 8:
        bx_row(paint(f"    … +{len(perms) - 8} more", C.GRY), "")
    if rep.get("risks"):
        bx_mid()
        bx_center(paint("  ⚠ RISK FLAGS", C.YEL))
        for r in rep["risks"]:
            bx_row(paint("    ! ", C.YEL), paint(r, C.YEL))
    if rep.get("errors"):
        bx_mid()
        for e in rep["errors"]:
            bx_row(paint("    - ", C.RED), paint(e, C.RED))
    bx_bot()
