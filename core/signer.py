#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.signer
Keystore management + apksigner (v1/v2/v3) with jarsigner fallback
"""

from __future__ import annotations

import os
import shutil
import subprocess

from .utils import (
    KEYSTORE_FILE, load_settings, save_settings, ensure_home,
    which, warn, ok, fail, info,
)


def _run(cmd: list, timeout: int = 120) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "command not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:
        return 1, str(e)


def have_apksigner() -> bool:
    return bool(which("apksigner"))


def have_jarsigner() -> bool:
    return bool(which("jarsigner"))


def have_keytool() -> bool:
    return bool(which("keytool"))


def have_zipalign() -> bool:
    return bool(which("zipalign"))


def ensure_keystore(settings: dict | None = None) -> tuple:
    """Generate signing keystore if missing. Returns (path, password, alias)."""
    ensure_home()
    s = settings or load_settings()
    pw = s.get("ks_pass", "shadowcrack")
    alias = s.get("ks_alias", "shadow_crack")
    if os.path.isfile(KEYSTORE_FILE):
        return KEYSTORE_FILE, pw, alias
    if not have_keytool():
        return None, pw, alias
    cmd = [
        "keytool", "-genkeypair",
        "-keystore", KEYSTORE_FILE,
        "-alias", alias,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", pw,
        "-keypass", pw,
        "-dname", "CN=SHADOW_CRACK, OU=Shield, O=SHADOWCRACK, L=Unknown, ST=Unknown, C=IN",
    ]
    rc, out = _run(cmd, timeout=60)
    if rc == 0 and os.path.isfile(KEYSTORE_FILE):
        try:
            os.chmod(KEYSTORE_FILE, 0o600)
        except Exception:
            pass
        return KEYSTORE_FILE, pw, alias
    fail(f"Keystore generation failed: {out.strip()[:200]}")
    return None, pw, alias


def rotate_keystore() -> bool:
    if os.path.isfile(KEYSTORE_FILE):
        try:
            os.remove(KEYSTORE_FILE)
        except Exception:
            return False
    path, _, _ = ensure_keystore()
    return path is not None


def keystore_info() -> str:
    if not os.path.isfile(KEYSTORE_FILE):
        return "keystore not found"
    if not have_keytool():
        return "keytool not installed"
    s = load_settings()
    rc, out = _run([
        "keytool", "-list", "-v",
        "-keystore", KEYSTORE_FILE,
        "-storepass", s.get("ks_pass", "shadowcrack"),
        "-alias", s.get("ks_alias", "shadow_crack"),
    ], timeout=30)
    if rc != 0:
        return out.strip()[:400]
    # trim to essentials
    keep = []
    for line in out.splitlines():
        if any(k in line for k in ("Alias name", "Valid from", "Owner:", "Issuer:",
                                   "Signature algorithm", "SHA1:", "SHA256:",
                                   "Keystore type", "Entry type")):
            keep.append(line.rstrip())
    return "\n".join(keep) if keep else out.strip()[:400]


def sign_apk(src: str, dst: str, settings: dict | None = None) -> tuple:
    """
    Sign APK → dst. Prefers apksigner (v1+v2+v3), falls back to jarsigner (v1).
    Returns (ok: bool, message: str).
    """
    s = settings or load_settings()
    ks, pw, alias = ensure_keystore(s)
    if ks is None:
        return False, "keystore unavailable (keytool install karo: pkg install openjdk-17)"

    # copy first (apksigner writes --out; jarsigner signs in place)
    if os.path.abspath(src) != os.path.abspath(dst):
        shutil.copy2(src, dst)

    if have_apksigner():
        cmd = [
            "apksigner", "sign",
            "--ks", ks,
            "--ks-pass", f"pass:{pw}",
            "--key-pass", f"pass:{pw}",
            "--ks-key-alias", alias,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            "--out", dst,
            src if os.path.abspath(src) != os.path.abspath(dst) else dst,
        ]
        if os.path.abspath(src) == os.path.abspath(dst):
            cmd = [c for c in cmd if c != "--out"] + [dst]
        rc, out = _run(cmd)
        if rc == 0:
            return True, "signed v1+v2+v3 (apksigner)"
        # retry without --out (in-place)
        rc, out2 = _run([
            "apksigner", "sign",
            "--ks", ks, "--ks-pass", f"pass:{pw}", "--key-pass", f"pass:{pw}",
            "--ks-key-alias", alias, dst,
        ])
        if rc == 0:
            return True, "signed v1+v2+v3 (apksigner, in-place)"
        return False, f"apksigner failed: {(out or out2).strip()[:200]}"

    if have_jarsigner():
        rc, out = _run([
            "jarsigner", "-keystore", ks,
            "-storepass", pw, "-keypass", pw,
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            dst, alias,
        ])
        if rc == 0:
            return True, "signed v1 (jarsigner fallback — install apksigner for v2/v3)"
        return False, f"jarsigner failed: {out.strip()[:200]}"

    return False, "koi signing tool nahi mila (apksigner ya jarsigner install karo)"


def verify_sign(apk: str) -> tuple:
    """Returns (status, detail). status: ok | bad | unsigned | unknown"""
    if have_apksigner():
        rc, out = _run(["apksigner", "verify", "--verbose", "--print-certs", apk])
        if rc == 0:
            detail = ""
            for line in out.splitlines():
                if "Verified using" in line or "Signer #1 certificate DN" in line:
                    detail = line.strip()
                    break
            return "ok", detail or "signature valid (apksigner)"
        if "DOES NOT VERIFY" in out or "FAILED" in out.upper():
            return "bad", out.strip().splitlines()[0][:160] if out.strip() else "verification failed"
        return "unknown", out.strip()[:160]
    if have_jarsigner():
        rc, out = _run(["jarsigner", "-verify", "-strict", apk])
        if rc == 0 and "verified" in out.lower():
            line = [l for l in out.splitlines() if "verified" in l.lower()]
            return "ok", (line[0].strip() if line else "verified (jarsigner)")
        if "unsigned" in out.lower():
            return "unsigned", "jar unsigned"
        return "bad", out.strip().splitlines()[0][:160] if out.strip() else "verification failed"
    return "unknown", "no verifier (apksigner/jarsigner missing)"
