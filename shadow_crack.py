#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║   ██████╗██╗  ██╗ █████╗ ██████╗  ██████╗██╗ ██╗ ██╗ ║
║  ██╔════╝██║  ██║██╔══██╗██╗  ██╗██╗  ██╗██║ ██║ ██║ ║
║   ██████╗███████║███████║██║  ██╗██║  ██║█████ █████ ║
║  ██╔════╝██╔══██║██╔══██╗██║  ██╗██║  ██║██║ ██║ ██║ ║
║   ██████╗██║  ██║██║  ██║╚██████╝╚██████╝╚██╝╚██╝    ║
║  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚═════╝     ║
║ ██████╗  ██████╗ █████╗ ██████╗ ██╗  ██╗            ║
║ ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝            ║
║ ██║     ██████║ ███████║██║     ██████╔╝            ║
║ ██║     ██╔══██╗██╔══██╗██║     ██╔══██╗            ║
║ ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██             ║
║ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝            ║
║      SHADOW_CRACK · ADVANCED APK SHIELD TOOLKIT      ║
╚══════════════════════════════════════════════════════╝
SHADOW_CRACK v1.0.0 — 100% FREE · NO CREDITS · NO LIMITS
"""

from __future__ import annotations

import os
import sys
import argparse

# make `core` importable no matter where we're launched from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import (  # noqa: E402
    VERSION, TOOL_NAME, TAGLINE, C, paint, ok, info, warn, fail,
    bx_top, bx_bot, bx_mid, bx_empty, bx_row, bx_center, hr,
    load_settings, save_settings, resolve_output_dir, read_history,
    clear_history, prompt, confirm, expand_path, fmt_size, ensure_home,
    KEYSTORE_FILE, HOME_DIR, which,
)
from core import protector, analyzer, signer, scanner  # noqa: E402

BANNER = r"""
  ██████╗██╗  ██╗ █████╗ ██████╗  ██████╗██╗ ██╗ ██╗
 ██╔════╝██║  ██║██╔══██╗██╗  ██╗██╗  ██╗██║ ██║ ██║
  ██████╗███████║███████║██║  ██╗██║  ██║█████ █████
 ██╔════╝██╔══██║██╔══██╗██║  ██╗██║  ██║██║ ██║ ██║
  ██████╗██║  ██║██║  ██║╚██████╝╚██████╝╚██╝╚██╝   
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚═════╝    
 ██████╗  ██████╗ █████╗ ██████╗ ██╗  ██╗
 ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
 ██║     ██████║ ███████║██║     ██████╔╝
 ██║     ██╔══██╗██╔══██╗██║     ██╔══██╗
 ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
"""


def banner() -> None:
    st = load_settings()
    print(paint(BANNER, C.MAG + C.B))
    bx_top()
    bx_center(paint(f"{TOOL_NAME} · {TAGLINE}", C.MAG + C.B))
    bx_center(paint(f"v{VERSION}  ·  100% FREE · NO CREDITS · NO LIMITS", C.GRN))
    bx_mid()
    bx_row(paint("  Mode", C.GRY), paint("FULL (unlimited protection)", C.GRN))
    bx_row(paint("  Device", C.GRY), paint(st.get("device_id", "?"), C.CYA))
    bx_bot()
    print()


def stage_check() -> None:
    """Environment health check shown once at start."""
    checks = [
        ("python3", True),
        ("keytool", False),
        ("apksigner", False),
        ("jarsigner", False),
        ("zipalign", False),
        ("aapt", False),
        ("zip", True),
    ]
    missing_core = []
    for name, essential in checks:
        if not which(name) and essential:
            missing_core.append(name)
    if missing_core:
        warn(f"missing tools: {', '.join(missing_core)}")
    # auto note for signing stack
    if not which("keytool"):
        info("signing ke liye Java chahiye → Termux me: pkg install openjdk-17")
    if not which("apksigner"):
        info("v2/v3 signature ke liye: pkg install apksigner (optional, jarsigner fallback hai)")


# ─────────────────────────── menu actions ───────────────────────────
def action_protect() -> None:
    print()
    bx_top()
    bx_center(paint("  PROTECT APK", C.CYA + C.B))
    bx_bot()
    path = prompt("APK file path (ya 'back')")
    if not path or path.lower() == "back":
        return
    apk = expand_path(path)
    if not os.path.isfile(apk):
        fail(f"file not found: {apk}")
        return
    st = load_settings()
    do_sign = confirm("Sign karna hai? (recommended)", default=st.get("auto_sign", True))
    do_backup = confirm("Original ka backup rakhna hai?", default=st.get("backup", True))
    out_dir = resolve_output_dir(st)
    info(f"output → {out_dir}")
    rep = protector.protect(apk, {"sign": do_sign, "backup": do_backup, "out_dir": out_dir})
    if rep.get("ok"):
        protector.print_result(rep)
    else:
        fail("protection fail hua — upar ka stage error dekho")


def action_analyze() -> None:
    print()
    bx_top()
    bx_center(paint("  APK ANALYZER", C.CYA + C.B))
    bx_bot()
    path = prompt("APK file path (ya 'back')")
    if not path or path.lower() == "back":
        return
    apk = expand_path(path)
    rep = analyzer.analyze(apk)
    if rep.get("errors") and not rep.get("entries"):
        for e in rep["errors"]:
            fail(e)
        return
    analyzer.print_report(rep)


def action_scan() -> None:
    print()
    bx_top()
    bx_center(paint("  PROTECTION SCANNER", C.CYA + C.B))
    bx_center(paint("  APK me kaun si protection hai?", C.GRY))
    bx_bot()
    path = prompt("APK file path (ya 'back')")
    if not path or path.lower() == "back":
        return
    apk = expand_path(path)
    rep = scanner.scan(apk)
    scanner.print_report(rep)


def action_batch() -> None:
    print()
    bx_top()
    bx_center(paint("  BATCH PROTECTION", C.CYA + C.B))
    bx_bot()
    path = prompt("Folder jisme saare APK hain (ya 'back')")
    if not path or path.lower() == "back":
        return
    folder = expand_path(path)
    if not os.path.isdir(folder):
        fail(f"folder not found: {folder}")
        return
    apks = sorted(
        os.path.join(folder, f) for f in os.listdir(folder)
        if f.lower().endswith(".apk") and os.path.isfile(os.path.join(folder, f))
    )
    if not apks:
        warn("is folder me koi .apk nahi mili")
        return
    info(f"{len(apks)} APK mile — sab protect honge")
    if not confirm("Start karein?", default=True):
        return
    out_dir = resolve_output_dir()
    results = []
    for i, apk in enumerate(apks, 1):
        print()
        print(paint(f"  ── [{i}/{len(apks)}] {os.path.basename(apk)} ──", C.BLU + C.B))
        rep = protector.protect(apk, {"sign": True, "backup": True, "out_dir": out_dir},
                                quiet=False)
        results.append((os.path.basename(apk), rep.get("status", "FAIL")))
    print()
    bx_top()
    bx_center(paint(" BATCH SUMMARY ", C.MAG + C.B))
    bx_mid()
    for name, status in results:
        col = {"OK": C.GRN, "PARTIAL": C.YEL}.get(status, C.RED)
        bx_row(paint(f"  {name[:34]}", C.WHT), paint(status, col))
    ok_n = sum(1 for _, s in results if s == "OK")
    bx_mid()
    bx_row(paint("  Total", C.GRY), paint(f"{len(results)} · OK {ok_n}", C.WHT))
    bx_bot()


def action_history() -> None:
    print()
    bx_top()
    bx_center(paint("  HISTORY", C.CYA + C.B))
    bx_mid()
    rows = read_history(15)
    if not rows:
        bx_center(paint("abhi tak koi activity nahi", C.GRY))
    for r in rows:
        status = r.get("status", "?")
        col = {"OK": C.GRN, "PARTIAL": C.YEL}.get(status, C.RED if status == "FAIL" else C.WHT)
        left = paint(f"  {r.get('ts', '?')[5:19]}", C.GRY) + "  " + \
            paint(str(r.get("input", ""))[:26], C.WHT)
        bx_row(left, paint(status, col))
        if r.get("sha256"):
            bx_row(paint(f"     sha256 {r['sha256'][:28]}...", C.GRY), "")
    bx_bot()
    print()
    if rows and confirm("History clear karni hai?", default=False):
        clear_history()
        ok("history cleared")


def action_keystore() -> None:
    print()
    bx_top()
    bx_center(paint("  KEYSTORE MANAGER", C.CYA + C.B))
    bx_mid()
    exists = os.path.isfile(KEYSTORE_FILE)
    bx_row(paint("  Keystore", C.GRY),
           paint(KEYSTORE_FILE if exists else "not generated", 
                 C.GRN if exists else C.YEL))
    bx_row(paint("  Tools", C.GRY),
           paint(f"keytool={'Y' if which('keytool') else 'N'} "
                 f"apksigner={'Y' if which('apksigner') else 'N'} "
                 f"jarsigner={'Y' if which('jarsigner') else 'N'}", C.GRY))
    bx_bot()
    print()
    print(f"  {paint('[1]', C.MAG)} Generate / Rotate keystore")
    print(f"  {paint('[2]', C.MAG)} Keystore details (keytool -list)")
    print(f"  {paint('[3]', C.MAG)} Back")
    print()
    ch = prompt("choice", "3")
    if ch == "1":
        if not which("keytool"):
            fail("keytool nahi mila → pkg install openjdk-17")
            return
        if exists and not confirm("Existing keystore replace karein? (purani signed apps update nahi ho payengi)", False):
            return
        if signer.rotate_keystore():
            ok(f"new keystore ready → {KEYSTORE_FILE}")
            info("password default 'shadowcrack' hai (settings.json me change kar sakte ho)")
        else:
            fail("generation fail")
    elif ch == "2":
        print()
        print(signer.keystore_info())
        print()


def action_settings() -> None:
    st = load_settings()
    while True:
        print()
        bx_top()
        bx_center(paint("  SETTINGS", C.CYA + C.B))
        bx_mid()
        bx_row(paint("  Output dir", C.GRY), paint(st.get("output_dir") or "auto (@SHADOW_CRACK)", C.WHT)[:44])
        bx_row(paint("  Backup original", C.GRY),
               paint("ON" if st.get("backup") else "OFF", C.GRN if st.get("backup") else C.YEL))
        bx_row(paint("  Auto-sign", C.GRY),
               paint("ON" if st.get("auto_sign") else "OFF", C.GRN if st.get("auto_sign") else C.YEL))
        bx_row(paint("  Keystore alias", C.GRY), paint(st.get("ks_alias", "?"), C.WHT))
        bx_row(paint("  Data dir", C.GRY), paint(HOME_DIR, C.GRY))
        bx_bot()
        print()
        print(f"  {paint('[1]', C.MAG)} Set output folder")
        print(f"  {paint('[2]', C.MAG)} Toggle backup original")
        print(f"  {paint('[3]', C.MAG)} Toggle auto-sign")
        print(f"  {paint('[4]', C.MAG)} Reset output to auto")
        print(f"  {paint('[5]', C.MAG)} Clear history")
        print(f"  {paint('[6]', C.MAG)} Back")
        print()
        ch = prompt("choice", "6")
        if ch == "1":
            p = prompt("custom output path")
            if p:
                st["output_dir"] = expand_path(p)
                save_settings(st)
                ok(f"output → {st['output_dir']}")
        elif ch == "2":
            st["backup"] = not st.get("backup", True)
            save_settings(st)
        elif ch == "3":
            st["auto_sign"] = not st.get("auto_sign", True)
            save_settings(st)
        elif ch == "4":
            st["output_dir"] = ""
            save_settings(st)
            ok("auto output restored")
        elif ch == "5":
            if confirm("Poori history delete?", False):
                clear_history()
                ok("history cleared")
        else:
            return


def action_about() -> None:
    print()
    bx_top()
    bx_center(paint("  ABOUT " + TOOL_NAME, C.MAG + C.B))
    bx_mid()
    bx_row(paint("  Version", C.GRY), paint(VERSION, C.WHT))
    bx_row(paint("  Tagline", C.GRY), paint(TAGLINE, C.CYA))
    bx_row(paint("  Credits", C.GRY), paint("NOT REQUIRED — 100% free forever", C.GRN))
    bx_row(paint("  Pipeline", C.GRY), paint("verify→clean→harden→align→sign→seal", C.WHT))
    bx_mid()
    bx_center(paint("maxshell jaisa lekin better:", C.YEL))
    bx_center(paint("· real 6-stage engine (no fake credits)", C.GRY))
    bx_center(paint("· batch mode + deep analyzer + history", C.GRY))
    bx_center(paint("· v1+v2+v3 signing · python zipalign", C.GRY))
    bx_center(paint("· sha256 sealing · auto versioning", C.GRY))
    bx_mid()
    bx_center(paint("Disclaimer", C.YEL))
    bx_center(paint("Apne hi APK protect karne ke liye.", C.GRY))
    bx_center(paint("Kisi aur ka app modify karna illegal hai.", C.GRY))
    bx_bot()
    print()
    prompt("Enter dabao wapas aane ke liye", "")


# ─────────────────────────── menu loop ───────────────────────────
def menu() -> None:
    ensure_home()
    banner()
    stage_check()
    actions = {
        "1": action_protect,
        "2": action_analyze,
        "3": action_batch,
        "4": action_history,
        "5": action_keystore,
        "6": action_settings,
        "7": action_about,
        "8": action_scan,
    }
    while True:
        print()
        bx_top()
        bx_empty()
        bx_row(paint("   [1]", C.MAG), paint("Protect APK", C.WHT))
        bx_row(paint("   [2]", C.MAG), paint("APK Analyzer", C.WHT))
        bx_row(paint("   [3]", C.MAG), paint("Batch Protect", C.WHT))
        bx_row(paint("   [4]", C.MAG), paint("History", C.WHT))
        bx_row(paint("   [5]", C.MAG), paint("Keystore Manager", C.WHT))
        bx_row(paint("   [6]", C.MAG), paint("Settings", C.WHT))
        bx_row(paint("   [7]", C.MAG), paint("About", C.WHT))
        bx_row(paint("   [8]", C.MAG), paint("Protection Scanner", C.WHT))
        bx_row(paint("   [0]", C.MAG), paint("Exit", C.RED))
        bx_empty()
        bx_bot()
        try:
            ch = prompt("select", "0").strip().lower()
        except KeyboardInterrupt:
            print()
            ch = "0"
        if ch in ("0", "q", "quit", "exit", "x"):
            print()
            info("SHADOW_CRACK band ho raha hai — apna APK safe rakho 🛡")
            print()
            break
        fn = actions.get(ch)
        if fn:
            try:
                fn()
            except KeyboardInterrupt:
                print()
                warn("action cancelled")
            except Exception as e:
                fail(f"error: {e}")
        else:
            warn("invalid choice — 0-7 try karo")


# ─────────────────────────── CLI ───────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadow_crack",
        description="SHADOW_CRACK — Advanced APK Shield Toolkit (maxshell-style, no credits)",
    )
    p.add_argument("-p", "--protect", metavar="APK", help="protect one APK")
    p.add_argument("-a", "--analyze", metavar="APK", help="analyze one APK")
    p.add_argument("-b", "--batch", metavar="DIR", help="protect all APKs in folder")
    p.add_argument("--history", action="store_true", help="show history")
    p.add_argument("--verify", metavar="APK", help="verify APK signature only")
    p.add_argument("--keystore", action="store_true", help="keystore status")
    p.add_argument("--scan", metavar="APK", help="protection scanner report")
    p.add_argument("-y", "--yes", action="store_true", help="auto-confirm prompts")
    p.add_argument("--no-sign", action="store_true", help="skip signing stage")
    p.add_argument("--no-backup", action="store_true", help="skip original backup")
    p.add_argument("-o", "--out", metavar="DIR", help="custom output folder")
    p.add_argument("--version", action="version", version=f"shadow_crack {VERSION}")
    p.add_argument("--menu", action="store_true", help="force interactive menu")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    ensure_home()

    if args.menu or not any([args.protect, args.analyze, args.batch,
                             args.history, args.verify, args.keystore,
                             args.scan]):
        menu()
        return 0

    if args.analyze:
        rep = analyzer.analyze(expand_path(args.analyze))
        if rep.get("errors") and not rep.get("entries"):
            for e in rep["errors"]:
                fail(e)
            return 1
        analyzer.print_report(rep)
        return 0

    if args.scan:
        rep = scanner.scan(expand_path(args.scan))
        scanner.print_report(rep)
        return 0 if rep.get("ok") else 1

    if args.protect:
        out = expand_path(args.out) if args.out else None
        opts = {
            "sign": not args.no_sign,
            "backup": not args.no_backup,
            "out_dir": out,
        }
        rep = protector.protect(expand_path(args.protect), opts, quiet=False)
        if rep.get("ok"):
            protector.print_result(rep)
            return 0
        return 1

    if args.batch:
        folder = expand_path(args.batch)
        apks = sorted(os.path.join(folder, f) for f in os.listdir(folder)
                      if f.lower().endswith(".apk")) if os.path.isdir(folder) else []
        if not apks:
            fail(f"koi APK nahi mili: {folder}")
            return 1
        out = expand_path(args.out) if args.out else None
        fails = 0
        for i, apk in enumerate(apks, 1):
            print(paint(f"\n── [{i}/{len(apks)}] {os.path.basename(apk)} ──", C.BLU + C.B))
            rep = protector.protect(apk, {"sign": not args.no_sign,
                                          "backup": not args.no_backup,
                                          "out_dir": out})
            if not rep.get("ok"):
                fails += 1
        print()
        ok(f"batch done: {len(apks) - fails}/{len(apks)} success")
        return 0 if fails == 0 else 1

    if args.history:
        rows = read_history(30)
        if not rows:
            info("history empty")
            return 0
        for r in rows:
            print(f"  {r.get('ts', '?')}  {r.get('input', '')} → "
                  f"{r.get('output', '-')}  [{r.get('status', '?')}]")
        return 0

    if args.verify:
        status, detail = signer.verify_sign(expand_path(args.verify))
        col = {"ok": C.GRN, "bad": C.RED, "unsigned": C.YEL}.get(status, C.GRY)
        print(f"  {paint(status.upper(), col)} — {detail}")
        return 0 if status == "ok" else 1

    if args.keystore:
        exists = os.path.isfile(KEYSTORE_FILE)
        print(f"  keystore: {'EXISTS' if exists else 'MISSING'} ({KEYSTORE_FILE})")
        if exists:
            print(signer.keystore_info())
        return 0

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
