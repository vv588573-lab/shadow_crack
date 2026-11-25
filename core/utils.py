#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHADOW_CRACK · core.utils
Colors · boxes · hashing · history · settings · storage detection
"""

from __future__ import annotations

import os
import sys
import json
import time
import uuid
import shutil
import hashlib
import datetime

VERSION = "1.3.0"
TOOL_NAME = "SHADOW_CRACK"
TAGLINE = "ADVANCED APK SHIELD TOOLKIT"

HOME_DIR = os.path.expanduser("~/.shadow_crack")
HISTORY_FILE = os.path.join(HOME_DIR, "history.jsonl")
KEYSTORE_FILE = os.path.join(HOME_DIR, "shadow_crack.jks")
SETTINGS_FILE = os.path.join(HOME_DIR, "settings.json")
BACKUP_DIR = os.path.join(HOME_DIR, "backups")
OUTPUT_FOLDER_NAME = "@SHADOW_CRACK"

DEFAULT_SETTINGS = {
    "device_id": "SHADOWCRACK-" + uuid.uuid4().hex[:12].upper(),
    "output_dir": "",
    "backup": True,
    "auto_sign": True,
    "ks_pass": "shadowcrack",
    "ks_alias": "shadow_crack",
    "created": datetime.datetime.now().isoformat(timespec="seconds"),
}


# ─────────────────────────── colors ───────────────────────────
class C:
    RST = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYA = "\033[96m"
    WHT = "\033[97m"
    GRY = "\033[90m"


def _color_ok() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") == "1":
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


COLOR = _color_ok()


def paint(text: str, color: str) -> str:
    return f"{color}{text}{C.RST}" if COLOR else text


def ok(msg: str) -> None:
    print(f"  {paint('[+]', C.GRN)} {msg}")


def info(msg: str) -> None:
    print(f"  {paint('[*]', C.CYA)} {msg}")


def warn(msg: str) -> None:
    print(f"  {paint('[!]', C.YEL)} {msg}")


def fail(msg: str) -> None:
    print(f"  {paint('[-]', C.RED)} {msg}")


# ─────────────────────────── boxes ───────────────────────────
BOX_W = 56


def _vis(s: str) -> int:
    """Visible length ignoring ANSI codes."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\033" and i + 1 < len(s) and s[i + 1] == "[":
            j = s.find("m", i)
            if j == -1:
                break
            i = j + 1
        else:
            out += 1
            i += 1
    return out


def bx_top(w: int = BOX_W) -> None:
    print(paint("╭" + "─" * w + "╮", C.GRY))


def bx_bot(w: int = BOX_W) -> None:
    print(paint("╰" + "─" * w + "╯", C.GRY))


def bx_mid(w: int = BOX_W) -> None:
    print(paint("├" + "─" * w + "┤", C.GRY))


def bx_empty(w: int = BOX_W) -> None:
    print(paint("│" + " " * w + "│", C.GRY))


def bx_row(left: str, right: str = "", w: int = BOX_W) -> None:
    lv, rv = _vis(left), _vis(right)
    pad = w - 2 - lv - rv
    if pad < 1:
        pad = 1
    print(paint("│", C.GRY) + left + " " * pad + right + paint("│", C.GRY))


def bx_center(text: str, w: int = BOX_W) -> None:
    t = text
    pad = w - _vis(t)
    if pad < 0:
        pad = 0
    left = pad // 2
    right = pad - left
    print(paint("│", C.GRY) + " " * left + t + " " * right + paint("│", C.GRY))


def hr() -> None:
    print(paint("─" * (BOX_W + 2), C.GRY))


# ─────────────────────────── helpers ───────────────────────────
def fmt_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.1f}{unit}" if unit != "B" else f"{int(f)}B"
        f /= 1024
    return f"{n}B"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ts_short() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


# ─────────────────────────── settings / history ───────────────────────────
def ensure_home() -> None:
    os.makedirs(HOME_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)


def load_settings() -> dict:
    ensure_home()
    if os.path.isfile(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = dict(DEFAULT_SETTINGS)
            merged.update(data)
            return merged
        except Exception:
            pass
    save_settings(dict(DEFAULT_SETTINGS))
    return dict(DEFAULT_SETTINGS)


def save_settings(s: dict) -> None:
    ensure_home()
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2, ensure_ascii=False)


def append_history(rec: dict) -> None:
    ensure_home()
    rec.setdefault("ts", now_stamp())
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_history(limit: int = 20) -> list:
    if not os.path.isfile(HISTORY_FILE):
        return []
    out = []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        return []
    return out[-limit:][::-1]


def clear_history() -> None:
    if os.path.isfile(HISTORY_FILE):
        os.remove(HISTORY_FILE)


# ─────────────────────────── storage / output ───────────────────────────
def find_storage_root() -> str:
    candidates = [
        "/storage/emulated/0",
        "/sdcard",
        os.path.expanduser("~/storage/shared"),
        "/storage/self/primary",
        os.path.expanduser("~"),
    ]
    for p in candidates:
        if os.path.isdir(p) and os.access(p, os.W_OK):
            return p
    return os.path.expanduser("~")


def resolve_output_dir(settings: dict | None = None) -> str:
    s = settings or load_settings()
    custom = (s.get("output_dir") or "").strip()
    if custom:
        path = os.path.expanduser(custom)
    else:
        path = os.path.join(find_storage_root(), OUTPUT_FOLDER_NAME)
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        path = os.path.join(HOME_DIR, "output")
        os.makedirs(path, exist_ok=True)
    return path


def next_version_path(out_dir: str, base_name: str, ext: str = ".apk") -> str:
    """Automatic versioning: name.apk → name_SHADOWCRACK.apk → name_SHADOWCRACK_2.apk ..."""
    candidate = os.path.join(out_dir, f"{base_name}{ext}")
    n = 2
    while os.path.exists(candidate):
        candidate = os.path.join(out_dir, f"{base_name}_{n}{ext}")
        n += 1
    return candidate


# ─────────────────────────── input prompts ───────────────────────────
def prompt(msg: str, default: str = "") -> str:
    try:
        suffix = f" [{default}]" if default else ""
        val = input(f"  {msg}{suffix}: ").strip()
        return val or default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def confirm(msg: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    ans = prompt(f"{msg} ({hint})", "y" if default else "n").lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def expand_path(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p.strip().strip('"').strip("'")))
