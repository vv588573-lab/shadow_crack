#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  SHADOW_CRACK · Installer v1.0.0
#  Advanced APK Shield Toolkit for Termux
#  Usage:  bash install.sh
# ─────────────────────────────────────────────
set -u

TOOL="SHADOW_CRACK"
VER="1.0.0"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.shadow_crack"
BIN_DIR="${PREFIX:-/usr/local}/bin"

# ── colors ──
if [ -t 1 ]; then
  R=$'\033[0m'; M=$'\033[95m'; G=$'\033[92m'; Y=$'\033[93m'; C=$'\033[96m'; GR=$'\033[90m'; B=$'\033[1m'
else
  R=""; M=""; G=""; Y=""; C=""; GR=""; B=""
fi

ok()   { printf "  ${G}[+]${R} %s\n" "$1"; }
info() { printf "  ${C}[*]${R} %s\n" "$1"; }
warn() { printf "  ${Y}[!]${R} %s\n" "$1"; }
die()  { printf "  ${R}[-]${R} %s\n" "$1"; exit 1; }

box_top() { printf "${GR}╭──────────────────────────────────────────────╮${R}\n"; }
box_bot() { printf "${GR}╰──────────────────────────────────────────────╯${R}\n"; }
box_mid() { printf "${GR}├──────────────────────────────────────────────┤${R}\n"; }
ctr() {
  local t="$1" esc=$'\033' vis len pad
  vis="$(printf '%s' "$t" | sed "s/${esc}\[[0-9;]*m//g")"
  len=${#vis}
  pad=$(( (46 - len) / 2 ))
  [ "$pad" -lt 0 ] && pad=0
  printf "${GR}│${R}%*s%s%*s${GR}│${R}\n" "$pad" '' "$t" "$(( 46 - len - pad ))" ''
}

clear 2>/dev/null || true
# ASCII art printed raw (box sirf chhote ASCII text ke liye — locale-safe centering)
printf '%s\n' \
"${M}${B} ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗   ██╗${R}" \
"${M}${B} ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║${R}" \
"${M}${B} ███████╗███████║███████║██████╔╝██║   ██║██║   ██║${R}" \
"${M}${B} ██╔════╝██╔══██║██╔══██║██╔══██╗██║   ██║██║   ██║${R}" \
"${M}${B} ███████╗██║  ██║██║  ██║██║  ██║╚██████╔╝╚██████╔╝${R}" \
"${M}${B} ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝${R}" \
"${M}${B} ██████╗  ██████╗ █████╗ ██████╗ ██╗  ██╗${R}" \
"${M}${B} ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝${R}" \
"${M}${B} ██║     ██████║ ███████║██║     ██████╔╝${R}" \
"${M}${B} ██║     ██╔══██╗██╔══██╗██║     ██╔══██╗${R}" \
"${M}${B} ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██║${R}" \
"${M}${B} ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝${R}"
box_top
ctr "${M}${B}SHADOW_CRACK INSTALLER v${VER}${R}"
ctr "${G}100% FREE - NO CREDITS - NO LIMITS${R}"
box_bot
echo

# ── 1. Termux detection ──
info "Environment check..."
# Robust detection: PREFIX ke bina bhi chalta hai (pkg / dir / TERMUX_VERSION / HOME)
IS_TERMUX=0
if command -v pkg >/dev/null 2>&1 \
   || [ -n "${TERMUX_VERSION:-}" ] \
   || [ -d /data/data/com.termux ] \
   || [ -n "${PREFIX:-}" ]; then
  IS_TERMUX=1
  ok "Termux detected"
else
  case "${HOME:-}" in
    *com.termux*) IS_TERMUX=1; ok "Termux detected (home path)" ;;
    *) warn "Termux nahi mila — generic Linux mode (paths adjust ho jayenge)" ;;
  esac
fi

# ── 2. Basic deps ──
need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  return 1
}

info "Checking dependencies..."
if [ "$IS_TERMUX" = 1 ]; then
  pkg update -y >/dev/null 2>&1 || true
  for p in python zip unzip; do
    if ! need "$p" && [ "$p" != "python" ] || ! need python3; then
      case "$p" in
        python) need python3 || pkg install -y python >/dev/null 2>&1 || warn "python install fail" ;;
        zip)    need zip    || pkg install -y zip >/dev/null 2>&1 || warn "zip install fail" ;;
        unzip)  need unzip  || pkg install -y unzip >/dev/null 2>&1 || warn "unzip install fail" ;;
      esac
    fi
  done
  # optional but recommended
  need keytool   || pkg install -y openjdk-17 >/dev/null 2>&1 || info "openjdk-17 (optional) — abhi skip, baad me: pkg install openjdk-17"
  need apksigner || pkg install -y apksigner >/dev/null 2>&1   || info "apksigner (optional) — jarsigner fallback active"
  need zipalign  || pkg install -y zipalign >/dev/null 2>&1    || info "zipalign (optional) — SHADOW_CRACK python engine use karega"
  need aapt      || pkg install -y aapt >/dev/null 2>&1        || info "aapt (optional) — analyzer deep-info ke liye"
else
  need python3 || die "python3 install karo (apt install python3)"
  need zip || warn "zip recommended"
fi

need python3 || die "python3 chahiye hi chahiye"
ok "python3 $(python3 --version 2>&1 | awk '{print $2}') ready"

# ── 3. Install files ──
info "Installing $TOOL → $DEST"
mkdir -p "$DEST"
if [ "$(readlink -f "$SRC" 2>/dev/null || echo "$SRC")" != "$(readlink -f "$DEST" 2>/dev/null || echo "$DEST")" ]; then
  cp -f "$SRC/shadow_crack.py" "$DEST/shadow_crack.py" 2>/dev/null || die "shadow_crack.py copy fail"
  rm -rf "$DEST/core"
  cp -r "$SRC/core" "$DEST/core" || die "core/ copy fail"
  cp -f "$SRC/launcher.sh" "$DEST/launcher.sh" 2>/dev/null || true
  cp -f "$SRC/README.md" "$DEST/README.md" 2>/dev/null || true
fi
chmod 755 "$DEST/shadow_crack.py" 2>/dev/null || true
[ -f "$DEST/launcher.sh" ] && chmod 755 "$DEST/launcher.sh"

# ── 4. Global command ──
info "Creating command 'shadow_crack'..."
mkdir -p "$BIN_DIR" 2>/dev/null || true
LAUNCHER="$BIN_DIR/shadow_crack"
if touch "$BIN_DIR/.shadowcrack_write_test" 2>/dev/null; then
  rm -f "$BIN_DIR/.shadowcrack_write_test"
  cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
exec python3 "$DEST/shadow_crack.py" "\$@"
EOF
  chmod 755 "$LAUNCHER"
  ok "command installed: $LAUNCHER"
else
  # fallback: ~/.local/bin
  FB="$HOME/.local/bin"
  mkdir -p "$FB"
  cat > "$FB/shadow_crack" <<EOF
#!/usr/bin/env bash
exec python3 "$DEST/shadow_crack.py" "\$@"
EOF
  chmod 755 "$FB/shadow_crack"
  warn "no write access to $BIN_DIR → installed at $FB/shadow_crack"
  case ":$PATH:" in
    *":$FB:"*) ok "$FB already in PATH" ;;
    *) warn "PATH me add karo:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
  esac
fi

# ── 5. First-run data dir ──
mkdir -p "$DEST/backups" "$HOME/.shadow_crack"

# ── 6. Done ──
echo
box_top
ctr "${G}${B}INSTALL SUCCESSFUL${R}"
box_mid
ctr "${C}Launch : shadow_crack${R}"
ctr "${C}Or     : python3 ~/.shadow_crack/shadow_crack.py${R}"
box_bot
echo
printf "  ${Y}[!]${R} Android 11+ install issue? → Play Protect OFF → Unknown sources ON\n"
printf "  ${Y}[!]${R} Apna hi APK protect karo — kisi aur ka modify karna illegal hai\n"
echo

echo
if [ -t 0 ]; then
  read -r -p "  Abhi launch karein? [Y/n] " ans </dev/tty 2>/dev/null || ans=""
  case "${ans:-Y}" in
    [Nn]*) info "Done — kabhi bhi chalao:  shadow_crack" ;;
    *)     exec python3 "$DEST/shadow_crack.py" ;;
  esac
else
  info "Launch karne ke liye type karo:  shadow_crack"
fi
