#!/usr/bin/env bash
# SHADOW_CRACK launcher — ye file $PREFIX/bin/shadow_crack se link hoti hai
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/shadow_crack.py" "$@"
