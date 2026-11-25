<p align="center">
  <b>🛡 SHADOW_CRACK · Advanced APK Shield Toolkit</b><br>
  <sub>maxshell-style · but faster, free & unlimited</sub>
</p>

---

## ⚡ One-Command Setup (Termux)

### Method 1 — GitHub Clone (recommended ✅)

**Termux me copy → paste → Enter. Bas!**

```bash
git clone https://github.com/vv588573-lab/shadow_crack.git ~/.shadow_crack && cd ~/.shadow_crack && bash install.sh
```

> 🌐 Public repo — bina login ke direct clone hoga. Installer khud sab dependencies handle karta hai.

### Method 2 — Download ZIP (bina git ke)

1. Browser me kholo → **github.com/vv588573-lab/shadow_crack**
2. Green **Code** button → **Download ZIP**
3. ZIP extract karo (file manager se bhi chalega), phir Termux me:

```bash
cd <extracted-folder> && bash install.sh
```

### Method 3 — Manual (tarball already on phone)

```bash
tar xzf shadow_crack.tar.gz && cd shadow_crack && bash install.sh
```

**Works on any Termux · Auto-handles everything · Zero config**

---

## 📱 Download Termux

Official F-Droid build · Android 7.0+ · arm64 / arm / x86 / x86_64

- [Termux v0.119 (F-Droid)](https://f-droid.org/repo/com.termux_1022.apk)

---

## 🎯 Core Features

| Feature | Details |
| --- | --- |
| 🔒 **6-Stage Engine** | `verify → clean → harden → align → sign → seal` — sab real, koi fake stage nahi |
| 🧹 **Archive Clean** | `.DS_Store`, `Thumbs.db`, `__MACOSX`, `.bak` junk auto-remove |
| 🗜️ **Resource Harden** | Saari compressed entries max-level recompress (APK chhoti hoti hai) |
| 📐 **Zip Align** | System `zipalign` ya built-in **pure-Python engine** (`.so` page-aligned) |
| ✍️ **Sign Engine** | `apksigner` → **v1+v2+v3** · fallback `jarsigner` (v1) · auto keystore |
| 🔑 **Keystore Manager** | Auto-generate / rotate / info — 1000 din validity, local & private |
| 🔍 **Deep Analyzer** | Package, version, SDK, permissions, DEX, native ABIs, cert, **risk flags** |
| 🛡️ **Protection Scanner** | **[8]** — v1/v2/v3 signature, zipalign, debuggable/testOnly, **packer/protection .so** (Jiagu, Bangcle, Tersafe, legu…) + Remove/Restore guide (sirf apne APK) |
| 📦 **Batch Mode** | Poore folder ke saare APK ek saath protect + summary table |
| 🧾 **History + SHA-256** | Har protect ka record with size delta & integrity hash |
| 🔢 **Auto Versioning** | `app_SHADOWCRACK.apk` → `app_SHADOWCRACK_2.apk` → … (kabhi overwrite nahi) |
| 🆓 **No Credits** | maxshell ki credits system yahan **nahi** — unlimited free |

---

## 🆚 shadow_crack vs maxshell

| | maxshell | **shadow_crack** |
| --- | --- | --- |
| Stages | 5 (mostly cosmetic) | **6 real working stages** |
| Credits | 1–2 per APK, website se lene padte hain | **0 — unlimited** |
| Batch mode | ❌ | ✅ |
| Deep analyzer + risk flags | ❌ | ✅ |
| Python zipalign (zipalign bin na ho tab bhi) | ❌ | ✅ |
| Signature verify after sign | partial | ✅ apksigner/jarsigner + SHA-256 seal |
| CLI flags (`-p/-a/-b/--verify/--scan`) | ❌ | ✅ |
| History | ✅ | ✅ + sha256 + size delta |
| Source | obfuscated / base64 | **clean, readable Python** |

---

## 🎨 Interface

```
╭────────────────────────────────────────────────────────────╮
│      ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗   ██╗   │
│      ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║   │
│      ███████╗███████║███████║██████╔╝██║   ██║██║   ██║   │
│      ██╔════╝██╔══██║██╔══██║██╔══██╗██║   ██║██║   ██║   │
│      ███████╗██║  ██║██║  ██║██║  ██║╚██████╔╝╚██████╔╝   │
│      ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝   │
├────────────────────────────────────────────────────────────┤
│              SHADOW_CRACK · ADVANCED APK SHIELD TOOLKIT        │
│              v1.1.0  ·  100% FREE · NO CREDITS · NO LIMITS │
├────────────────────────────────────────────────────────────┤
│  Mode     : FULL (unlimited protection)                    │
│  Device   : SHADOWCRACK-A3F9C2B71E4D                           │
├────────────────────────────────────────────────────────────┤
│   [1]   Protect APK                                        │
│   [2]   APK Analyzer                                       │
│   [3]   Batch Protect                                      │
│   [4]   History                                            │
│   [5]   Keystore Manager                                   │
│   [6]   Settings                                           │
│   [7]   About                                              │
│   [8]   Protection Scanner                                 │
│   [0]   Exit                                               │
╰────────────────────────────────────────────────────────────╯
```

### Protection pipeline output

```
▸ PROTECTION PIPELINE  myapp.apk

  [01] Verify APK .................. OK   (0.1s)
  [02] Clean Archive ............... OK   (0.3s)
  [03] Resource Harden ............. OK   (2.1s)
  [04] Zip Align ................... OK   (0.4s)
  [05] Sign Engine ................. OK   (1.2s)
  [06] Seal + Verify ............... OK   (0.3s)
```

---

## ⌨️ CLI Usage

```bash
shadow_crack                          # interactive menu
shadow_crack -p app.apk               # protect 1 APK
shadow_crack -p app.apk --no-sign     # protect without signing
shadow_crack -a app.apk               # deep analyze
shadow_crack -b ~/downloads/apks      # batch protect folder
shadow_crack --verify app.apk         # signature check only
shadow_crack --history                # show history
shadow_crack --keystore               # keystore status
shadow_crack --scan app.apk            # protection scanner report
shadow_crack --version                # version info
```

---

## 📁 Output Location

```
/storage/emulated/0/@SHADOW_CRACK/     (auto-detect hota hai)
```

Termux storage access chahiye: `termux-setup-storage`

Custom folder: menu → **[6] Settings → [1] Set output folder**

---

## ⚙️ System Requirements

| | |
| --- | --- |
| 📱 **Platform** | Termux (F-Droid) · Android 7.0+ |
| 💾 **Storage** | 300 MB free |
| 🧠 **RAM** | 1 GB minimum |
| ☕ **Java** | `pkg install openjdk-17` (signing ke liye — auto try hota hai) |
| 🐍 **Python** | 3.8+ (auto install) |

**Optional tools** (auto-install, na ho toh fallback hai):

| Tool | Kaam | Fallback |
| --- | --- | --- |
| `apksigner` | v1+v2+v3 signature | `jarsigner` (v1) |
| `zipalign` | system aligner | SHADOW_CRACK python engine |
| `aapt` | deep package info | regex-based manifest reader |
| `keytool` | keystore + cert info | signing skip (warn) |

---

## 🆘 Troubleshooting

| Issue | Fix |
| --- | --- |
| `Permission denied` | `chmod 755 ~/.shadow_crack/shadow_crack.py` |
| `Command not found` | `python3 ~/.shadow_crack/shadow_crack.py` |
| `Storage error` | `termux-setup-storage` |
| `keytool missing` | `pkg install openjdk-17` |
| `apksigner missing` | `pkg install apksigner` (nahi toh jarsigner chalega) |
| `Python missing` | `pkg install python` |
| APK install fail (Android 11+) | Play Protect OFF → Unknown sources ON → file manager se install karo |
| MIUI/HyperOS install block | Developer options → Install via USB → ON |

### 🗑️ Uninstall

```bash
rm -rf ~/.shadow_crack
rm -f  $PREFIX/bin/shadow_crack    # ya ~/.local/bin/shadow_crack
```

---

## 📜 License

MIT — see [LICENSE](LICENSE)

### ⚠️ Disclaimer

> Ye tool **legitimate APK protection** ke liye hai — sirf **apne khud ke** APK protect karo.
> Kisi aur ke application ko modify/repackage karna **illegal** hai aur iske liye aap khud zimmedar honge.

---

**⭐ Star this repo if SHADOW_CRACK helps you!**
