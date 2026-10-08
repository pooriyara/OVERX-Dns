# OVERX Dns

<p align="center">
  <img src="assets/icon.png" width="170" style="filter:drop-shadow(0 0 24px #168cff66)" alt="OVERX Dns">
</p>

<h3 align="center">OVERX Dns — Lightweight • Fast • Secure</h3>
<p align="center">One icon. One HTML heart. Two platforms.</p>
<p align="center">
  <a href="windows/README.md"><b>Windows</b></a> • <a href="android/README.md"><b>Android</b></a> • <a href="shared/ui/index.html"><b>UI Preview</b></a>
  <br>
  <img src="https://img.shields.io/badge/Windows-.NET_8_|_WebView2-0078D4">
  <img src="https://img.shields.io/badge/Android-Kotlin_|_VpnService-3DDC84">
  <img src="https://img.shields.io/badge/UI-HTML_|_Logs_+_No_Gaming_Mode-7b35ff">
  <img src="https://img.shields.io/badge/Renamed-OverlordDns_→_OVERX_Dns-18d8ff">
</p>

---

## What's inside

```
OVERX-Dns/
├─ assets/              # icon.png (1254) + icon.ico + icon-{32,192,512}.png  ← single source
├─ shared/ui/           # index.html  ← THE HEART — used by both platforms
│   ├─ index.html       #  Gaming Mode removed, Logs added to bottom nav, OVERX Dns wording
│   └─ icon.png         #  same icon as logo + Android top-bar + Windows tray
├─ windows/             # .NET 8 WinForms (+ WebView2 Hybrid) — renamed to OVERX Dns
│   ├─ OVERX-Dns.sln
│   ├─ OVERX-Dns/
│   │   ├─ OVERXDns.cs          # full engine (21× OverlordDns → OVERX Dns)
│   │   ├─ HybridForm.cs        # WebView2 wrapper for shared UI
│   │   ├─ ui/index.html        # copied from shared
│   │   └─ Resources/icon.ico
│   └─ README.md
├─ android/             # Kotlin + VpnService + WebView — same HTML, same icon on status bar
│   ├─ app/src/main/assets/index.html   # copied from shared
│   ├─ app/src/main/java/com/overxdns/app/
│   │   ├─ MainActivity.kt     # WebView + AndroidBridge ↔ shared UI
│   │   ├─ DnsVpnService.kt    # TUN + DNS intercept + foreground notification (same icon)
│   │   └─ DnsEngine.kt        # UDP/DoH, cache, rescue
│   └─ README.md
└─ .github/workflows/   # build-windows.yml · build-android.yml · release.yml
```

### Rename guarantee

Every occurrence of `OverlordDns` (21x in `windows/OVERX-Dns/OVERXDns.cs`) was replaced with **exact** `OVERX Dns` (capital `O V E R X`, space, capital `D`, lower `ns`):

* registry `HKCU\Software\OVERX Dns`
* mutex `OVERX DnsSingleInstance`
* task `schtasks /tn OVERX Dns`
* firewall `netsh … name="OVERX Dns"` / `OVERX Dns QUIC`
* `USER_AGENT`, `appIcon.Text`, `Text = "OVERX Dns"`, etc.

Case-sensitive — `grep -c "OVERX Dns" windows/OVERX-Dns/OVERXDns.cs` → `21`.

### HTML changes — exactly like your screenshot + Logs

* **Base:** Windows hero با shield neon و کوهستان، ۳ کارت Lower Ping / Less Packet Loss / Better Routing (+ DNS Servers) دقیقا مثل تصویر؛ Android هم DNS Servers / Advanced Settings (بدون Game Mode)
* **Removed:** `<div class="feature"><b>Gaming Mode</b>…` and `<div class="card"><b>🎮 Game Mode</b>…` (حتی در تم Light/Aurora/Sunset هم حذف)
* **Reworded:** `Gaming DNS Active` → `OVERX Dns Active`, `Enable Gaming DNS` → `Enable OVERX Dns`, desc `Gaming DNS…` → `OVERX Dns…`, quick cards now: Smart Routing / Secure DNS / Rules & Split-DNS
* **Added:** `Logs` everywhere:
  * Sidebar: new item `≡ Logs`
  * Bottom nav (mobile): `DNS · Profiles · Logs · Settings · About` — `Logs` is the middle bottom-bar button
  * Dedicated page `#page-logs` with live scrolling, Copy / Clear / Export, auto-scroll toggle, clickable entry → rule demo
  * Windows native: `btnLogs` added to `navPanel` (now 3 buttons 152/252/352), `page == 1` = Logs, `FitWindow` / `UpdateNav` / `tbLog` updated, tray tooltip `Logs`

### Icon

Upload `file_00000000aa40820a82826bfde343cd4c.png` → processed to:

* `assets/icon.png` + `assets/icon.ico` (16–256)
* `shared/ui/icon.png`, `windows/ui/icon.png`, `windows/Resources/icon.ico` + `icon.png`
* `android/mipmap-*/ic_launcher.png` (48–192) + `ic_stat_overx.xml` (vector small icon)

**Android top-bar:** when `DnsVpnService` is connected, the persistent notification uses `smallIcon = @drawable/ic_stat_overx` + `largeIcon = @mipmap/ic_launcher` — so the icon appearing at the top of the phone *is* the same OVERX X-in-circle.

## Quick start

### Windows

```bash
cd windows
dotnet restore
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained false -o publish/win-x64
./publish/win-x64/"OVERX Dns.exe"        # systray + logs page
# Hybrid WebView2 demo (loads shared UI):
dotnet run --project OVERX-Dns/OVERX-Dns.csproj -c Release  # or set StartupObject to HybridForm
```

### Android

```bash
cd android
# copy shared UI (workflow does this automatically)
cp ../shared/ui/index.html app/src/main/assets/index.html
cp ../shared/ui/icon.png   app/src/main/assets/icon.png
# build
./gradlew assembleDebug   # → app/build/outputs/apk/debug/app-debug.apk
adb install app/build/outputs/apk/debug/app-debug.apk
# open app → WebView → Apply → grant VPN → notification with OVERX icon appears at top
```

### Edit UI

Edit **once** in `shared/ui/index.html`, it propagates:

```bash
# manual sync (also in CI)
cp shared/ui/index.html windows/OVERX-Dns/ui/index.html
cp shared/ui/index.html android/app/src/main/assets/index.html
cp shared/ui/icon.png   windows/OVERX-Dns/ui/icon.png
cp shared/ui/icon.png   android/app/src/main/assets/icon.png
```

## GitHub publishing

1. Create repo `overx-dns/overx-dns` (or yours), push:
   ```bash
   git init
   git add .
   git commit -m "OVERX Dns v1.0.0 — Windows+Android, shared HTML, Logs, renamed"
   git branch -M main
   git remote add origin https://github.com/<you>/overx-dns.git
   git push -u origin main
   ```
2. Push a tag → Release workflow builds both:
   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   # → Actions: Build Windows (windows-latest + .NET 8) + Build Android (ubuntu + JDK17/Gradle)
   # → artifacts: OVERX-Dns-Windows.zip + OVERX-Dns-Android.apk
   # → GitHub Release with binaries
   ```
   Manual dispatch also works (Actions → Release → Run workflow).

Local builds need no GitHub — `dotnet publish` / `./gradlew assembleDebug` produce the same bits.

## License

MIT © 2026 OVERX. The icon and HTML are original (C2PA-signed source kept in `assets/`).

---

<p align="center"><i>Built for the Persian community — UI supports English / فارسی (Store lang_fa).</i></p>
