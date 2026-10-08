# OVERX Dns — Android

Android client for **OVERX Dns**. Same HTML heart (`shared/ui/index.html`) as Windows, rendered in a `WebView`. The VPN service intercepts DNS (port 53) and forwards to the selected upstream (Cloudflare / Google / Quad9 / Shecan / Electro) with DoH fallback, local cache and live logs.

> Spec: gaming mode removed, Logs added to bottom bar, status-bar icon = same OVERX icon when connected.

## What it does

* **UI:** `index.html` loaded via `file:///android_asset/index.html` — sidebar + bottom nav (`DNS · Profiles · Logs · Settings · About`). The `Logs` page is the new bottom-bar item.
* **Bridge:** JS `chrome.webview.postMessage` / `AndroidBridge.postMessage` ↔ Kotlin `@JavascriptInterface`
  * `{"action":"apply"}` → request VPN permission → start `DnsVpnService`
  * `{"action":"clear"}` → stop VPN
  * Host pushes `{"type":"status","state":"connected"}` and `{"type":"log","line":"..."}` into WebView
* **VPN:** `DnsVpnService : VpnService`
  * Creates `Builder` TUN `10.211.0.1/24`, `addRoute 0.0.0.0/0`, adds selected DNS servers
  * Reads raw packets from TUN, parses IPv4+UDP port 53, extracts DNS query, resolves via `DnsEngine` (UDP → DoH fallback → rescue 8.8.8.8), builds response packet (swap IP/ports, recalc checksums) and writes back
  * Shows **foreground notification** with the same OVERX icon (`@mipmap/ic_launcher` large + `@drawable/ic_stat_overx` small) — visible at the top status bar while connected (per requirement)
  * `blockQuic` / `noAAAA` / `useRescue` obey `SettingsStore` flags
* **Engine:** `DnsEngine` mirrors Windows `Router/Upstream` logic: UDP → DoH GET (`application/dns-message`), cache (TTL 60–3600s), bootstrap, short-circuit for AAAA when enabled, block/unknown handling.

## Icon

`assets/icon.png` (1254×1254 original) is:

* `mipmap-*/ic_launcher.png` (launcher + notification large icon)
* `drawable/ic_stat_overx.xml` (status-bar small icon, monochrome vector derived from same X-in-circle)
* `assets/index.html` logo + `shared/ui/icon.png`

When the VPN is **connected**, `DnsVpnService.buildNotification()` uses both icons — so the icon appearing at the top of the phone *is* the same OVERX mark.

## Build

```bash
cd android
./gradlew assembleDebug           # → app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease         # → app/build/outputs/apk/release/app-release-unsigned.apk
# signed release via keystore:
./gradlew assembleRelease -PstoreFile=../release.keystore -PstorePassword=... -PkeyPassword=... -PkeyAlias=overx
# or: bundleRelease
./gradlew bundleRelease
```

Requires JDK 17, Android SDK 34, `local.properties` with `sdk.dir`.

## HTML sync

`shared/ui/index.html` is the single source. The Gradle build copies it:

```
shared/ui/index.html ──▶ android/app/src/main/assets/index.html
shared/ui/icon.png   ──▶ android/app/src/main/assets/icon.png
```

To edit UI: modify `shared/ui/index.html` (already has Logs page, no Gaming Mode) and rerun.

## Permissions

```
INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, POST_NOTIFICATIONS, BIND_VPN_SERVICE
```

`VpnService.prepare()` prompt is shown on first Apply.

## Store

`SettingsStore` (SharedPreferences `OVERX_Dns`) mirrors Windows registry `HKCU\Software\OVERX Dns`:

* `dns_profile`, `primary_dns`, `secondary_dns`, `doh_url`, `connected`, `block_quic`, `no_aaaa`, `use_rescue`, `lang_fa`, `logs`

