# Changelog

## 1.0.0 — 2026-10-08
- Initial release as **OVERX Dns** (renamed from OverlordDns, 21 replacements)
- Shared HTML heart `shared/ui/index.html` — Gaming Mode removed, Logs added to bottom nav, OVERX Dns wording
- Windows: .NET 8 WinForms + WebView2 hybrid, 3-page nav (Home · Logs · Settings), icon everywhere
- Android: Kotlin VpnService + WebView, same HTML + same icon on status bar when connected, DoH/DoT, cache, split-DNS
- GitHub Actions: build-windows.yml (win-x64) + build-android.yml (APK/AAB) + release.yml
