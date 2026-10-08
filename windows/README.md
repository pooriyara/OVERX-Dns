# OVERX Dns — Windows

Windows client for **OVERX Dns** — system-wide DNS engine (UDP / DoH / DoT) with smart routing, split-DNS rules, block lists, local cache and live logs.

> Renamed from `OverlordDns` → `OVERX Dns` (exact casing).

## UI

* Hybrid UI: `shared/ui/index.html` is the heart. Loaded in:
  * **Classic WinForms** (`OVERXDns.cs` / `MainForm`) — native controls, bottom nav: **Home · Logs · Settings** (Logs added, Gaming Mode removed)
  * **Hybrid WebView2** (`HybridForm.cs`) — renders the same HTML via `Microsoft.Web.WebView2` and bridges JS ↔ C# engine.

HTML changes per spec:

* **Removed:** `Gaming Mode` feature card + `🎮 Game Mode` quick card + “Gaming DNS” wording → `OVERX Dns`
* **Added:** `Logs` to sidebar + mobile bottom nav + dedicated `Logs` page (live, copy/clear/export, clickable domain → rule)

Icon: `assets/icon.png` → `Resources/icon.ico` + `ui/icon.png`. Used for window, systray, and HTML logo.

## Build

```bash
# .NET 8 Windows
dotnet restore
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained false -o publish
# or single exe:
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish-single
```

Output: `OVERX Dns.exe` (icon embedded). Installer optional via Inno Setup (see `.github/workflows/build-windows.yml`).

## Engine

`OVERXDns.cs` contains the full stack:

* `DnsUtil` / `DotClient` / `Upstream` (UDP, DoH GET/POST, DoT TLS 1.2+)
* `Router` (bootstrap, per-domain rules, NoAAAA, rescue)
* `Engine` (UDP listener on 127.0.0.1:53, cache with TTL, refresh)
* `Store` (registry `HKCU\Software\OVERX Dns`)
* `MainForm` (tray, 3-page nav, logs, firewall/QUIC)

Registry / mutex / tasks / firewall rules all renamed to `OVERX Dns`:

* `HKCU\Software\OVERX Dns`
* `OVERX DnsSingleInstance`
* `schtasks /tn OVERX Dns`
* `netsh advfirewall … name="OVERX Dns"` / `OVERX Dns QUIC`

## WebView2 Bridge

`HybridForm.cs` shows the pattern:

```csharp
web.CoreWebView2.WebMessageReceived += (s,e) => {
 var msg = e.TryGetWebMessageAsString(); // JSON {action:"apply"}
};
web.CoreWebView2.PostWebMessageAsString("{\"type\":\"log\",\"line\":\"...\"}");
```

JS side (`index.html`):

```js
chrome.webview.postMessage(JSON.stringify({action:"apply"}));
window.chrome.webview.addEventListener('message', e=> handleHostMessage(e.data));
```

## GitHub Actions

See `.github/workflows/build-windows.yml` — builds x64 + x86, uploads artifacts, optional release.

