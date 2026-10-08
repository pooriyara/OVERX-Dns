# Themes — مطابق تصویر ارسالی

تصویر ارسالی 4 تم و یک Header/ Icon را نشان می‌دهد. پیاده شد:

| Theme | CSS | رنگ |
|---|---|---|
| **Dark Galaxy** | `data-theme="dark"` (default) | #050a1e → #0b102e ، neon cyan #19d6ff ، mountain #0f1a44→#1a0b2e |
| **Light Theme** | `data-theme="light"` | سفید #ffffff ، #eef2ff ، cyan #0a7dff |
| **Aurora** | `data-theme="aurora"` | #041210 → #0a2420 ، teal #2affd8 |
| **Sunset** | `data-theme="sunset"` | #1a0808 → #2a0f0f ، orange #ff9a3d |

سوییچ: دات‌های بالا در سایدبار + کارت‌های تم در صفحه DNS/Settings + `localStorage("overx_theme")`

تصویر وسط Windows App: هیرو با `ring` + `shield` + mountain SVG + stats + toggle `Enable OVERX Dns`
تصویر Android: WebView همین HTML — ریسپانسیو با Bottom Nav 4تایی `DNS · Profiles · Logs · Settings` (Logs جدید)

همه تم‌ها روی ویندوز (WebView2) و اندروید (WebView) یکسان کار می‌کنند — انتخاب تم از JS به Kotlin/C# بریج هم می‌رود (`AndroidBridge.postMessage({theme})`).
