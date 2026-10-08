# OVERX Dns — مستند فنی (Persian notes)

این پروژه نسخه‌ی بازنویسی‌شده‌ی نرم‌افزار DNS قبلی شما (`OVERXDns.txt` → `OVERX Dns`) است که قالب HTML شما را به عنوان قلب مشترک ویندوز و اندروید ادغام کرده است.

## انجام‌شده‌ها

**۱. تغییر نام:** همه‌ی ۲۱ مورد `OverlordDns` به `OVERX Dns` (حروف بزرگ/کوچک دقیق) جایگزین شد:
- رجیستری `HKCU\Software\OVERX Dns`
- Mutex `OVERX DnsSingleInstance`
- Task `OVERX Dns`
- فایروال `OVERX Dns` + `OVERX Dns QUIC`
- User-Agent، متن‌ها، Tray

**۲. HTML (قلب):**
- حذف بخش گیمینگ: `Gaming Mode` (feature) و `🎮 Game Mode` (quick card) حذف شدند
- متون `Gaming DNS …` → `OVERX Dns …`
- افزودن `Logs` به نوار پایین: سایدبار + BottomNav موبایل شامل ۵ آیتم `DNS · Profiles · Logs · Settings · About` — `Logs` دکمه‌ی وسط پایین است
- صفحه‌ی اختصاصی لاگ‌ها با اسکرول زنده، کپی/پاک/خروجی، Auto-scroll
- لوگو و آیکون‌ها از فایل ارسالی شما (`icon.png`) گرفته شد

**۳. آیکون:**
- تصویر شما به `icon.ico` (16–256) + `mipmap-*` (48–192) + `ic_stat_overx.xml` تبدیل شد
- ویندوز: آیکون پنجره، سینی، فایل اجرایی و لوگوی HTML
- اندروید: آیکون لانچر + نوار وضعیت (notification small/large icon) هنگام اتصال همان آیکون است

**۴. ویندوز:**
- `OVERXDns.cs` با سه‌صفحه‌ی ناوبری Noweb (Home/Logs/Settings) — `btnLogs` جدید
- `HybridForm.cs` برای بارگذاری HTML با WebView2 و پل `PostWebMessage`
- پروژه‌ی `.NET 8` + WebView2، آماده‌ی `dotnet publish`

**۵. اندروید:**
- `MainActivity` با WebView + پل `AndroidBridge`
- `DnsVpnService` با TUN و نوتیفیکیشن Foreground دارای آیکون OVERX در بالای پرده
- `DnsEngine` با UDP/DoH و کش

**۶. آماده‌ی انتشار روی گیت‌هاب:**
- سه workflow: `build-windows.yml`, `build-android.yml`, `release.yml`
- `README.md`, `LICENSE`, `sync-ui.sh`, تگ `v1.0.0` → ریلیز خودکار

## انتشار

```bash
git init
git add .
git commit -m "OVERX Dns v1.0.0"
git remote add origin https://github.com/<you>/overx-dns.git
git push -u origin main
git tag v1.0.0 && git push origin v1.0.0
```
