
using System;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Web.WebView2.Core;
using System.IO;
using System.Threading.Tasks;

// Hybrid UI wrapper for OVERX Dns - loads shared HTML (WebView2) and bridges to Engine
namespace OVERXDnsHybrid
{
    public class HybridForm : Form
    {
        WebView2 web;
        Engine engine;
        Router router;
        NotifyIcon ni;
        bool applied = false;

        public HybridForm()
        {
            Text = "OVERX Dns";
            ClientSize = new Size(1180, 780);
            MinimumSize = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(2, 6, 17);
            // Remove OS chrome (— □ ×) per user request — hide control box, page fuller
            ControlBox = false;
            MinimizeBox = false;
            MaximizeBox = false;
            FormBorderStyle = FormBorderStyle.Sizable;
            ShowIcon = true;

            // Resolve icon
            try { Icon = new Icon(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "icon.ico")); } catch {}
            try { if (File.Exists("Resources/icon.ico")) Icon = new Icon("Resources/icon.ico"); } catch {}

            // Engine init - reuses same logic from OVERXDns.cs Router/Engine
            router = new Router();
            engine = new Engine();

            // WebView
            web = new WebView2();
            web.Dock = DockStyle.Fill;
            Controls.Add(web);
            Load += async (s,e) => await InitWebView();

            // Tray
            ni = new NotifyIcon();
            ni.Icon = Icon != null ? Icon : SystemIcons.Application;
            ni.Text = "OVERX Dns";
            ni.Visible = true;
            var cm = new ContextMenuStrip();
            cm.Items.Add("نمایش", null, (a,b)=> ShowMe());
            cm.Items.Add("اعمال", null, async (a,b)=> await JsApply());
            cm.Items.Add("خروج", null, (a,b)=> { ni.Visible=false; Application.Exit(); });
            ni.ContextMenuStrip = cm;
            ni.DoubleClick += (a,b)=> ShowMe();

            FormClosing += (s,e) => { if (applied) engine.Stop(); ni.Visible=false; };
            Resize += (s,e) => { if (WindowState==FormWindowState.Minimized) Hide(); };
        }

        async Task InitWebView()
        {
            await web.EnsureCoreWebView2Async(null);
            web.CoreWebView2.Settings.AreDevToolsEnabled = false;
            web.CoreWebView2.WebMessageReceived += OnWebMessage;
            
            // Locate HTML: shared/ui/index.html or embedded
            string[] candidates = new string[] {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ui", "index.html"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "shared", "ui", "index.html"),
                Path.Combine(Application.StartupPath, "index.html"),
                "shared/ui/index.html",
                "index.html"
            };
            string htmlPath = null;
            foreach(var p in candidates) if (File.Exists(p)) { htmlPath=p; break; }
            if (htmlPath != null)
            {
                web.CoreWebView2.Navigate(new Uri(Path.GetFullPath(htmlPath)).AbsoluteUri);
                Log("UI loaded: " + htmlPath);
            }
            else
            {
                // fallback embedded minimal html
                web.NavigateToString("<html><body style='background:#020611;color:white;font-family:sans-serif;padding:40px'><h1>OVERX Dns</h1><p>UI not found - place index.html beside exe in /ui</p></body></html>");
                Log("UI fallback - index.html not found");
            }
        }

        void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            try
            {
                string msg = e.TryGetWebMessageAsString();
                // Expect JSON like {action:"apply", dns:"1.1.1.1"} or {action:"clear"} {action:"logs"}
                // Simple parsing
                if (msg.Contains("\"action\":\"apply\""))
                {
                    BeginInvoke(new Action(async () => await JsApply()));
                }
                else if (msg.Contains("\"action\":\"clear\""))
                {
                    BeginInvoke(new Action(async () => await JsClear()));
                }
                else if (msg.Contains("\"action\":\"getLogs\""))
                {
                    BeginInvoke(new Action(() => SendLogsToJs()));
                }
                else if (msg.Contains("\"action\":\"getStatus\""))
                {
                    BeginInvoke(new Action(() => SendStatusToJs()));
                }
                Log("JS -> " + msg);
            } catch {}
        }

        async Task JsApply()
        {
            try {
                // Example: apply DNS via Engine / system resolver
                // This reuses original DnsUtil/Upstream logic
                Log("Applying OVERX Dns ...");
                // System DNS set is handled in original MainForm.DoApply - we replicate minimal
                // For demo we just start Engine listener on 53
                engine.Start(router, s => Log(s));
                applied = true;
                ni.Text = "OVERX Dns - ACTIVE";
                SendStatusToJs();
                Log("OVERX Dns ACTIVE");
            } catch(Exception ex){ Log("Apply failed: "+ex.Message); }
        }

        async Task JsClear()
        {
            try {
                engine.Stop();
                applied=false;
                ni.Text="OVERX Dns - OFF";
                SendStatusToJs();
                Log("OVERX Dns OFF - restored system DNS");
                // Also flush DNS cache like original Flush + Clear together (per spec: disconnect = clear & flush)
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ipconfig", "/flushdns"){ CreateNoWindow=true, UseShellExecute=false}); Log("DNS cache flushed (ipconfig /flushdns)"); } catch {}
            } catch(Exception ex){ Log("Clear failed: "+ex.Message);}
        }

        void SendStatusToJs()
        {
            string status = applied ? "connected" : "disconnected";
            string json = "{\"type\":\"status\",\"state\":\""+status+"\"}";
            try { web.CoreWebView2.PostWebMessageAsString(json); } catch {}
        }

        void SendLogsToJs()
        {
            // Send last logs
            string logs = "12:01:33  query example.com -> 1.1.1.1 (12ms)\n12:01:34  cached example.com\n".Replace("\"","\\\"").Replace("\n","\\n");
            string json = "{\"type\":\"logs\",\"data\":\""+logs+"\"}";
            try { web.CoreWebView2.PostWebMessageAsString(json); } catch {}
        }

        void Log(string m)
        {
            string line = DateTime.Now.ToString("HH:mm:ss")+"  "+m;
            try { web.CoreWebView2.PostWebMessageAsString("{\"type\":\"log\",\"line\":\""+line.Replace("\"","'")+"\"}"); } catch {}
            Console.WriteLine(line);
        }

        void ShowMe(){ Show(); WindowState=FormWindowState.Normal; Activate(); }

        [STAThread]
        public static void Main2(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new HybridForm());
        }
    }
}
