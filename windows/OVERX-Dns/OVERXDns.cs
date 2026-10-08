using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.InteropServices;

class Entry
{
    public string Name = "", Type = "UDP", Primary = "", Secondary = "", Url = "";
    public override string ToString() { return Name + "  (" + Type + ")"; }
    public string ToLine() { return Name + "|" + Type + "|" + Primary + "|" + Secondary + "|" + Url; }
}

class Rule { public string Domain = ""; public bool Block, UseOrig; public Entry Target; }

class CacheItem
{
    public byte[] Data; public DateTime Expire;
    public CacheItem(byte[] d, int ttl) { Data = d; Expire = DateTime.UtcNow.AddSeconds(ttl); }
}

// ---------------------------------------------------------------- DNS helpers
static class DnsUtil
{
    public static byte[] BuildQuery(string domain)
    {
        List<byte> b = new List<byte>();
        b.AddRange(new byte[] { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 });
        foreach (string part in domain.Split('.'))
        {
            b.Add((byte)part.Length);
            b.AddRange(Encoding.ASCII.GetBytes(part));
        }
        b.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return b.ToArray();
    }

    public static string QName(byte[] q, out int qtype, out int qend)
    {
        qtype = 0; qend = q.Length;
        StringBuilder sb = new StringBuilder();
        int p = 12;
        while (true)
        {
            if (p >= q.Length) return sb.ToString();
            int l = q[p++];
            if (l == 0) break;
            if ((l & 0xC0) != 0 || p + l > q.Length) return sb.ToString();
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(q, p, l));
            p += l;
        }
        if (p + 4 <= q.Length) { qtype = (q[p] << 8) | q[p + 1]; qend = p + 4; }
        return sb.ToString().ToLowerInvariant();
    }

    public static int SkipName(byte[] b, int pos)
    {
        while (true)
        {
            int len = b[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;
            pos += len + 1;
        }
    }

    // build a reply from a query: rcode, optional single A record
    public static byte[] Make(byte[] q, int rcode, string ip)
    {
        int qt, qend;
        QName(q, out qt, out qend);
        int ans = ip != null ? 16 : 0;
        byte[] r = new byte[qend + ans];
        Buffer.BlockCopy(q, 0, r, 0, qend);
        r[2] = 0x81; r[3] = (byte)(0x80 | rcode);
        r[4] = 0; r[5] = 1; r[6] = 0; r[7] = (byte)(ip != null ? 1 : 0);
        r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0;
        if (ip != null)
        {
            int p = qend;
            r[p++] = 0xC0; r[p++] = 0x0C;
            r[p++] = 0; r[p++] = 1; r[p++] = 0; r[p++] = 1;
            r[p++] = 0; r[p++] = 0; r[p++] = 1; r[p++] = 0x2C;
            r[p++] = 0; r[p++] = 4;
            string[] o = ip.Split('.');
            for (int i = 0; i < 4; i++) r[p++] = byte.Parse(o[i]);
        }
        return r;
    }

    public static int MinTtl(byte[] r)
    {
        long min = -1;
        try
        {
            int qd = (r[4] << 8) | r[5];
            int total = ((r[6] << 8) | r[7]) + ((r[8] << 8) | r[9]) + ((r[10] << 8) | r[11]);
            int p = 12;
            for (int i = 0; i < qd; i++) p = SkipName(r, p) + 4;
            for (int i = 0; i < total; i++)
            {
                p = SkipName(r, p);
                int type = (r[p] << 8) | r[p + 1];
                long ttl = ((long)r[p + 4] << 24) | ((long)r[p + 5] << 16) | ((long)r[p + 6] << 8) | r[p + 7];
                int rdl = (r[p + 8] << 8) | r[p + 9];
                if (type != 41 && (min < 0 || ttl < min)) min = ttl;
                p += 10 + rdl;
            }
        }
        catch { }
        return min > int.MaxValue ? int.MaxValue : (int)min;
    }

    public static List<string> ParseA(byte[] r)
    {
        List<string> res = new List<string>();
        try
        {
            int qd = (r[4] << 8) | r[5];
            int an = (r[6] << 8) | r[7];
            int p = 12;
            for (int i = 0; i < qd; i++) p = SkipName(r, p) + 4;
            for (int i = 0; i < an; i++)
            {
                p = SkipName(r, p);
                int type = (r[p] << 8) | r[p + 1];
                int rdl = (r[p + 8] << 8) | r[p + 9];
                p += 10;
                if (type == 1 && rdl == 4) res.Add(r[p] + "." + r[p + 1] + "." + r[p + 2] + "." + r[p + 3]);
                p += rdl;
            }
        }
        catch { }
        return res;
    }

    public static bool LooksForged(byte[] r)
    {
        foreach (string ip in ParseA(r))
            if (ip.StartsWith("10.10.34.") || ip.StartsWith("10.10.35.")) return true;
        return false;
    }

    public static string Summ(byte[] r)
    {
        if (r == null || r.Length < 12) return "no answer";
        int rc = r[3] & 0x0F;
        if (rc == 3) return "NXDOMAIN";
        List<string> a = ParseA(r);
        if (a.Count > 0) return string.Join(", ", a.GetRange(0, Math.Min(4, a.Count)).ToArray());
        return rc == 0 ? "ok (no A record)" : "rcode " + rc;
    }

    public static string TypeName(int t)
    {
        switch (t) { case 1: return "A"; case 28: return "AAAA"; case 5: return "CNAME"; case 15: return "MX"; case 16: return "TXT"; case 65: return "HTTPS"; case 12: return "PTR"; }
        return "T" + t;
    }

    // returns null on clean EOF at the start
    public static byte[] ReadExact(Stream s, int n)
    {
        byte[] buf = new byte[n]; int got = 0;
        while (got < n)
        {
            int r = s.Read(buf, got, n - got);
            if (r <= 0) { if (got == 0) return null; throw new IOException("connection closed"); }
            got += r;
        }
        return buf;
    }
}

// ---------------------------------------------------------------- upstream clients
class DotClient
{
    string ip, sni; bool strict;
    TcpClient tcp; SslStream ssl; object sync = new object();
    public string LastErr;
    static SslProtocols proto = (SslProtocols)0; // 0 = let Windows pick (TLS 1.2/1.3)

    public DotClient(string ip, string sni, bool strict) { this.ip = ip; this.sni = sni; this.strict = strict; }

    public byte[] Query(byte[] q)
    {
        lock (sync)
        {
            for (int a = 0; a < 2; a++)
            {
                try
                {
                    if (ssl == null) Connect();
                    byte[] msg = new byte[q.Length + 2];
                    msg[0] = (byte)(q.Length >> 8); msg[1] = (byte)(q.Length & 0xFF);
                    Buffer.BlockCopy(q, 0, msg, 2, q.Length);
                    ssl.Write(msg, 0, msg.Length); ssl.Flush();
                    byte[] lb = DnsUtil.ReadExact(ssl, 2);
                    if (lb == null) throw new IOException("closed");
                    byte[] r = DnsUtil.ReadExact(ssl, (lb[0] << 8) | lb[1]);
                    if (r == null) throw new IOException("closed");
                    return r;
                }
                catch (Exception ex) { LastErr = ex.Message; if (ex.InnerException != null) LastErr += " / " + ex.InnerException.Message; Close(); }
            }
            return null;
        }
    }

    void Connect()
    {
        tcp = new TcpClient(); tcp.NoDelay = true;
        IAsyncResult ar = tcp.BeginConnect(ip, 853, null, null);
        if (!ar.AsyncWaitHandle.WaitOne(4000)) throw new TimeoutException("connect timeout");
        tcp.EndConnect(ar);
        for (int i = 0; i < 3; i++)
        {
            ssl = new SslStream(tcp.GetStream(), false,
                delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return !strict || e == SslPolicyErrors.None; });
            ssl.ReadTimeout = 5000; ssl.WriteTimeout = 5000;
            try { ssl.AuthenticateAsClient(sni, null, proto, false); return; }
            catch (ArgumentException) { if (i == 1) throw; proto = SslProtocols.Tls12; }
        }
    }

    void Close()
    {
        try { if (ssl != null) ssl.Close(); } catch { }
        try { if (tcp != null) tcp.Close(); } catch { }
        ssl = null; tcp = null;
    }
}

static class Upstream
{
    static Dictionary<string, DotClient[]> dots = new Dictionary<string, DotClient[]>();
    static int dotRr;

    [ThreadStatic] public static string LastError;

    public static byte[] Forward(Entry e, byte[] q)
    {
        LastError = null;
        try
        {
            byte[] r;
            if (e.Type == "DOH") r = Doh(e, q);
            else if (e.Type == "DOT") r = Dot(e, q);
            else r = Udp(e, q);
            if (r != null && r.Length >= 12) return r;
            if (LastError == null)
                LastError = e.Type == "UDP" ? "no UDP reply from " + e.Primary + " (port 53 closed, firewall, or your IP is not allowed)" : "empty reply";
            return null;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            if (ex.InnerException != null) LastError += " / " + ex.InnerException.Message;
            return null;
        }
    }

    static byte[] Udp(Entry e, byte[] q)
    {
        List<IPEndPoint> eps = new List<IPEndPoint>();
        string[] ips = new string[] { e.Primary, e.Secondary };
        foreach (string ip in ips)
        {
            IPAddress a;
            if (!string.IsNullOrEmpty(ip) && IPAddress.TryParse(ip, out a) &&
                (eps.Count == 0 || a.AddressFamily == eps[0].AddressFamily))
                eps.Add(new IPEndPoint(a, 53));
        }
        if (eps.Count == 0) return null;
        byte[] r = UdpRace(eps, q);
        if (r != null && (r[2] & 0x02) != 0)
        {
            byte[] t = TcpOne(eps[0].Address.ToString(), q);
            if (t != null) r = t;
        }
        return r;
    }

    // fast retransmits (a lost UDP packet costs ~0.4s instead of 2s); secondary joins from the 2nd try
    static byte[] UdpRace(List<IPEndPoint> eps, byte[] q)
    {
        int[] waits = new int[] { 350, 500, 700 };
        byte[] suspect = null;
        AddressFamily fam = eps[0].AddressFamily;
        using (Socket s = new Socket(fam, SocketType.Dgram, ProtocolType.Udp))
        {
            byte[] buf = new byte[4096];
            for (int attempt = 0; attempt < waits.Length; attempt++)
            {
                try
                {
                    s.SendTo(q, eps[0]);
                    if (attempt > 0 && eps.Count > 1) s.SendTo(q, eps[1]);
                    DateTime end = DateTime.UtcNow.AddMilliseconds(waits[attempt]);
                    while (true)
                    {
                        int left = (int)(end - DateTime.UtcNow).TotalMilliseconds;
                        if (left <= 0) break;
                        s.ReceiveTimeout = left;
                        EndPoint from = new IPEndPoint(fam == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                        int n = s.ReceiveFrom(buf, ref from);
                        if (n >= 12 && buf[0] == q[0] && buf[1] == q[1])
                        {
                            byte[] r = new byte[n];
                            Buffer.BlockCopy(buf, 0, r, 0, n);
                            if (DnsUtil.LooksForged(r)) { if (suspect == null) suspect = r; continue; }
                            return r;
                        }
                    }
                }
                catch (SocketException) { }
            }
        }
        return suspect;
    }
    static byte[] TcpOne(string ip, byte[] q)
    {
        try
        {
            using (TcpClient c = new TcpClient())
            {
                IAsyncResult ar = c.BeginConnect(ip, 53, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(2000)) return null;
                c.EndConnect(ar);
                c.ReceiveTimeout = 3000;
                NetworkStream ns = c.GetStream();
                byte[] msg = new byte[q.Length + 2];
                msg[0] = (byte)(q.Length >> 8); msg[1] = (byte)(q.Length & 0xFF);
                Buffer.BlockCopy(q, 0, msg, 2, q.Length);
                ns.Write(msg, 0, msg.Length);
                byte[] lb = DnsUtil.ReadExact(ns, 2);
                if (lb == null) return null;
                return DnsUtil.ReadExact(ns, (lb[0] << 8) | lb[1]);
            }
        }
        catch { return null; }
    }

    static byte[] Dot(Entry e, byte[] q)
    {
        DotClient[] pool; string k = e.ToLine();
        lock (dots)
        {
            if (!dots.TryGetValue(k, out pool))
            {
                string ip = e.Primary != "" ? e.Primary : e.Url;
                string sni = e.Url != "" ? e.Url : e.Primary;
                pool = new DotClient[4];
                for (int i = 0; i < pool.Length; i++) pool[i] = new DotClient(ip, sni, e.Url != "");
                dots[k] = pool;
            }
        }
        DotClient c = pool[(int)((uint)Interlocked.Increment(ref dotRr) % 4)];
        byte[] rr = c.Query(q);
        if (rr == null) LastError = c.LastErr;
        return rr;
    }

    static byte[] Doh(Entry e, byte[] q)
    {
        try { return DohPost(e, q); }
        catch (WebException ex)
        {
            HttpWebResponse hr = ex.Response as HttpWebResponse;
            if (hr != null && (hr.StatusCode == HttpStatusCode.MethodNotAllowed || hr.StatusCode == HttpStatusCode.BadRequest ||
                hr.StatusCode == HttpStatusCode.UnsupportedMediaType || hr.StatusCode == HttpStatusCode.NotImplemented))
                return DohGet(e, q);
            throw;
        }
    }

    static HttpWebRequest NewReq(string url, string method)
    {
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Method = method;
        req.Accept = "application/dns-message";
        req.Proxy = null;
        req.Timeout = 5000; req.ReadWriteTimeout = 5000;
        req.KeepAlive = true;
        req.UserAgent = "OVERX Dns";
        req.ServicePoint.UseNagleAlgorithm = false;
        return req;
    }

    static byte[] DohRead(HttpWebRequest req)
    {
        using (HttpWebResponse rs = (HttpWebResponse)req.GetResponse())
        using (Stream rd = rs.GetResponseStream())
        {
            MemoryStream ms = new MemoryStream();
            rd.CopyTo(ms);
            return ms.ToArray();
        }
    }

    static byte[] DohPost(Entry e, byte[] q)
    {
        HttpWebRequest req = NewReq(e.Url, "POST");
        req.ContentType = "application/dns-message";
        req.ContentLength = q.Length;
        using (Stream s = req.GetRequestStream()) s.Write(q, 0, q.Length);
        return DohRead(req);
    }

    static byte[] DohGet(Entry e, byte[] q)
    {
        string b64 = Convert.ToBase64String(q).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string url = e.Url + (e.Url.Contains("?") ? "&" : "?") + "dns=" + b64;
        return DohRead(NewReq(url, "GET"));
    }
}

// ---------------------------------------------------------------- routing + engine
class Router
{
    public Entry Main, Fallback;
    public List<Rule> Rules = new List<Rule>();
    public Dictionary<string, string> Bootstrap = new Dictionary<string, string>();
    bool hasRoute;
    public volatile bool NoAAAA, UseRescue;
    public Entry Orig;

    public string Signature()
    {
        StringBuilder sb = new StringBuilder();
        sb.Append(Main.ToLine()).Append('#');
        if (Fallback != null) sb.Append(Fallback.ToLine());
        sb.Append('#').Append(NoAAAA ? 1 : 0);
        foreach (Rule r in Rules)
            sb.Append('#').Append(r.Block ? "!" : "").Append(r.Domain).Append(r.UseOrig ? "~orig" : (r.Target != null ? r.Target.Name : ""));
        return sb.ToString();
    }

    public void SetRules(List<Rule> list)
    {
        bool hr = false;
        foreach (Rule r in list) if (!r.Block) hr = true;
        hasRoute = hr; Rules = list;
    }

    public Entry Pick(string name, out bool block)
    {
        block = false;
        Rule best = null;
        List<Rule> rules = Rules;
        foreach (Rule r in rules)
            if (name == r.Domain || name.EndsWith("." + r.Domain))
                if (best == null || r.Domain.Length > best.Domain.Length) best = r;
        if (best != null)
        {
            if (best.Block) { block = true; return null; }
            if (best.UseOrig && Orig != null) return Orig;
            return best.Target != null ? best.Target : Main;
        }
        if (hasRoute && Fallback != null) return Fallback;
        return Main;
    }
}

class Engine
{
    volatile bool run;
    Router router; Action<string> qlog;
    List<UdpClient> udps = new List<UdpClient>();
    List<TcpListener> tcps = new List<TcpListener>();
    Dictionary<string, CacheItem> cache = new Dictionary<string, CacheItem>();

    public bool Running { get { return run; } }

    public void ClearCache() { lock (cache) { cache.Clear(); } }

    public void Start(Router r, Action<string> ql)
    {
        router = r; qlog = ql;
        lock (cache) { cache.Clear(); }
        run = true;
        IPAddress[] addrs = new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
        foreach (IPAddress a in addrs)
        {
            try
            {
                UdpClient u = new UdpClient(new IPEndPoint(a, 53));
                udps.Add(u);
                TcpListener t = new TcpListener(a, 53);
                t.Start();
                tcps.Add(t);
                Thread tu = new Thread(UdpLoop); tu.IsBackground = true; tu.Start(u);
                Thread tt = new Thread(TcpLoop); tt.IsBackground = true; tt.Start(t);
            }
            catch (Exception ex)
            {
                if (a.AddressFamily == AddressFamily.InterNetwork)
                {
                    Stop();
                    throw new Exception("Port 53 is busy on 127.0.0.1 (" + ex.Message + ")");
                }
            }
        }
    }

    public void Stop()
    {
        run = false;
        foreach (UdpClient u in udps) { try { u.Close(); } catch { } }
        foreach (TcpListener t in tcps) { try { t.Stop(); } catch { } }
        udps.Clear(); tcps.Clear();
    }

    void UdpLoop(object o)
    {
        UdpClient u = (UdpClient)o;
        IPAddress any = u.Client.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
        while (run)
        {
            try
            {
                IPEndPoint ep = new IPEndPoint(any, 0);
                byte[] q = u.Receive(ref ep);
                if (q.Length < 12) continue;
                ThreadPool.QueueUserWorkItem(delegate { HandleUdp(u, q, ep); });
            }
            catch { if (!run) break; Thread.Sleep(5); }
        }
    }

    void HandleUdp(UdpClient u, byte[] q, IPEndPoint ep)
    {
        try
        {
            byte[] r = Resolve(q);
            if (r == null) r = DnsUtil.Make(q, 2, null);
            r[0] = q[0]; r[1] = q[1];
            lock (u) { u.Send(r, r.Length, ep); }
        }
        catch { }
    }

    void TcpLoop(object o)
    {
        TcpListener t = (TcpListener)o;
        while (run)
        {
            try
            {
                TcpClient c = t.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(delegate { HandleTcp(c); });
            }
            catch { if (!run) break; Thread.Sleep(5); }
        }
    }

    void HandleTcp(TcpClient c)
    {
        try
        {
            c.ReceiveTimeout = 5000;
            NetworkStream ns = c.GetStream();
            while (run)
            {
                byte[] lb = DnsUtil.ReadExact(ns, 2);
                if (lb == null) break;
                byte[] q = DnsUtil.ReadExact(ns, (lb[0] << 8) | lb[1]);
                if (q == null || q.Length < 12) break;
                byte[] r = Resolve(q);
                if (r == null) r = DnsUtil.Make(q, 2, null);
                r[0] = q[0]; r[1] = q[1];
                byte[] msg = new byte[r.Length + 2];
                msg[0] = (byte)(r.Length >> 8); msg[1] = (byte)(r.Length & 0xFF);
                Buffer.BlockCopy(r, 0, msg, 2, r.Length);
                ns.Write(msg, 0, msg.Length);
            }
        }
        catch { }
        finally { try { c.Close(); } catch { } }
    }

    HashSet<string> refreshing = new HashSet<string>();
    Dictionary<string, DateTime> failUntil = new Dictionary<string, DateTime>();

    void Store(string key, byte[] r)
    {
        int rc = r[3] & 0x0F;
        if (rc != 0 && rc != 3) return;
        int ttl = rc == 3 ? 30 : DnsUtil.MinTtl(r);
        if (ttl < 0) ttl = 30;
        if (rc == 0 && ttl < 300) ttl = 300;
        if (ttl > 3600) ttl = 3600;
        lock (cache)
        {
            if (cache.Count > 4000) cache.Clear();
            cache[key] = new CacheItem((byte[])r.Clone(), ttl);
        }
    }

    void Refresh(Entry e, byte[] q, string key)
    {
        lock (cache) { if (!refreshing.Add(key)) return; }
        try
        {
            byte[] r = Upstream.Forward(e, q);
            if (r != null) Store(key, r);
        }
        finally { lock (cache) { refreshing.Remove(key); } }
    }

    byte[] Resolve(byte[] q)
    {
        Router rt = router;
        int qt, qe;
        string name = DnsUtil.QName(q, out qt, out qe);
        Stopwatch sw = Stopwatch.StartNew();
        byte[] r = null; string via = ""; string err = null;
        string bip;
        if (rt.Bootstrap.TryGetValue(name, out bip))
        {
            r = DnsUtil.Make(q, 0, qt == 1 ? bip : null); via = "bootstrap";
        }
        else
        {
            bool block;
            Entry e = rt.Pick(name, out block);
            if (block) { r = DnsUtil.Make(q, 3, null); via = "BLOCKED"; }
            else if (rt.NoAAAA && (qt == 28 || qt == 65 || qt == 64) && e != rt.Orig && e != rt.Fallback)
            {
                r = DnsUtil.Make(q, 0, null); via = "IPv6/HTTPS record skipped";
            }
            else
            {
                via = e.Name;
                string key = Convert.ToBase64String(q, 2, q.Length - 2);
                bool stale = false;
                lock (cache)
                {
                    CacheItem ci;
                    if (cache.TryGetValue(key, out ci))
                    {
                        DateTime now = DateTime.UtcNow;
                        if (ci.Expire > now) { r = (byte[])ci.Data.Clone(); via += " (cache)"; if ((ci.Expire - now).TotalSeconds < 30) stale = true; }
                        else if (ci.Expire.AddHours(6) > now) { r = (byte[])ci.Data.Clone(); via += " (cache, refreshing)"; stale = true; }
                        else cache.Remove(key);
                    }
                }
                if (stale)
                {
                    byte[] qc = (byte[])q.Clone(); Entry ec = e; string kc = key;
                    ThreadPool.QueueUserWorkItem(delegate { Refresh(ec, qc, kc); });
                }
                if (r == null)
                {
                    bool rescued = false, skipMain = false;
                    lock (cache)
                    {
                        DateTime fu;
                        if (failUntil.TryGetValue(key, out fu))
                        {
                            if (fu > DateTime.UtcNow) skipMain = true; else failUntil.Remove(key);
                        }
                    }
                    if (skipMain) err = "main DNS failed a moment ago, skipped";
                    else
                    {
                        r = Upstream.Forward(e, q);
                        if (r == null)
                        {
                            err = Upstream.LastError;
                            lock (cache)
                            {
                                if (failUntil.Count > 2000) failUntil.Clear();
                                failUntil[key] = DateTime.UtcNow.AddSeconds(20);
                            }
                        }
                    }
                    if (r == null && rt.Fallback != null && rt.Fallback != e)
                    {
                        r = Upstream.Forward(rt.Fallback, q);
                        if (r != null) { via = rt.Fallback.Name + " (failover)"; rescued = true; }
                    }
                    if (r == null && rt.UseRescue && rt.Orig != null && rt.Orig != e && rt.Orig != rt.Fallback)
                    {
                        r = Upstream.Forward(rt.Orig, q);
                        if (r != null) { via = "original DNS (rescue)"; rescued = true; }
                    }
                    if (r != null && !rescued) Store(key, r);
                }
            }
        }
        sw.Stop();
        if (qlog != null)
            qlog(name + "  " + DnsUtil.TypeName(qt) + "  ->  " + via + "  :  " + DnsUtil.Summ(r) + "  (" + sw.ElapsedMilliseconds + " ms)" + (err != null ? "   [main DNS failed: " + err + "]" : ""));
        return r;
    }
}

// ---------------------------------------------------------------- settings store (per-user registry, no files)
static class Store
{
    const string KeyPath = @"Software\OVERX Dns";

    public static string Get(string name, string def)
    {
        try
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(KeyPath))
            {
                if (k != null) { object v = k.GetValue(name); if (v != null) return v.ToString(); }
            }
        }
        catch { }
        return def;
    }

    public static void Set(string name, string val)
    {
        try { using (RegistryKey k = Registry.CurrentUser.CreateSubKey(KeyPath)) { k.SetValue(name, val, RegistryValueKind.String); } }
        catch { }
    }

    public static void Wipe() { try { Registry.CurrentUser.DeleteSubKeyTree(KeyPath, false); } catch { } }
}

// ---------------------------------------------------------------- UI
class MainForm : Form
{
    ComboBox cbDns, cbFb, cbLang, cbTheme;
    CheckBox chkLeak, chkQ, chkStart, chkNoV6, chkRescue, chkQuic;
    Label lbInfo, lbStatus, lMain, lFb, lLang, lTheme;
    TextBox tbLog;
    NotifyIcon ni;
    ToolStripItem mShow, mApply, mClear, mReset, mExit;
    ToolTip tip = new ToolTip();
    System.Windows.Forms.Timer timer;
    List<Entry> entries = new List<Entry>();
    List<string> appliedAdapters = new List<string>();
    Dictionary<string, string> cfg = new Dictionary<string, string>();
    Queue<string> pend = new Queue<string>();
    Engine engine = new Engine();
    Router router;
    bool applied, exiting, loading = true;
    volatile bool showQ;
    static bool fwDone;

    bool wiped, dark = true, mirrored, logOpen, uiSync;
    static bool fa;
    int page;
    Panel bodyPanel, headerPanel, homePanel, settingsPanel, navPanel;
    Button btnApply, btnClear, btnFlush, btnGear, btnLog, btnRules, btnHome, btnSettings, btnLogs;
    Icon appIcon;
    static Color LOGBG = Color.FromArgb(12, 14, 20), LOGFG = Color.FromArgb(130, 235, 190),
                 HOVER = Color.FromArgb(54, 62, 88), PRESS = Color.FromArgb(72, 82, 114);

    static void SetColors(bool d)
    {
        if (d)
        {
            BG = Color.FromArgb(18, 20, 28); FIELD = Color.FromArgb(30, 35, 48); BTN = Color.FromArgb(38, 44, 62);
            TEXT = Color.FromArgb(226, 230, 240); MUTED = Color.FromArgb(140, 150, 175);
            LOGBG = Color.FromArgb(12, 14, 20); LOGFG = Color.FromArgb(130, 235, 190);
            HOVER = Color.FromArgb(54, 62, 88); PRESS = Color.FromArgb(72, 82, 114);
        }
        else
        {
            BG = Color.FromArgb(243, 244, 250); FIELD = Color.FromArgb(255, 255, 255); BTN = Color.FromArgb(225, 228, 240);
            TEXT = Color.FromArgb(30, 34, 48); MUTED = Color.FromArgb(96, 106, 128);
            LOGBG = Color.FromArgb(255, 255, 255); LOGFG = Color.FromArgb(18, 108, 70);
            HOVER = Color.FromArgb(208, 213, 233); PRESS = Color.FromArgb(188, 195, 222);
        }
    }

    // ---------------------------------------------------------------- language (English / Persian)
    static Dictionary<string, string[]> TR = new Dictionary<string, string[]>();
    static void Tr(string k, string en, string faText) { TR[k] = new string[] { en, faText }; }
    static string T(string k) { InitTr(); string[] v; if (TR.TryGetValue(k, out v)) return fa ? v[1] : v[0]; return k; }
    static string TF(string k, params object[] a) { return string.Format(T(k), a); }

    static void InitTr()
    {
        if (TR.Count > 0) return;
        Tr("sub", "system-wide DNS   |   UDP  -  DoH  -  DoT", "DNS کل سیستم   |   UDP  -  DoH  -  DoT");
        Tr("home", "Home", "خانه");
        Tr("settings", "Settings", "تنظیمات");
        Tr("mainDns", "Main DNS", "DNS اصلی");
        Tr("fallback", "Fallback for all other domains", "جایگزین برای بقیه دامنه‌ها");
        Tr("sameMain", "(same as main)", "(همان DNS اصلی)");
        Tr("origDns", "(original DNS)", "(DNS پیش‌فرض سیستم)");
        Tr("apply", "Apply (system-wide)", "اعمال روی کل سیستم");
        Tr("clear", "Clear (Auto)", "پاک‌سازی (خودکار)");
        Tr("flush", "Flush DNS", "پاک کردن کش DNS");
        Tr("showLogs", "Show logs  \u25BE", "نمایش لاگ‌ها  \u25BE");
        Tr("hideLogs", "Hide logs  \u25B4", "پنهان کردن لاگ‌ها  \u25B4");
        Tr("active", "ACTIVE", "فعال");
        Tr("off", "OFF", "خاموش");
        Tr("language", "Language", "زبان برنامه");
        Tr("theme", "Theme", "تم برنامه");
        Tr("dark", "Dark", "تیره");
        Tr("light", "Light", "روشن");
        Tr("rules", "Rules...", "قوانین...");
        Tr("chkLeak", "Block DNS leaks (browser secure-DNS, multi-homed)", "جلوگیری از نشت DNS (DNS امن مرورگر و چند کارت شبکه)");
        Tr("chkQ", "Log DNS queries", "ثبت درخواست‌های DNS در لاگ");
        Tr("chkStart", "Start with Windows (auto-apply)", "اجرا همراه ویندوز (اعمال خودکار)");
        Tr("chkNoV6", "Skip IPv6/HTTPS lookups (faster)", "رد کردن درخواست‌های IPv6/HTTPS (سریع‌تر)");
        Tr("chkRescue", "Rescue: use the original DNS if the main DNS does not answer", "پشتیبان: اگر DNS اصلی جواب نداد، از DNS پیش‌فرض سیستم استفاده شود");
        Tr("chkQuic", "Block QUIC (UDP 443) so YouTube/Google work in any browser", "مسدود کردن QUIC (پورت UDP 443) تا یوتیوب و گوگل در هر مرورگری کار کنند");
        Tr("trayShow", "Show", "نمایش");
        Tr("trayApply", "Apply", "اعمال");
        Tr("trayClear", "Clear (Auto)", "پاک‌سازی (خودکار)");
        Tr("trayReset", "Reset saved data", "حذف داده‌های ذخیره‌شده");
        Tr("trayExit", "Exit", "خروج");
        Tr("logs", "Logs", "لاگ‌ها");
        Tr("dnsTitle", "DNS servers", "سرورهای DNS");
        Tr("colName", "Name", "نام");
        Tr("colType", "Type", "نوع");
        Tr("colAddr", "Address", "آدرس");
        Tr("colPing", "Ping", "پینگ");
        Tr("select", "Select", "انتخاب");
        Tr("add", "Add", "افزودن");
        Tr("edit", "Edit", "ویرایش");
        Tr("del", "Delete", "حذف");
        Tr("test", "Test speed", "تست سرعت");
        Tr("close", "Close", "بستن");
        Tr("mainTag", "(main)", "(اصلی)");
        Tr("failTxt", "fail", "ناموفق");
        Tr("delConfirm", "Delete \"{0}\"?", "«{0}» حذف شود؟");
        Tr("addTitle", "Add DNS", "افزودن DNS");
        Tr("editTitle", "Edit DNS", "ویرایش DNS");
        Tr("eName", "Name", "نام");
        Tr("eType", "Type", "نوع");
        Tr("ePrimary", "Primary IP", "آی‌پی اصلی");
        Tr("eSecondary", "Secondary IP (optional)", "آی‌پی دوم (اختیاری)");
        Tr("eUrl", "DoH URL / DoT hostname", "آدرس DoH / نام میزبان DoT");
        Tr("save", "Save", "ذخیره");
        Tr("cancel", "Cancel", "انصراف");
        Tr("errName", "Enter a name (no | character).", "یک نام وارد کنید (بدون علامت |).");
        Tr("errP", "Primary IP is not valid.", "آی‌پی اصلی معتبر نیست.");
        Tr("errS", "Secondary IP is not valid.", "آی‌پی دوم معتبر نیست.");
        Tr("errUdp", "UDP needs a primary IP.", "برای UDP آی‌پی اصلی لازم است.");
        Tr("errDoh", "DoH URL must start with https://", "آدرس DoH باید با https:// شروع شود.");
        Tr("errDot", "DoT needs an IP or hostname.", "برای DoT آی‌پی یا نام میزبان لازم است.");
        Tr("rulesTitle", "Rules", "قوانین");
        Tr("addRuleTitle", "Add rule", "افزودن قانون");
        Tr("addRuleText", "Domain: {0}\n\nYes = send it (and its subdomains) to your ORIGINAL DNS\nNo = send it to the MAIN DNS (explicit rule)\nCancel = do nothing",
            "دامنه: {0}\n\nبله = این دامنه (و زیردامنه‌هایش) از DNS پیش‌فرض سیستم جواب بگیرد\nخیر = از DNS اصلی جواب بگیرد (قانون صریح)\nانصراف = هیچ کاری انجام نشود");
        Tr("ready", "Ready. Pick a main DNS (or open the gear to manage the list), then press Apply.", "آماده است. یک DNS اصلی انتخاب کنید (یا با چرخ‌دنده لیست را مدیریت کنید) و دکمه‌ی اعمال را بزنید.");
        Tr("wiped", "Saved data removed. Restart the app to load the defaults.", "داده‌های ذخیره‌شده حذف شد. برای بارگذاری مقادیر پیش‌فرض برنامه را دوباره باز کنید.");
        Tr("ruleAdded", "Rule added: {0} -> {1}", "قانون اضافه شد: {0} -> {1}");
        Tr("flushed", "DNS cache flushed.", "کش DNS پاک شد.");
        Tr("mainSet", "Main DNS: {0}", "DNS اصلی: {0}");
        Tr("recovered", "Recovered DNS settings left behind by a previous crash.", "تنظیمات DNS که از بسته شدن ناگهانی قبلی مانده بود، بازگردانی شد.");
        Tr("rulesSaved", "Rules saved (they load when you press Apply).", "قوانین ذخیره شد (با زدن دکمه‌ی اعمال بارگذاری می‌شوند).");
        Tr("rulesReloaded", "Rules reloaded: {0} rule(s).", "قوانین دوباره بارگذاری شد: {0} قانون.");
        Tr("addDnsFirst", "Add a DNS first.", "ابتدا یک DNS اضافه کنید.");
        Tr("noAdapter", "No active network adapter found.", "هیچ کارت شبکه‌ی فعالی پیدا نشد.");
        Tr("origDetected", "Original DNS detected: {0}", "DNS پیش‌فرض سیستم: {0}");
        Tr("activeMsg", "ACTIVE: main = {0}{1}{2}, adapters: {3}", "فعال شد: DNS اصلی = {0}{1}{2}، کارت‌های شبکه: {3}");
        Tr("fbPart", ", fallback = {0}", "، جایگزین = {0}");
        Tr("rulesPart", ", {0} rule(s)", "، {0} قانون");
        Tr("selfOk", "Self-test OK: {0} answered in {1} ms", "تست خودکار موفق: {0} در {1} میلی‌ثانیه جواب داد");
        Tr("selfFail", "Self-test FAILED for {0}: {1}", "تست خودکار ناموفق برای {0}: {1}");
        Tr("error", "Error: {0}", "خطا: {0}");
        Tr("port53", "Port 53 is used by: {0} (stop it, then Apply again)", "پورت 53 توسط {0} اشغال شده است (آن را ببندید و دوباره اعمال کنید)");
        Tr("dnsReset", "DNS reset to automatic, firewall rule removed.", "DNS به حالت خودکار برگشت و قانون فایروال حذف شد.");
        Tr("stopped", "Stopped. DNS reset to automatic, firewall rule removed.", "متوقف شد. DNS به حالت خودکار برگشت و قانون فایروال حذف شد.");
        Tr("fwAdded", "Firewall: allow rules added for OVERX Dns.exe (in + out).", "فایروال: قوانین اجازه برای OVERX Dns.exe (ورودی و خروجی) اضافه شد.");
        Tr("already", "OVERX Dns is already running (check the tray icon).", "OVERX Dns از قبل در حال اجراست (آیکون کنار ساعت را ببینید).");
    }

    static DialogResult Msg(IWin32Window owner, string text, string caption, MessageBoxButtons b)
    {
        MessageBoxOptions o = fa ? (MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign) : (MessageBoxOptions)0;
        return MessageBox.Show(owner, text, caption, b, MessageBoxIcon.None, MessageBoxDefaultButton.Button1, o);
    }

    // mirror the positions of a container's children (used for the Persian right-to-left layout)
    static void Mirror(Control p)
    {
        foreach (Control c in p.Controls)
        {
            c.Left = p.ClientSize.Width - c.Left - c.Width;
            AnchorStyles a = c.Anchor;
            bool l = (a & AnchorStyles.Left) != 0, r = (a & AnchorStyles.Right) != 0;
            a &= ~(AnchorStyles.Left | AnchorStyles.Right);
            if (r) a |= AnchorStyles.Left;
            if (l) a |= AnchorStyles.Right;
            c.Anchor = a;
        }
    }

    static void Rtl(Form f)
    {
        if (!fa) return;
        f.RightToLeft = RightToLeft.Yes;
        Mirror(f);
    }

    static string DefaultRules =
        "# One rule per line. Subdomains are included automatically.\r\n" +
        "#   domain              -> resolved by the MAIN dns\r\n" +
        "#   domain|DnsName      -> resolved by a specific dns from the list\r\n" +
        "#   domain|original     -> resolved by your ORIGINAL dns (router/ISP)\r\n" +
        "#   !domain             -> blocked (NXDOMAIN)\r\n" +
        "# Domains NOT listed go to the main dns (or the Fallback, if you chose one).\r\n" +
        "# Tip: double-click a line in the query log to add its domain here.\r\n\r\n" +
        "steamserver.net|original\r\n";

    static string DefaultRulesFa =
        "# هر خط یک قانون است. زیردامنه‌ها خودکار شامل می‌شوند.\r\n" +
        "#   domain              -> با DNS اصلی جواب می‌گیرد\r\n" +
        "#   domain|DnsName      -> با یکی از DNSهای لیست جواب می‌گیرد\r\n" +
        "#   domain|original     -> با DNS پیش‌فرض سیستم (روتر/ISP) جواب می‌گیرد\r\n" +
        "#   !domain             -> مسدود می‌شود (NXDOMAIN)\r\n" +
        "# دامنه‌هایی که در لیست نیستند با DNS اصلی (یا جایگزین، اگر انتخاب کرده باشید) جواب می‌گیرند.\r\n" +
        "# نکته: روی هر خط لاگ دو بار کلیک کنید تا دامنه‌اش اینجا اضافه شود.\r\n\r\n" +
        "steamserver.net|original\r\n";

    static string RulesText() { return Store.Get("rules", fa ? DefaultRulesFa : DefaultRules); }

    // one-time import of files created by older versions (so nothing is lost)
    static void Migrate()
    {
        try
        {
            string d = AppDomain.CurrentDomain.BaseDirectory;
            string f1 = Path.Combine(d, "dns-list.txt"), f2 = Path.Combine(d, "rules.txt"), f3 = Path.Combine(d, "settings.ini");
            if (Store.Get("dnslist", null) == null && File.Exists(f1)) Store.Set("dnslist", File.ReadAllText(f1, Encoding.UTF8));
            if (Store.Get("rules", null) == null && File.Exists(f2)) Store.Set("rules", File.ReadAllText(f2, Encoding.UTF8));
            if (Store.Get("cfg_main", null) == null && File.Exists(f3))
                foreach (string line in File.ReadAllLines(f3, Encoding.UTF8))
                {
                    int i = line.IndexOf('=');
                    if (i > 0) Store.Set("cfg_" + line.Substring(0, i), line.Substring(i + 1));
                }
        }
        catch { }
    }

    static Color BG = Color.FromArgb(18, 20, 28), FIELD = Color.FromArgb(30, 35, 48), BTN = Color.FromArgb(38, 44, 62);
    static Color TEXT = Color.FromArgb(226, 230, 240), MUTED = Color.FromArgb(140, 150, 175), ACCENT = Color.FromArgb(108, 92, 231);

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        TitleBar(this);
    }

    void TitleBar(Form f)
    {
        try { int v = dark ? 1 : 0; DwmSetWindowAttribute(f.Handle, 20, ref v, 4); } catch { }
    }

    public MainForm(bool auto)
    {
        InitTr();
        fa = Store.Get("cfg_lang", "en") == "fa";
        dark = Store.Get("cfg_dark", "1") != "0";
        logOpen = Store.Get("cfg_log", "0") == "1";
        SetColors(dark);
        Text = "OVERX Dns";
        ClientSize = new Size(600, 556);
        BackColor = BG; ForeColor = TEXT;
        try { appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        if (appIcon != null) Icon = appIcon;
        Font = new Font("Segoe UI", 9f);
        StartPosition = FormStartPosition.CenterScreen;
        tip.ShowAlways = true;

        // ----- home page
        lMain = new Label(); lMain.SetBounds(12, 12, 290, 18);
        cbDns = new ComboBox(); cbDns.DropDownStyle = ComboBoxStyle.DropDownList; cbDns.SetBounds(12, 32, 256, 24);
        btnGear = MakeBtn("\u2699", 274, 31, 34); btnGear.Height = 26; btnGear.Font = new Font("Segoe UI Symbol", 11f);
        lFb = new Label(); lFb.SetBounds(316, 12, 272, 18);
        cbFb = new ComboBox(); cbFb.DropDownStyle = ComboBoxStyle.DropDownList; cbFb.SetBounds(316, 32, 272, 24);
        cbDns.SelectedIndexChanged += delegate { ShowInfo(); };
        lbInfo = new Label(); lbInfo.SetBounds(12, 64, 576, 34);
        lbInfo.RightToLeft = RightToLeft.No;
        btnApply = MakeBtn("", 12, 106, 250); btnApply.Font = new Font(Font, FontStyle.Bold);
        btnClear = MakeBtn("", 268, 106, 160);
        btnFlush = MakeBtn("", 434, 106, 154);
        btnApply.Height = btnClear.Height = btnFlush.Height = 36;
        btnLog = MakeBtn("", 12, 152, 576); btnLog.Height = 30;
        tbLog = new TextBox(); tbLog.Multiline = true; tbLog.ReadOnly = true; tbLog.ScrollBars = ScrollBars.Vertical;
        tbLog.SetBounds(12, 190, 576, 238); tbLog.Font = new Font("Consolas", 9f); tbLog.BorderStyle = BorderStyle.FixedSingle;
        tbLog.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        cbFb.Anchor = lbInfo.Anchor = btnLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        homePanel = new Panel(); homePanel.Dock = DockStyle.Fill;
        homePanel.Controls.AddRange(new Control[] { lMain, cbDns, btnGear, lFb, cbFb, lbInfo, btnApply, btnClear, btnFlush, btnLog, tbLog });

        // ----- settings page
        lLang = new Label(); lLang.SetBounds(12, 14, 280, 18);
        cbLang = new ComboBox(); cbLang.DropDownStyle = ComboBoxStyle.DropDownList; cbLang.SetBounds(12, 34, 280, 24);
        lTheme = new Label(); lTheme.SetBounds(316, 14, 272, 18);
        cbTheme = new ComboBox(); cbTheme.DropDownStyle = ComboBoxStyle.DropDownList; cbTheme.SetBounds(316, 34, 272, 24);
        btnRules = MakeBtn("", 12, 76, 260); btnRules.Height = 32;
        chkLeak = new CheckBox(); chkLeak.Checked = true; chkLeak.SetBounds(12, 124, 576, 24);
        chkQ = new CheckBox(); chkQ.Checked = true; chkQ.SetBounds(12, 152, 576, 24);
        chkStart = new CheckBox(); chkStart.SetBounds(12, 180, 576, 24);
        chkNoV6 = new CheckBox(); chkNoV6.Checked = true; chkNoV6.SetBounds(12, 208, 576, 24);
        chkRescue = new CheckBox(); chkRescue.Checked = true; chkRescue.SetBounds(12, 236, 576, 24);
        chkQuic = new CheckBox(); chkQuic.Checked = true; chkQuic.SetBounds(12, 264, 576, 24);
        chkLeak.Anchor = chkQ.Anchor = chkStart.Anchor = chkNoV6.Anchor = chkRescue.Anchor = chkQuic.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        settingsPanel = new Panel(); settingsPanel.Dock = DockStyle.Fill;
        settingsPanel.Controls.AddRange(new Control[] { lLang, cbLang, lTheme, cbTheme, btnRules, chkLeak, chkQ, chkStart, chkNoV6, chkRescue, chkQuic });

        bodyPanel = new Panel(); bodyPanel.SetBounds(0, 64, 600, 440);
        bodyPanel.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        bodyPanel.Controls.Add(homePanel); bodyPanel.Controls.Add(settingsPanel);

        // ----- bottom navigation (Home / Settings)
        Font icoFont = new Font("Segoe MDL2 Assets", 16f);
        bool mdl = icoFont.Name == "Segoe MDL2 Assets";
        if (!mdl) icoFont = new Font("Segoe UI Symbol", 16f);
        navPanel = new Panel(); navPanel.SetBounds(0, 504, 600, 52);
        navPanel.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        btnHome = new Button(); btnHome.Text = mdl ? "\uE80F" : "\u2302"; btnHome.Font = icoFont; btnHome.SetBounds(152, 6, 96, 40);
        btnLogs = new Button(); btnLogs.Text = mdl ? "\uE8A5" : "\u2630"; btnLogs.Font = icoFont; btnLogs.SetBounds(252, 6, 96, 40);
        btnSettings = new Button(); btnSettings.Text = mdl ? "\uE713" : "\u2699"; btnSettings.Font = icoFont; btnSettings.SetBounds(352, 6, 96, 40);
        btnHome.Anchor = btnLogs.Anchor = btnSettings.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        navPanel.Controls.Add(btnHome); navPanel.Controls.Add(btnLogs); navPanel.Controls.Add(btnSettings);

        // ----- header
        headerPanel = new Panel(); headerPanel.SetBounds(0, 0, 600, 64);
        headerPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        headerPanel.Paint += delegate (object hs, PaintEventArgs pe)
        {
            if (headerPanel.Width <= 0 || headerPanel.Height <= 0) return;
            Graphics g = pe.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int W = headerPanel.Width;
            using (LinearGradientBrush br = new LinearGradientBrush(headerPanel.ClientRectangle, Color.FromArgb(34, 20, 84), Color.FromArgb(78, 48, 190), 0f))
                g.FillRectangle(br, headerPanel.ClientRectangle);
            if (appIcon != null) g.DrawIcon(appIcon, new Rectangle(fa ? W - 54 : 14, 12, 40, 40));
            using (StringFormat sfm = new StringFormat())
            {
                if (fa) sfm.FormatFlags = StringFormatFlags.DirectionRightToLeft;
                RectangleF r1 = fa ? new RectangleF(0, 6, W - 62, 34) : new RectangleF(62, 6, W - 62, 34);
                RectangleF r2 = fa ? new RectangleF(0, 38, W - 64, 20) : new RectangleF(64, 38, W - 64, 20);
                using (Font tf = new Font("Segoe UI Semibold", 17f)) g.DrawString("OVERX Dns", tf, Brushes.White, r1, sfm);
                using (Font sf2 = new Font("Segoe UI", 8.5f))
                using (SolidBrush sb = new SolidBrush(Color.FromArgb(195, 200, 235)))
                    g.DrawString(T("sub"), sf2, sb, r2, sfm);
            }
        };
        headerPanel.Resize += delegate { headerPanel.Invalidate(); };
        lbStatus = new Label(); lbStatus.AutoSize = false; lbStatus.SetBounds(426, 20, 162, 24);
        lbStatus.TextAlign = ContentAlignment.MiddleRight; lbStatus.BackColor = Color.Transparent;
        lbStatus.Font = new Font("Segoe UI Semibold", 10f); lbStatus.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        headerPanel.Controls.Add(lbStatus);

        Controls.Add(bodyPanel); Controls.Add(navPanel); Controls.Add(headerPanel);

        // ----- tray
        ni = new NotifyIcon(); ni.Icon = appIcon != null ? appIcon : SystemIcons.Application; ni.Text = "OVERX Dns"; ni.Visible = true;
        ContextMenuStrip cm = new ContextMenuStrip();
        mShow = cm.Items.Add("", null, delegate { ShowMe(); });
        mApply = cm.Items.Add("", null, delegate { DoApply(); });
        mClear = cm.Items.Add("", null, delegate { DoClear(); });
        mReset = cm.Items.Add("", null, delegate { wiped = true; Store.Wipe(); Log(T("wiped")); });
        mExit = cm.Items.Add("", null, delegate { exiting = true; Close(); });
        ni.ContextMenuStrip = cm;
        ni.DoubleClick += delegate { ShowMe(); };

        ApplyTheme();
        ApplyLanguage();

        timer = new System.Windows.Forms.Timer(); timer.Interval = 300;
        timer.Tick += delegate { Drain(); };
        timer.Start();

        tbLog.MouseDoubleClick += delegate (object ms, MouseEventArgs me)
        {
            try
            {
                int ch = tbLog.GetCharIndexFromPosition(me.Location);
                int ln = tbLog.GetLineFromCharIndex(ch);
                if (ln < 0 || ln >= tbLog.Lines.Length) return;
                string[] tk = tbLog.Lines[ln].Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (tk.Length < 5 || tk[3] != "->" || !tk[1].Contains(".")) return;
                string dom = tk[1];
                DialogResult dr = Msg(this, TF("addRuleText", dom), T("addRuleTitle"), MessageBoxButtons.YesNoCancel);
                if (dr == DialogResult.Cancel) return;
                Entry mm = SelMain();
                string target = dr == DialogResult.Yes ? "original" : (mm != null ? mm.Name : "");
                if (target == "") return;
                Store.Set("rules", AddRuleLine(RulesText(), dom, target));
                ReloadRules();
                Log(TF("ruleAdded", dom, target));
            }
            catch { }
        };
        btnApply.Click += delegate { DoApply(); };
        btnClear.Click += delegate { DoClear(); };
        btnFlush.Click += delegate { Run("ipconfig", "/flushdns"); Log(T("flushed")); };
        btnLog.Click += delegate { SetLogOpen(!logOpen); };
        btnGear.Click += delegate { ManageDns(); };
        btnRules.Click += delegate { OpenRules(); };
        btnHome.Click += delegate { ShowPage(0); };
        btnLogs.Click += delegate { ShowPage(1); };
        btnSettings.Click += delegate { ShowPage(2); };
        cbLang.SelectedIndexChanged += delegate
        {
            if (uiSync) return;
            fa = cbLang.SelectedIndex == 1;
            ApplyLanguage(); SaveCfg();
        };
        cbTheme.SelectedIndexChanged += delegate
        {
            if (uiSync) return;
            dark = cbTheme.SelectedIndex == 0;
            ApplyTheme(); SaveCfg();
        };
        chkQuic.CheckedChanged += delegate { if (applied) SetQuicBlock(chkQuic.Checked); SaveCfg(); };
        chkQ.CheckedChanged += delegate { showQ = chkQ.Checked; SaveCfg(); };
        chkLeak.CheckedChanged += delegate { SaveCfg(); };
        chkRescue.CheckedChanged += delegate { if (router != null) router.UseRescue = chkRescue.Checked; SaveCfg(); };
        chkNoV6.CheckedChanged += delegate { if (router != null) router.NoAAAA = chkNoV6.Checked; SaveCfg(); };
        chkStart.CheckedChanged += delegate
        {
            if (loading) return;
            string exe = Application.ExecutablePath;
            if (chkStart.Checked)
                Run("schtasks", "/create /tn OVERX Dns /sc onlogon /rl highest /f /tr \"\\\"" + exe + "\\\" --auto\"");
            else
                Run("schtasks", "/delete /tn OVERX Dns /f");
            SaveCfg();
        };

        Resize += delegate { if (WindowState == FormWindowState.Minimized) Hide(); };
        FormClosing += delegate (object s, FormClosingEventArgs ev)
        {
            if (!exiting && ev.CloseReason == CloseReason.UserClosing && applied) { ev.Cancel = true; Hide(); return; }
            if (applied) ResetAll(); else RemoveFirewall();
            SaveCfg();
            ni.Visible = false; ni.Dispose();
        };
        Shown += delegate
        {
            if (auto) { DoApply(); WindowState = FormWindowState.Minimized; }
        };

        Migrate();
        LoadCfg();
        LoadList();
        RecoverFromCrash();
        ApplyCfgToUi();
        loading = false;
        showQ = chkQ.Checked;
        btnLog.Text = logOpen ? T("hideLogs") : T("showLogs");
        page = 0;
        FitWindow();
        UpdateNav();
        UpdateStatus();
        Log(T("ready"));
    }

    // ---------- language / pages ----------
    void ApplyLanguage()
    {
        bool oldLoading = loading; loading = true; uiSync = true;
        RightToLeft = fa ? RightToLeft.Yes : RightToLeft.No;
        tbLog.RightToLeft = RightToLeft.No;
        lMain.Text = T("mainDns"); lFb.Text = T("fallback");
        btnApply.Text = T("apply"); btnClear.Text = T("clear"); btnFlush.Text = T("flush");
        btnLog.Text = logOpen ? T("hideLogs") : T("showLogs");
        lLang.Text = T("language"); lTheme.Text = T("theme"); btnRules.Text = T("rules");
        chkLeak.Text = T("chkLeak"); chkQ.Text = T("chkQ"); chkStart.Text = T("chkStart");
        chkNoV6.Text = T("chkNoV6"); chkRescue.Text = T("chkRescue"); chkQuic.Text = T("chkQuic");
        tip.SetToolTip(btnHome, T("home")); tip.SetToolTip(btnLogs, T("logs")); tip.SetToolTip(btnSettings, T("settings")); tip.SetToolTip(btnGear, T("dnsTitle"));
        mShow.Text = T("trayShow"); mApply.Text = T("trayApply"); mClear.Text = T("trayClear");
        mReset.Text = T("trayReset"); mExit.Text = T("trayExit");

        Entry cur = SelMain(); string fk = FbKey();
        FillCombos(cur != null ? cur.Name : "", fk);
        cbLang.Items.Clear(); cbLang.Items.Add("English"); cbLang.Items.Add("فارسی"); cbLang.SelectedIndex = fa ? 1 : 0;
        cbTheme.Items.Clear(); cbTheme.Items.Add(T("dark")); cbTheme.Items.Add(T("light")); cbTheme.SelectedIndex = dark ? 0 : 1;

        if (fa != mirrored)
        {
            Mirror(headerPanel); Mirror(homePanel); Mirror(settingsPanel); Mirror(navPanel);
            mirrored = fa;
        }
        lbStatus.TextAlign = fa ? ContentAlignment.MiddleLeft : ContentAlignment.MiddleRight;
        headerPanel.Invalidate();
        UpdateStatus();
        loading = oldLoading; uiSync = false;
    }

    void ShowPage(int p) { page = p; FitWindow(); UpdateNav(); }

    void FitWindow()
    {
        int body = page == 2 ? 346 : (page == 1 ? 440 : (logOpen ? 440 : 206));
        homePanel.Visible = page == 0;
        settingsPanel.Visible = page == 2;
        MinimumSize = Size.Empty;
        ClientSize = new Size(ClientSize.Width, 64 + body + 52);
        MinimumSize = new Size(616, Height);
        tbLog.Visible = (logOpen && page == 0) || page == 1;
        if (page == 0 && logOpen) tbLog.SetBounds(12, 190, 576, Math.Max(60, body - 190 - 12));
        if (page == 1) tbLog.SetBounds(12, 12, 576, Math.Max(60, body - 24));
    }

    void SetLogOpen(bool open)
    {
        logOpen = open;
        btnLog.Text = open ? T("hideLogs") : T("showLogs");
        FitWindow();
        SaveCfg();
    }

    void UpdateNav()
    {
        Button[] bs = new Button[] { btnHome, btnLogs, btnSettings };
        for (int i = 0; i < 3; i++)
        {
            bool sel = i == page;
            Button b = bs[i];
            b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0; b.Cursor = Cursors.Hand;
            b.BackColor = sel ? ACCENT : BTN;
            b.ForeColor = sel ? Color.White : TEXT;
            b.FlatAppearance.MouseOverBackColor = sel ? Color.FromArgb(132, 117, 246) : HOVER;
            b.FlatAppearance.MouseDownBackColor = sel ? Color.FromArgb(88, 72, 210) : PRESS;
        }
        navPanel.BackColor = BTN;
    }

    // ---------- DNS list window ----------
    void FillGrid(DataGridView dg, int selectRow)
    {
        dg.Rows.Clear();
        Entry cur = SelMain();
        foreach (Entry e in entries)
        {
            string addr = e.Type == "UDP" ? e.Primary + (e.Secondary != "" ? ", " + e.Secondary : "") : (e.Url != "" ? e.Url : e.Primary);
            int idx = dg.Rows.Add(e.Name + (e == cur ? "   " + T("mainTag") : ""), e.Type, addr, "-");
            if (e == cur) dg.Rows[idx].DefaultCellStyle.Font = new Font(Font, FontStyle.Bold);
        }
        if (dg.Rows.Count > 0)
        {
            int r = Math.Max(0, Math.Min(selectRow, dg.Rows.Count - 1));
            dg.CurrentCell = dg.Rows[r].Cells[0];
            dg.Rows[r].Selected = true;
        }
    }

    void ManageDns()
    {
        Form f = new Form();
        f.Text = T("dnsTitle"); f.ClientSize = new Size(660, 420); f.MinimumSize = new Size(580, 320);
        f.Font = Font; f.StartPosition = FormStartPosition.CenterParent; f.BackColor = BG;
        f.ShowIcon = false; f.MaximizeBox = false; f.MinimizeBox = false;
        f.HandleCreated += delegate { TitleBar(f); };

        DataGridView dg = new DataGridView();
        dg.SetBounds(12, 12, 636, 350);
        dg.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        dg.AllowUserToAddRows = false; dg.AllowUserToDeleteRows = false; dg.AllowUserToResizeRows = false;
        dg.ReadOnly = true; dg.RowHeadersVisible = false; dg.MultiSelect = false;
        dg.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        dg.BorderStyle = BorderStyle.None; dg.BackgroundColor = FIELD; dg.GridColor = BTN;
        dg.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        dg.EnableHeadersVisualStyles = false;
        dg.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        dg.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        dg.ColumnHeadersHeight = 32;
        dg.ColumnHeadersDefaultCellStyle.BackColor = BTN; dg.ColumnHeadersDefaultCellStyle.ForeColor = TEXT;
        dg.ColumnHeadersDefaultCellStyle.SelectionBackColor = BTN; dg.ColumnHeadersDefaultCellStyle.SelectionForeColor = TEXT;
        dg.DefaultCellStyle.BackColor = FIELD; dg.DefaultCellStyle.ForeColor = TEXT;
        dg.DefaultCellStyle.SelectionBackColor = dark ? Color.FromArgb(58, 52, 112) : Color.FromArgb(214, 210, 245); dg.DefaultCellStyle.SelectionForeColor = TEXT;
        dg.RowTemplate.Height = 32;
        dg.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        dg.Columns.Add("name", T("colName")); dg.Columns.Add("type", T("colType")); dg.Columns.Add("addr", T("colAddr")); dg.Columns.Add("ping", T("colPing"));
        DataGridViewButtonColumn bc = new DataGridViewButtonColumn();
        bc.Name = "sel"; bc.HeaderText = ""; bc.Text = T("select"); bc.UseColumnTextForButtonValue = true; bc.FlatStyle = FlatStyle.Flat;
        bc.DefaultCellStyle.BackColor = ACCENT; bc.DefaultCellStyle.ForeColor = Color.White;
        bc.DefaultCellStyle.SelectionBackColor = ACCENT; bc.DefaultCellStyle.SelectionForeColor = Color.White;
        dg.Columns.Add(bc);
        dg.Columns[0].FillWeight = 28; dg.Columns[1].FillWeight = 9; dg.Columns[2].FillWeight = 38;
        dg.Columns[3].FillWeight = 13; dg.Columns[4].FillWeight = 16;
        dg.RightToLeft = fa ? RightToLeft.Yes : RightToLeft.No;

        Button bAdd = MakeBtn(T("add"), 12, 374, 100);
        Button bEdit = MakeBtn(T("edit"), 118, 374, 100);
        Button bDel = MakeBtn(T("del"), 224, 374, 100);
        Button bTest = MakeBtn(T("test"), 330, 374, 130);
        Button bClose = MakeBtn(T("close"), 548, 374, 100);
        bAdd.Height = bEdit.Height = bDel.Height = bTest.Height = bClose.Height = 34;
        bAdd.Anchor = bEdit.Anchor = bDel.Anchor = bTest.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        bClose.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        bClose.DialogResult = DialogResult.Cancel; f.CancelButton = bClose;
        f.Controls.Add(dg); f.Controls.AddRange(new Control[] { bAdd, bEdit, bDel, bTest, bClose });
        StyleAll(f); StyleBtn(bAdd, true);
        Rtl(f);

        Entry chosen = null;
        dg.CellContentClick += delegate (object so, DataGridViewCellEventArgs ce)
        {
            if (ce.RowIndex < 0 || ce.ColumnIndex != 4 || ce.RowIndex >= entries.Count) return;
            chosen = entries[ce.RowIndex];
            f.Close();
        };
        bAdd.Click += delegate
        {
            string fk = FbKey(); Entry cur = SelMain();
            Entry n = ShowEditor(null, f);
            if (n == null) return;
            entries.Add(n); SaveList();
            FillCombos(cur != null ? cur.Name : "", fk);
            FillGrid(dg, entries.Count - 1);
        };
        bEdit.Click += delegate
        {
            if (dg.CurrentRow == null) return;
            int i = dg.CurrentRow.Index;
            if (i < 0 || i >= entries.Count) return;
            string fk = FbKey(); Entry cur = SelMain(); Entry old = entries[i];
            Entry n = ShowEditor(old, f);
            if (n == null) return;
            entries[i] = n; SaveList();
            if (fk == old.Name) fk = n.Name;
            FillCombos(cur == old ? n.Name : (cur != null ? cur.Name : ""), fk);
            FillGrid(dg, i);
        };
        bDel.Click += delegate
        {
            if (dg.CurrentRow == null) return;
            int i = dg.CurrentRow.Index;
            if (i < 0 || i >= entries.Count) return;
            if (Msg(f, TF("delConfirm", entries[i].Name), T("del"), MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            string fk = FbKey(); Entry cur = SelMain(); Entry old = entries[i];
            if (fk == old.Name) fk = "";
            entries.RemoveAt(i); SaveList();
            FillCombos(cur == null || cur == old ? "" : cur.Name, fk);
            FillGrid(dg, i);
        };
        bTest.Click += delegate
        {
            bTest.Enabled = bAdd.Enabled = bEdit.Enabled = bDel.Enabled = false;
            List<Entry> copy = new List<Entry>(entries);
            for (int p = 0; p < dg.Rows.Count; p++) dg.Rows[p].Cells[3].Value = "...";
            string failText = T("failTxt");
            Thread t = new Thread(delegate ()
            {
                for (int k = 0; k < copy.Count; k++)
                {
                    long best = -1; string why = "";
                    for (int j = 0; j < 3; j++)
                    {
                        Stopwatch sw = Stopwatch.StartNew();
                        byte[] rr = Upstream.Forward(copy[k], DnsUtil.BuildQuery("google.com"));
                        sw.Stop();
                        if (rr == null) { why = Upstream.LastError; break; }
                        if (best < 0 || sw.ElapsedMilliseconds < best) best = sw.ElapsedMilliseconds;
                    }
                    string txt = best < 0 ? failText : best + " ms";
                    string tipTxt = best < 0 ? why : "";
                    int row = k;
                    try { f.BeginInvoke(new Action(delegate { if (row < dg.Rows.Count) { dg.Rows[row].Cells[3].Value = txt; dg.Rows[row].Cells[3].ToolTipText = tipTxt; } })); } catch { }
                }
                try { f.BeginInvoke(new Action(delegate { bTest.Enabled = bAdd.Enabled = bEdit.Enabled = bDel.Enabled = true; })); } catch { }
            });
            t.IsBackground = true; t.Start();
        };

        Entry m0 = SelMain();
        FillGrid(dg, m0 != null ? entries.IndexOf(m0) : 0);
        f.ShowDialog(this);
        if (chosen != null)
        {
            FillCombos(chosen.Name, FbKey());
            Log(TF("mainSet", chosen.Name));
            if (applied) DoApply();
        }
    }

    // ---------- theme ----------
    void ApplyTheme()
    {
        SetColors(dark);
        BackColor = BG; ForeColor = TEXT;
        bodyPanel.BackColor = BG; homePanel.BackColor = BG; settingsPanel.BackColor = BG;
        StyleAll(homePanel); StyleAll(settingsPanel); StyleBtn(btnApply, true);
        tbLog.BackColor = LOGBG; tbLog.ForeColor = LOGFG;
        UpdateNav();
        headerPanel.Invalidate();
        if (IsHandleCreated) TitleBar(this);
        if (lbStatus != null && ni != null) UpdateStatus();
    }

    void StyleAll(Control parent)
    {
        foreach (Control x in parent.Controls)
        {
            if (x is Button) StyleBtn((Button)x, false);
            else if (x is ComboBox) { ComboBox c = (ComboBox)x; c.FlatStyle = FlatStyle.Flat; c.BackColor = FIELD; c.ForeColor = TEXT; }
            else if (x is TextBox)
            {
                TextBox t = (TextBox)x;
                if (t != tbLog) { t.BorderStyle = BorderStyle.FixedSingle; t.BackColor = FIELD; t.ForeColor = TEXT; }
            }
            else if (x is CheckBox) x.ForeColor = TEXT;
            else if (x is Label) x.ForeColor = MUTED;
        }
    }

    void StyleBtn(Button b, bool primary)
    {
        b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0; b.Cursor = Cursors.Hand;
        if (primary)
        {
            b.ForeColor = Color.White;
            b.BackColor = ACCENT;
            b.FlatAppearance.MouseOverBackColor = Color.FromArgb(132, 117, 246);
            b.FlatAppearance.MouseDownBackColor = Color.FromArgb(88, 72, 210);
        }
        else
        {
            b.ForeColor = TEXT;
            b.BackColor = BTN;
            b.FlatAppearance.MouseOverBackColor = HOVER;
            b.FlatAppearance.MouseDownBackColor = PRESS;
        }
    }

    void UpdateStatus()
    {
        if (applied) { lbStatus.Text = "\u25CF  " + T("active"); lbStatus.ForeColor = Color.FromArgb(46, 213, 115); }
        else { lbStatus.Text = "\u25CB  " + T("off"); lbStatus.ForeColor = Color.FromArgb(200, 206, 232); }
        ni.Text = applied ? "OVERX Dns - " + T("active") : "OVERX Dns - " + T("off");
    }

    Button MakeBtn(string t, int x, int y, int w) { Button b = new Button(); b.Text = t; b.SetBounds(x, y, w, 30); return b; }

    void ShowMe() { Show(); WindowState = FormWindowState.Normal; Activate(); }

    // ---------- settings ----------
    void LoadCfg()
    {
        cfg.Clear();
        string[] keys = new string[] { "main", "fb", "leak", "q", "start", "nov6", "rescue", "quic" };
        foreach (string k in keys) { string v = Store.Get("cfg_" + k, null); if (v != null) cfg[k] = v; }
    }

    string Cfg(string k, string d) { string v; return cfg.TryGetValue(k, out v) ? v : d; }

    void ApplyCfgToUi()
    {
        FillCombos(Cfg("main", ""), Cfg("fb", ""));
        chkLeak.Checked = Cfg("leak", "1") == "1";
        chkQ.Checked = Cfg("q", "1") == "1";
        chkStart.Checked = Cfg("start", "0") == "1";
        chkNoV6.Checked = Cfg("nov6", "1") == "1";
        chkRescue.Checked = Cfg("rescue", "1") == "1";
        chkQuic.Checked = Cfg("quic", "1") == "1";
    }

    void SaveCfg()
    {
        if (loading || wiped) return;
        try
        {
            Entry m = SelMain();
            List<string> l = new List<string>();
            l.Add("main=" + (m != null ? m.Name : ""));
            l.Add("fb=" + FbKey());
            l.Add("leak=" + (chkLeak.Checked ? "1" : "0"));
            l.Add("q=" + (chkQ.Checked ? "1" : "0"));
            l.Add("start=" + (chkStart.Checked ? "1" : "0"));
            l.Add("nov6=" + (chkNoV6.Checked ? "1" : "0"));
            l.Add("rescue=" + (chkRescue.Checked ? "1" : "0"));
            l.Add("dark=" + (dark ? "1" : "0"));
            l.Add("quic=" + (chkQuic.Checked ? "1" : "0"));
            l.Add("log=" + (logOpen ? "1" : "0"));
            l.Add("lang=" + (fa ? "fa" : "en"));
            foreach (string x in l) { int i = x.IndexOf('='); Store.Set("cfg_" + x.Substring(0, i), x.Substring(i + 1)); }
        }
        catch { }
    }

    // ---------- list ----------
    void LoadList()
    {
        entries.Clear();
        string text = Store.Get("dnslist", null);
        if (text == null)
        {
            string[] def = new string[] {
                "Google|UDP|8.8.8.8|8.8.4.4|",
                "Cloudflare|UDP|1.1.1.1|1.0.0.1|",
                "Quad9|UDP|9.9.9.9|149.112.112.112|",
                "Cloudflare DoH|DOH|1.1.1.1|1.0.0.1|https://1.1.1.1/dns-query",
                "Google DoT|DOT|8.8.8.8||dns.google"
            };
            text = string.Join("\n", def);
        }
        text = text.Replace("|1.1.1.1|1.0.0.1|https://cloudflare-dns.com/dns-query", "|1.1.1.1|1.0.0.1|https://1.1.1.1/dns-query");
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            string[] p = line.Split('|');
            if (p.Length < 5) continue;
            Entry e = new Entry();
            e.Name = p[0]; e.Type = p[1].ToUpper(); e.Primary = p[2]; e.Secondary = p[3]; e.Url = p[4];
            entries.Add(e);
        }
    }

    void SaveList()
    {
        List<string> lines = new List<string>();
        foreach (Entry e in entries) lines.Add(e.ToLine());
        Store.Set("dnslist", string.Join("\n", lines.ToArray()));
    }

    void FillCombos(string mainName, string fbKey)
    {
        bool old = loading; loading = true;
        cbDns.Items.Clear(); cbFb.Items.Clear();
        cbFb.Items.Add(T("sameMain")); cbFb.Items.Add(T("origDns"));
        foreach (Entry e in entries) { cbDns.Items.Add(e.ToString()); cbFb.Items.Add(e.ToString()); }
        int mi = 0, fi = 0;
        for (int i = 0; i < entries.Count; i++)
        {
            if (entries[i].Name == mainName) mi = i;
            if (entries[i].Name == fbKey) fi = i + 2;
        }
        if (fbKey == "@orig") fi = 1;
        if (cbDns.Items.Count > 0) cbDns.SelectedIndex = mi;
        cbFb.SelectedIndex = fi;
        loading = old;
        ShowInfo();
    }

    Entry SelMain() { int i = cbDns.SelectedIndex; return i < 0 || i >= entries.Count ? null : entries[i]; }

    string FbKey()
    {
        int i = cbFb.SelectedIndex;
        if (i <= 0) return "";
        if (i == 1) return "@orig";
        return i - 2 < entries.Count ? entries[i - 2].Name : "";
    }

    void ShowInfo()
    {
        Entry e = SelMain();
        if (e == null) { lbInfo.Text = ""; return; }
        string s = e.Type + "   " + e.Primary;
        if (e.Secondary != "") s += " , " + e.Secondary;
        if (e.Url != "") s += "\n" + e.Url;
        lbInfo.Text = s;
        SaveCfg();
    }

    // every active physical network adapter is used (no manual selection)
    List<string> TargetAdapters()
    {
        List<string> t = new List<string>();
        foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (n.OperationalStatus != OperationalStatus.Up) continue;
            if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || n.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
            string d = n.Description.ToLower();
            if (d.Contains("virtualbox") || d.Contains("vmware") || d.Contains("hyper-v") || d.Contains("loopback")) continue;
            t.Add(n.Name);
        }
        return t;
    }

    // ---------- rules ----------
    List<Rule> ParseRules()
    {
        List<Rule> list = new List<Rule>();
        foreach (string raw in RulesText().Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            Rule ru = new Rule();
            if (line[0] == '!') { ru.Block = true; line = line.Substring(1).Trim(); }
            string target = "";
            int bar = line.IndexOf('|');
            if (bar >= 0) { target = line.Substring(bar + 1).Trim(); line = line.Substring(0, bar).Trim(); }
            line = line.ToLowerInvariant().TrimStart('*', '.');
            if (line.Length == 0) continue;
            ru.Domain = line;
            if (string.Equals(target, "original", StringComparison.OrdinalIgnoreCase)) ru.UseOrig = true;
            else if (target != "")
                foreach (Entry e in entries)
                    if (string.Equals(e.Name, target, StringComparison.OrdinalIgnoreCase)) ru.Target = e;
            list.Add(ru);
        }
        return list;
    }

    void OpenRules()
    {
        Form f = new Form();
        f.Text = T("rulesTitle"); f.ClientSize = new Size(540, 420); f.Font = Font; f.StartPosition = FormStartPosition.CenterParent;
        f.BackColor = BG; f.MinimumSize = new Size(400, 300);
        TextBox tb = new TextBox(); tb.Multiline = true; tb.AcceptsReturn = true; tb.ScrollBars = ScrollBars.Vertical;
        tb.Font = new Font("Consolas", 9.5f); tb.SetBounds(10, 10, 520, 360);
        tb.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        tb.Text = RulesText().Replace("\r", "").Replace("\n", "\r\n");
        Button ok = new Button(); ok.Text = T("save"); ok.SetBounds(330, 380, 95, 30); ok.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        Button cancel = new Button(); cancel.Text = T("cancel"); cancel.SetBounds(435, 380, 95, 30); cancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        cancel.DialogResult = DialogResult.Cancel;
        f.Controls.Add(tb); f.Controls.Add(ok); f.Controls.Add(cancel);
        f.CancelButton = cancel;
        StyleAll(f); StyleBtn(ok, true);
        Rtl(f);
        tb.RightToLeft = fa ? RightToLeft.Yes : RightToLeft.No;
        f.HandleCreated += delegate { TitleBar(f); };
        ok.Click += delegate { Store.Set("rules", tb.Text); f.DialogResult = DialogResult.OK; f.Close(); };
        f.Shown += delegate { tb.SelectionStart = 0; tb.SelectionLength = 0; };
        if (f.ShowDialog(this) == DialogResult.OK) ReloadRules();
    }

    static string AddRuleLine(string text, string domain, string target)
    {
        List<string> keep = new List<string>();
        foreach (string raw in text.Replace("\r", "").Split('\n'))
        {
            string t = raw.Trim();
            if (t.Length > 0 && t[0] != '#')
            {
                string d = t.TrimStart('!');
                int bar = d.IndexOf('|');
                if (bar >= 0) d = d.Substring(0, bar);
                d = d.Trim().ToLowerInvariant().TrimStart('*', '.');
                if (d == domain) continue;
            }
            keep.Add(raw.TrimEnd());
        }
        while (keep.Count > 0 && keep[keep.Count - 1] == "") keep.RemoveAt(keep.Count - 1);
        keep.Add(domain + "|" + target);
        return string.Join("\r\n", keep.ToArray()) + "\r\n";
    }

    // after a crash the DNS can be left on 127.0.0.1 with nothing listening: put it back to automatic
    void RecoverFromCrash()
    {
        try
        {
            bool free;
            try { UdpClient t = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53)); t.Close(); free = true; } catch { free = false; }
            if (!free) return;
            bool fixedAny = false;
            foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || n.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                foreach (IPAddress a in n.GetIPProperties().DnsAddresses)
                    if (a.AddressFamily == AddressFamily.InterNetwork && IPAddress.IsLoopback(a)) { ResetOne(n.Name); fixedAny = true; break; }
            }
            if (fixedAny)
            {
                Policies(false); RemoveFirewall(); Run("ipconfig", "/flushdns");
                Log(T("recovered"));
            }
        }
        catch { }
    }

    void ReloadRules()
    {
        if (router == null) { Log(T("rulesSaved")); return; }
        List<Rule> l = ParseRules();
        router.SetRules(l);
        engine.ClearCache();
        Log(TF("rulesReloaded", l.Count));
    }

    // ---------- apply / clear ----------
    Entry MakeOrig(List<string> targets)
    {
        List<string> v4 = new List<string>(), v6 = new List<string>();
        foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!targets.Contains(n.Name)) continue;
            foreach (IPAddress a in n.GetIPProperties().DnsAddresses)
            {
                if (IPAddress.IsLoopback(a)) continue;
                string t = a.ToString();
                if (a.AddressFamily == AddressFamily.InterNetwork) { if (!v4.Contains(t)) v4.Add(t); }
                else if (a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6SiteLocal) { if (!v6.Contains(t)) v6.Add(t); }
            }
        }
        List<string> ips = v4.Count > 0 ? v4 : v6;
        Entry e = new Entry();
        e.Name = "original DNS"; e.Type = "UDP";
        e.Primary = ips.Count > 0 ? ips[0] : "1.1.1.1";
        e.Secondary = ips.Count > 1 ? ips[1] : (ips.Count == 0 ? "8.8.8.8" : "");
        return e;
    }

    Router BuildRouter(Entry main, Entry orig)
    {
        Router r = new Router();
        r.Main = main;
        r.NoAAAA = chkNoV6.Checked;
        r.UseRescue = chkRescue.Checked;
        r.Orig = orig;
        string fk = FbKey();
        if (fk == "@orig") r.Fallback = orig;
        else if (fk != "") foreach (Entry e in entries) if (e.Name == fk) r.Fallback = e;
        r.SetRules(ParseRules());

        List<Entry> used = new List<Entry>();
        used.Add(main);
        if (r.Fallback != null) used.Add(r.Fallback);
        foreach (Rule x in r.Rules) if (x.Target != null) used.Add(x.Target);

        // resolve encrypted-DNS host names now (before DNS changes) so the proxy never waits on itself
        foreach (Entry e in used)
        {
            string host = null;
            if (e.Type == "DOH") { try { host = new Uri(e.Url).Host; } catch { } }
            else if (e.Type == "DOT" && e.Primary == "") host = e.Url;
            if (host == null) continue;
            IPAddress dummy;
            if (IPAddress.TryParse(host, out dummy)) continue;
            string ip = e.Primary;
            if (ip == "")
            {
                foreach (IPAddress a in System.Net.Dns.GetHostAddresses(host))
                    if (a.AddressFamily == AddressFamily.InterNetwork) { ip = a.ToString(); break; }
            }
            if (ip != "") r.Bootstrap[host.ToLowerInvariant()] = ip;
            else throw new Exception("Could not resolve " + host + " - set a Primary IP for that entry.");
        }
        return r;
    }

    void DoApply()
    {
        Entry main = SelMain();
        if (main == null) { Log(T("addDnsFirst")); return; }
        List<string> targets = TargetAdapters();
        if (targets.Count == 0) { Log(T("noAdapter")); return; }
        Cursor = Cursors.WaitCursor;
        try
        {
            if (applied) ResetAll();
            EnsureFirewall();
            Entry orig = MakeOrig(targets);
            router = BuildRouter(main, orig);
            Log(TF("origDetected", orig.Primary + (orig.Secondary != "" ? ", " + orig.Secondary : "")));
            engine.Start(router, QLog);

            foreach (string ad in targets)
            {
                string o = Run("netsh", "interface ip set dns name=\"" + ad + "\" static 127.0.0.1 primary validate=no");
                if (o != "") Log(ad + ": " + o);
                Run("netsh", "interface ipv6 set dnsservers name=\"" + ad + "\" static ::1 primary validate=no");
            }
            appliedAdapters = targets;
            if (chkLeak.Checked) Policies(true);
            SetQuicBlock(chkQuic.Checked);
            Run("ipconfig", "/flushdns");
            applied = true;
            UpdateStatus();
            SaveCfg();
            string rules = router.Rules.Count > 0 ? TF("rulesPart", router.Rules.Count) : "";
            Log(TF("activeMsg", main.Name, router.Fallback != null ? TF("fbPart", router.Fallback.Name) : "", rules, string.Join(", ", targets.ToArray())));
            Entry mt = main;
            Thread tst = new Thread(delegate ()
            {
                Stopwatch swt = Stopwatch.StartNew();
                byte[] rt2 = Upstream.Forward(mt, DnsUtil.BuildQuery("google.com"));
                swt.Stop();
                if (rt2 != null) Log(TF("selfOk", mt.Name, swt.ElapsedMilliseconds));
                else Log(TF("selfFail", mt.Name, Upstream.LastError));
            });
            tst.IsBackground = true; tst.Start();
        }
        catch (Exception ex)
        {
            Log(TF("error", ex.Message));
            if (ex.Message.Contains("53")) { string w = WhoUses53(); if (w != "") Log(TF("port53", w)); }
            engine.Stop(); router = null;
        }
        finally { Cursor = Cursors.Default; }
    }

    void DoClear()
    {
        Cursor = Cursors.WaitCursor;
        if (applied) ResetAll();
        else
        {
            foreach (string ad in TargetAdapters()) ResetOne(ad);
            Run("ipconfig", "/flushdns");
            RemoveFirewall();
            Log(T("dnsReset"));
        }
        Cursor = Cursors.Default;
    }

    void ResetOne(string ad)
    {
        Run("netsh", "interface ip set dns name=\"" + ad + "\" source=dhcp");
        Run("netsh", "interface ipv6 set dnsservers name=\"" + ad + "\" source=dhcp");
    }

    void ResetAll()
    {
        foreach (string ad in appliedAdapters) ResetOne(ad);
        Policies(false);
        engine.Stop();
        router = null; applied = false;
        UpdateStatus();
        Run("ipconfig", "/flushdns");
        RemoveFirewall();
        Log(T("stopped"));
    }

    static void Policies(bool on)
    {
        SetPol(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DisableSmartNameResolution", on ? (object)1 : null, RegistryValueKind.DWord);
        SetPol(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", on ? (object)"off" : null, RegistryValueKind.String);
        SetPol(@"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", on ? (object)"off" : null, RegistryValueKind.String);
        SetPol(@"SOFTWARE\Policies\Google\Chrome", "QuicAllowed", on ? (object)0 : null, RegistryValueKind.DWord);
        SetPol(@"SOFTWARE\Policies\Microsoft\Edge", "QuicAllowed", on ? (object)0 : null, RegistryValueKind.DWord);
        SetPol(@"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", on ? (object)"off" : null, RegistryValueKind.String);
        SetPol(@"SOFTWARE\Policies\BraveSoftware\Brave", "QuicAllowed", on ? (object)0 : null, RegistryValueKind.DWord);
        SetPol(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", on ? (object)0 : null, RegistryValueKind.DWord);
    }

    static void SetPol(string path, string name, object val, RegistryValueKind kind)
    {
        try
        {
            if (val != null)
            {
                using (RegistryKey k = Registry.LocalMachine.CreateSubKey(path)) { k.SetValue(name, val, kind); }
            }
            else
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(path, true)) { if (k != null) k.DeleteValue(name, false); }
            }
        }
        catch { }
    }

    // Windows Firewall: remove old (auto-created) block rules for this exe and add allow rules in+out
    void EnsureFirewall()
    {
        if (fwDone) return;
        string exe = Application.ExecutablePath;
        Run("netsh", "advfirewall firewall delete rule name=all program=\"" + exe + "\"");
        Run("netsh", "advfirewall firewall add rule name=\"OVERX Dns\" dir=in action=allow program=\"" + exe + "\" enable=yes profile=any");
        Run("netsh", "advfirewall firewall add rule name=\"OVERX Dns\" dir=out action=allow program=\"" + exe + "\" enable=yes profile=any");
        fwDone = true;
        Log(T("fwAdded"));
    }

    // remove the allow rules again (called on Clear and on exit)
    void RemoveFirewall()
    {
        Run("netsh", "advfirewall firewall delete rule name=\"OVERX Dns\"");
        Run("netsh", "advfirewall firewall delete rule name=\"OVERX Dns QUIC\"");
        fwDone = false;
    }

    // QUIC (HTTP/3 over UDP 443) cannot pass a DNS-based TCP proxy; blocking it makes every browser fall back to normal HTTPS at once
    static void SetQuicBlock(bool on)
    {
        Run("netsh", "advfirewall firewall delete rule name=\"OVERX Dns QUIC\"");
        if (on) Run("netsh", "advfirewall firewall add rule name=\"OVERX Dns QUIC\" dir=out action=block protocol=UDP remoteport=443 profile=any");
    }

    static string WhoUses53()
    {
        try
        {
            string o = Run("netstat", "-ano -p UDP");
            foreach (string line in o.Split('\n'))
            {
                string[] c = line.Split(new char[] { ' ', '\t', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                if (c.Length >= 4 && c[0] == "UDP" && c[1].EndsWith(":53"))
                {
                    int pid = int.Parse(c[c.Length - 1]);
                    return Process.GetProcessById(pid).ProcessName + " (pid " + pid + ", " + c[1] + ")";
                }
            }
        }
        catch { }
        return "";
    }

    // ---------- helpers ----------
    static string Run(string file, string args)
    {
        try
        {
            Process p = new Process();
            p.StartInfo.FileName = file; p.StartInfo.Arguments = args;
            p.StartInfo.UseShellExecute = false; p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardOutput = true; p.StartInfo.RedirectStandardError = true;
            p.Start();
            string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return o.Trim();
        }
        catch (Exception ex) { return ex.Message; }
    }

    public void Log(string m)
    {
        if (InvokeRequired) { try { BeginInvoke(new Action<string>(Log), m); } catch { } return; }
        tbLog.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + m + "\r\n");
    }

    void QLog(string s)
    {
        if (!showQ) return;
        lock (pend) { if (pend.Count < 500) pend.Enqueue(DateTime.Now.ToString("HH:mm:ss") + "  " + s); }
    }

    void Drain()
    {
        StringBuilder sb = new StringBuilder();
        lock (pend) { while (pend.Count > 0) sb.Append(pend.Dequeue()).Append("\r\n"); }
        if (sb.Length == 0) return;
        tbLog.AppendText(sb.ToString());
        if (tbLog.TextLength > 80000)
        {
            tbLog.Text = tbLog.Text.Substring(tbLog.TextLength - 40000);
            tbLog.SelectionStart = tbLog.TextLength; tbLog.ScrollToCaret();
        }
    }

    Entry ShowEditor(Entry src, IWin32Window owner)
    {
        Form f = new Form();
        f.Text = src == null ? T("addTitle") : T("editTitle");
        f.ClientSize = new Size(390, 250); f.Font = Font;
        f.FormBorderStyle = FormBorderStyle.FixedDialog; f.StartPosition = FormStartPosition.CenterParent;
        f.MaximizeBox = false; f.MinimizeBox = false;

        string[] labs = new string[] { T("eName"), T("eType"), T("ePrimary"), T("eSecondary"), T("eUrl") };
        TextBox tName = new TextBox(), tP = new TextBox(), tS = new TextBox(), tU = new TextBox();
        ComboBox cT = new ComboBox(); cT.DropDownStyle = ComboBoxStyle.DropDownList;
        cT.Items.AddRange(new object[] { "UDP", "DOH", "DOT" }); cT.SelectedIndex = 0;
        Control[] ctl = new Control[] { tName, cT, tP, tS, tU };
        for (int i = 0; i < 5; i++)
        {
            Label l = new Label(); l.Text = labs[i]; l.Left = 10; l.Top = 18 + i * 36; l.Width = 150;
            ctl[i].Left = 165; ctl[i].Top = 15 + i * 36; ctl[i].Width = 212;
            f.Controls.Add(l); f.Controls.Add(ctl[i]);
        }
        if (src != null)
        {
            tName.Text = src.Name; tP.Text = src.Primary; tS.Text = src.Secondary; tU.Text = src.Url;
            cT.SelectedItem = src.Type;
        }
        Button ok = new Button(); ok.Text = T("save"); ok.SetBounds(165, 205, 100, 30);
        Button cancel = new Button(); cancel.Text = T("cancel"); cancel.SetBounds(277, 205, 100, 30);
        cancel.DialogResult = DialogResult.Cancel;
        f.Controls.Add(ok); f.Controls.Add(cancel);
        f.AcceptButton = ok; f.CancelButton = cancel;

        f.BackColor = BG; StyleAll(f); StyleBtn(ok, true);
        Rtl(f);
        tP.RightToLeft = tS.RightToLeft = tU.RightToLeft = RightToLeft.No;
        Entry result = null;
        ok.Click += delegate
        {
            string type = cT.SelectedItem.ToString();
            string err = null;
            IPAddress tmp;
            if (tName.Text.Trim() == "" || tName.Text.Contains("|")) err = T("errName");
            else if (tP.Text.Trim() != "" && !IPAddress.TryParse(tP.Text.Trim(), out tmp)) err = T("errP");
            else if (tS.Text.Trim() != "" && !IPAddress.TryParse(tS.Text.Trim(), out tmp)) err = T("errS");
            else if (type == "UDP" && tP.Text.Trim() == "") err = T("errUdp");
            else if (type == "DOH" && !tU.Text.Trim().StartsWith("https://")) err = T("errDoh");
            else if (type == "DOT" && tU.Text.Trim() == "" && tP.Text.Trim() == "") err = T("errDot");
            if (err != null) { Msg(f, err, f.Text, MessageBoxButtons.OK); return; }
            Entry n = new Entry();
            n.Name = tName.Text.Trim(); n.Type = type; n.Primary = tP.Text.Trim();
            n.Secondary = tS.Text.Trim(); n.Url = tU.Text.Trim();
            result = n;
            f.DialogResult = DialogResult.OK; f.Close();
        };
        f.HandleCreated += delegate { TitleBar(f); };
        f.ShowDialog(owner);
        return result;
    }

    [STAThread]
    static void Main(string[] args)
    {
        InitTr();
        fa = Store.Get("cfg_lang", "en") == "fa";
        bool created;
        Mutex m = new Mutex(true, "OVERX DnsSingleInstance", out created);
        if (!created) { Msg(null, T("already"), "OVERX Dns", MessageBoxButtons.OK); return; }
        ThreadPool.SetMinThreads(64, 64);
        try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288; }
        catch { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
        ServicePointManager.DefaultConnectionLimit = 32;
        ServicePointManager.Expect100Continue = false;
        Application.EnableVisualStyles();
        Application.Run(new MainForm(Array.IndexOf(args, "--auto") >= 0));
        GC.KeepAlive(m);
    }
}
