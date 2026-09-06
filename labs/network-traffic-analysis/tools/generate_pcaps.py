#!/usr/bin/env python3
"""
Network Traffic Analysis lab :: pcap builder
=============================================
Crafts the capture files every room in this module works against. Everything is
synthetic and deterministic - the ANSWER-KEY.md values are derived straight from
the constants below, so a rebuild always produces the same answers.

    python3 generate_pcaps.py [OUTDIR]     # default OUTDIR = ../pcaps

Requires: scapy  (pip install scapy)
Only writes .pcap files. Sends nothing on the wire.
"""
import sys, os, struct

try:
    from scapy.all import (
        Ether, ARP, IP, ICMP, UDP, TCP, Raw, DNS, DNSQR, DNSRR, wrpcap,
    )
except ImportError:
    sys.exit("scapy is required:  pip install scapy")

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "pcaps")
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------------------
# Fixed lab facts (also the answer key)
# ---------------------------------------------------------------------------
T0 = 1725624000.0                       # 2024-09-06 12:00:00 UTC

ANALYST_MAC  = "08:00:27:aa:bb:01"      # the SOC workstation / capture host
GW_MAC       = "08:00:27:00:00:fe"      # default gateway
VICTIM_MAC   = "08:00:27:de:ad:10"      # 10.14.0.10  (compromised workstation)
ATTACKER_MAC = "52:54:00:13:37:99"      # 10.14.0.99  (attacker box, room 4)

DNS_SERVER   = "10.14.0.2"
GW_IP        = "10.14.0.1"


def png_1x1():
    """Smallest valid PNG (1x1 transparent) - NetworkMiner file-carving target."""
    import zlib
    sig = b"\x89PNG\r\n\x1a\n"
    def chunk(typ, data):
        return struct.pack(">I", len(data)) + typ + data + \
               struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x00\x00\x00")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


class Stream:
    """A single TCP conversation with correct seq/ack so Wireshark reassembles
    it and 'Follow Stream' / 'Export Objects' work."""

    def __init__(self, cmac, smac, cip, sip, sport, dport, t):
        self.cmac, self.smac = cmac, smac
        self.cip, self.sip = cip, sip
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.t = t
        self.pkts = []

    def _emit(self, pkt, dt=0.002):
        self.t += dt
        pkt.time = self.t
        self.pkts.append(pkt)

    def _c(self, flags, ack=True, load=b""):
        p = (Ether(src=self.cmac, dst=self.smac) /
             IP(src=self.cip, dst=self.sip) /
             TCP(sport=self.sport, dport=self.dport, flags=flags,
                 seq=self.cseq, ack=self.sseq if ack else 0))
        if load:
            p = p / Raw(load=load)
        return p

    def _s(self, flags, load=b""):
        p = (Ether(src=self.smac, dst=self.cmac) /
             IP(src=self.sip, dst=self.cip) /
             TCP(sport=self.dport, dport=self.sport, flags=flags,
                 seq=self.sseq, ack=self.cseq))
        if load:
            p = p / Raw(load=load)
        return p

    def handshake(self):
        self._emit(self._c("S", ack=False))
        self._emit(self._s("SA"))
        self.cseq += 1
        self.sseq += 1
        self._emit(self._c("A"))
        return self

    def send(self, data, dt=0.01):
        raw = data if isinstance(data, bytes) else data.encode()
        self._emit(self._c("PA", load=raw), dt)
        self.cseq += len(raw)
        self._emit(self._s("A"))
        return self

    def recv(self, data, dt=0.03):
        raw = data if isinstance(data, bytes) else data.encode()
        self._emit(self._s("PA", load=raw), dt)
        self.sseq += len(raw)
        self._emit(self._c("A"))
        return self

    def close(self):
        self._emit(self._c("FA"))
        self.cseq += 1
        self._emit(self._s("FA"))
        self.sseq += 1
        self._emit(self._c("A"))
        return self


def http_response(body, ctype="text/html", extra=""):
    if isinstance(body, str):
        body = body.encode()
    head = (f"HTTP/1.1 200 OK\r\n"
            f"Server: nginx/1.18.0\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"{extra}"
            f"Connection: close\r\n\r\n").encode()
    return head + body


# ===========================================================================
# 1. net-basics.pcap  -- ARP, ICMP, DNS, one HTTP GET/200, clean teardown
# ===========================================================================
def build_net_basics():
    p = []
    t = T0

    # ARP: analyst resolves the gateway
    a = Ether(src=ANALYST_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=ANALYST_MAC, psrc="10.14.0.50", pdst=GW_IP)
    a.time = t; p.append(a); t += 0.004
    b = Ether(src=GW_MAC, dst=ANALYST_MAC) / ARP(
        op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=ANALYST_MAC, pdst="10.14.0.50")
    b.time = t; p.append(b); t += 0.2

    # ICMP: ping the gateway 3x
    for i in range(3):
        q = Ether(src=ANALYST_MAC, dst=GW_MAC) / IP(src="10.14.0.50", dst=GW_IP) / \
            ICMP(type=8, id=0x1337, seq=i + 1) / Raw(load=b"abcdefghijklmnop")
        q.time = t; p.append(q); t += 0.03
        r = Ether(src=GW_MAC, dst=ANALYST_MAC) / IP(src=GW_IP, dst="10.14.0.50") / \
            ICMP(type=0, id=0x1337, seq=i + 1) / Raw(load=b"abcdefghijklmnop")
        r.time = t; p.append(r); t += 1.0

    # DNS: A query for example.com -> 93.184.216.34
    dq = Ether(src=ANALYST_MAC, dst=GW_MAC) / IP(src="10.14.0.50", dst=DNS_SERVER) / \
        UDP(sport=51000, dport=53) / DNS(id=0x2a2a, rd=1, qd=DNSQR(qname="example.com"))
    dq.time = t; p.append(dq); t += 0.05
    dr = Ether(src=GW_MAC, dst=ANALYST_MAC) / IP(src=DNS_SERVER, dst="10.14.0.50") / \
        UDP(sport=53, dport=51000) / DNS(id=0x2a2a, qr=1, rd=1, ra=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", type="A", ttl=3600, rdata="93.184.216.34"))
    dr.time = t; p.append(dr); t += 0.1

    # HTTP GET / -> 200
    s = Stream(ANALYST_MAC, GW_MAC, "10.14.0.50", "93.184.216.34", 51001, 80, t)
    s.handshake()
    s.send("GET / HTTP/1.1\r\nHost: example.com\r\n"
           "User-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n")
    s.recv(http_response("<html><body><h1>Example Domain</h1></body></html>\n"))
    s.close()
    p += s.pkts

    wrpcap(os.path.join(OUT, "net-basics.pcap"), p)
    print(f"  net-basics.pcap            {len(p):4d} pkts")


# ===========================================================================
# 2. wireshark-basics.pcap -- a browsing session: DNS x3, HTTP x2, ICMP,
#    gratuitous ARP, one NXDOMAIN. For display filters / Statistics / hierarchy.
# ===========================================================================
def build_wireshark_basics():
    p = []
    t = T0
    client = "10.14.0.50"
    cmac = ANALYST_MAC

    # gratuitous ARP from the gateway
    g = Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=GW_MAC, psrc=GW_IP, pdst=GW_IP)
    g.time = t; p.append(g); t += 0.5

    def dns(qname, ip, qid, nx=False):
        nonlocal t
        q = Ether(src=cmac, dst=GW_MAC) / IP(src=client, dst=DNS_SERVER) / \
            UDP(sport=52000 + qid, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname))
        q.time = t; p.append(q); t += 0.04
        ans = DNS(id=qid, qr=1, rd=1, ra=1, rcode=3 if nx else 0,
                  qd=DNSQR(qname=qname))
        if not nx:
            ans.an = DNSRR(rrname=qname, type="A", ttl=300, rdata=ip)
        r = Ether(src=GW_MAC, dst=cmac) / IP(src=DNS_SERVER, dst=client) / \
            UDP(sport=53, dport=52000 + qid) / ans
        r.time = t; p.append(r); t += 0.3

    dns("www.company-intranet.lan", "10.14.0.80", 101)
    dns("cdn.jsdelivr.net", "151.101.1.229", 102)
    dns("nosuch.company-intranet.lan", None, 103, nx=True)

    # HTTP GET to the intranet
    s1 = Stream(cmac, GW_MAC, client, "10.14.0.80", 40001, 80, t)
    s1.handshake()
    s1.send("GET /index.html HTTP/1.1\r\nHost: www.company-intranet.lan\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n"
            "Accept-Language: en-US\r\n\r\n")
    s1.recv(http_response(
        "<html><head><title>Company Intranet</title></head>"
        "<body>Welcome. <img src=/logo.png></body></html>\n"))
    s1.send("GET /logo.png HTTP/1.1\r\nHost: www.company-intranet.lan\r\n"
            "Referer: http://www.company-intranet.lan/index.html\r\n\r\n")
    s1.recv(http_response(png_1x1(), ctype="image/png"))
    s1.close()
    p += s1.pkts
    t = s1.t + 0.5

    # HTTP GET to the CDN
    s2 = Stream(cmac, GW_MAC, client, "151.101.1.229", 40002, 80, t)
    s2.handshake()
    s2.send("GET /npm/jquery@3.7.1/dist/jquery.min.js HTTP/1.1\r\n"
            "Host: cdn.jsdelivr.net\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    s2.recv(http_response("/*! jQuery v3.7.1 */\n", ctype="application/javascript"))
    s2.close()
    p += s2.pkts
    t = s2.t + 0.5

    # a few ICMP pings to the CDN host
    for i in range(4):
        q = Ether(src=cmac, dst=GW_MAC) / IP(src=client, dst="151.101.1.229") / \
            ICMP(type=8, id=0x4242, seq=i + 1) / Raw(load=b"wireshark-basics")
        q.time = t; p.append(q); t += 0.02
        r = Ether(src=GW_MAC, dst=cmac) / IP(src="151.101.1.229", dst=client) / \
            ICMP(type=0, id=0x4242, seq=i + 1) / Raw(load=b"wireshark-basics")
        r.time = t; p.append(r); t += 0.8

    wrpcap(os.path.join(OUT, "wireshark-basics.pcap"), p)
    print(f"  wireshark-basics.pcap      {len(p):4d} pkts")


# ===========================================================================
# 3. packet-operations.pcap -- cleartext creds everywhere + a file to export.
#    HTTP Basic auth, an HTTP POST login form, an HTTP file download, and a
#    full cleartext FTP session (USER / PASS / RETR).
# ===========================================================================
def build_packet_operations():
    import base64
    p = []
    t = T0
    client = "10.14.0.50"
    cmac = ANALYST_MAC
    web = "10.14.0.80"

    # --- HTTP Basic auth (admin:Password123!) to /admin ---
    creds = base64.b64encode(b"admin:Password123!").decode()
    s = Stream(cmac, GW_MAC, client, web, 44001, 80, t)
    s.handshake()
    s.send(f"GET /admin/ HTTP/1.1\r\nHost: portal.company-intranet.lan\r\n"
           f"Authorization: Basic {creds}\r\n"
           f"User-Agent: Mozilla/5.0\r\n\r\n")
    s.recv(http_response("<html><body>Admin dashboard</body></html>\n"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # --- HTTP POST login form (j.doe / S3cr3t-Winter-2024) ---
    body = "username=j.doe&password=S3cr3t-Winter-2024&remember=1"
    s = Stream(cmac, GW_MAC, client, web, 44002, 80, t)
    s.handshake()
    s.send("POST /login.php HTTP/1.1\r\nHost: portal.company-intranet.lan\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n"
           "User-Agent: Mozilla/5.0\r\n\r\n" + body)
    s.recv(("HTTP/1.1 302 Found\r\nLocation: /dashboard.php\r\n"
            "Set-Cookie: PHPSESSID=b1f7c0de9a4e11ee; path=/\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # --- HTTP download of a sensitive file (Export Objects > HTTP) ---
    secret = ("CONFIDENTIAL - Q3 salary review\n"
              "flag{http_object_export_works}\n"
              "Do not distribute.\n")
    s = Stream(cmac, GW_MAC, client, web, 44003, 80, t)
    s.handshake()
    s.send("GET /files/q3-salaries.txt HTTP/1.1\r\n"
           "Host: portal.company-intranet.lan\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    s.recv(http_response(
        secret, ctype="text/plain",
        extra='Content-Disposition: attachment; filename="q3-salaries.txt"\r\n'))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # --- cleartext FTP: USER / PASS / RETR ---
    ftp = "10.14.0.90"
    fs = Stream(cmac, GW_MAC, client, ftp, 44010, 21, t)
    fs.handshake()
    fs.recv("220 (vsFTPd 3.0.3)\r\n")
    fs.send("USER backup-svc\r\n"); fs.recv("331 Please specify the password.\r\n")
    fs.send("PASS Backup#2024!\r\n"); fs.recv("230 Login successful.\r\n")
    fs.send("SYST\r\n");             fs.recv("215 UNIX Type: L8\r\n")
    fs.send("TYPE I\r\n");           fs.recv("200 Switching to Binary mode.\r\n")
    fs.send("PASV\r\n");             fs.recv("227 Entering Passive Mode (10,14,0,90,200,1).\r\n")
    fs.send("RETR backups/db-2024-09-06.sql\r\n")
    fs.recv("150 Opening BINARY mode data connection.\r\n")
    fs.recv("226 Transfer complete.\r\n")
    fs.send("QUIT\r\n");             fs.recv("221 Goodbye.\r\n")
    fs.close()
    p += fs.pkts

    # FTP-DATA on the negotiated passive port 51201 (200*256+1)
    ds = Stream(cmac, GW_MAC, client, ftp, 44011, 51201, fs.pkts[3].time + 0.05)
    ds.handshake()
    ds.recv(b"-- MySQL dump 10.13\n-- Host: db01  Database: intranet\n"
            b"INSERT INTO users VALUES (1,'j.doe','$2y$10$abcdef...');\n")
    ds.close()
    p += ds.pkts

    p.sort(key=lambda x: x.time)
    wrpcap(os.path.join(OUT, "packet-operations.pcap"), p)
    print(f"  packet-operations.pcap     {len(p):4d} pkts")


# ===========================================================================
# 4. traffic-analysis.pcap -- an incident.
#    (a) SYN scan 10.14.0.99 -> 10.14.0.10   (20 ports, 3 open)
#    (b) Nikto-style web scan against the one open web port
#    (c) malicious download  GET /update.exe -> MZ...
#    (d) 8 C2 beacons  10.14.0.10 -> 185.199.108.153:443  every 60s, ~identical size
#    (e) DNS tunneling burst: long TXT queries to *.c2.evil-corp.xyz
# ===========================================================================
def build_traffic_analysis():
    p = []
    t = T0
    victim = "10.14.0.10"
    attacker = "10.14.0.99"
    c2 = "185.199.108.153"

    # (a) SYN scan  (nmap-style top-ports sweep from one source port)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                  443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    open_ports = {22, 80, 445}
    for i, port in enumerate(scan_ports):
        syn = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / \
            IP(src=attacker, dst=victim) / \
            TCP(sport=44444, dport=port, flags="S", seq=0x1000 + i)
        syn.time = t; p.append(syn); t += 0.006
        if port in open_ports:
            sa = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / \
                IP(src=victim, dst=attacker) / \
                TCP(sport=port, dport=44444, flags="SA", seq=0x9000 + i, ack=0x1001 + i)
            sa.time = t; p.append(sa); t += 0.002
            rst = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / \
                IP(src=attacker, dst=victim) / \
                TCP(sport=44444, dport=port, flags="R", seq=0x1001 + i)
            rst.time = t; p.append(rst); t += 0.006
        else:
            ra = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / \
                IP(src=victim, dst=attacker) / \
                TCP(sport=port, dport=44444, flags="RA", seq=0, ack=0x1001 + i)
            ra.time = t; p.append(ra); t += 0.006
    t += 2.0

    # (b) Nikto-style web scan from the attacker
    s = Stream(ATTACKER_MAC, VICTIM_MAC, attacker, victim, 44500, 80, t)
    s.handshake()
    for path in ("/", "/admin/", "/cgi-bin/test.cgi", "/../../etc/passwd", "/phpinfo.php"):
        s.send(f"GET {path} HTTP/1.1\r\nHost: 10.14.0.10\r\n"
               f"User-Agent: Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)\r\n\r\n")
        s.recv("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found")
    s.close()
    p += s.pkts
    t = s.t + 3.0

    # (c) malicious binary download by the victim
    mz = b"MZ\x90\x00" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 128
    s = Stream(VICTIM_MAC, GW_MAC, victim, "45.9.148.37", 49700, 80, t)
    s.handshake()
    s.send("GET /win/update.exe HTTP/1.1\r\nHost: cdn-updates.xyz\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n")
    s.recv(http_response(mz, ctype="application/octet-stream"))
    s.close()
    p += s.pkts
    t = s.t + 5.0

    # (d) C2 beacons: 8, every 60s, near-identical
    beacon_t = t
    for i in range(8):
        b = Stream(VICTIM_MAC, GW_MAC, victim, c2, 50000 + i, 443, beacon_t)
        b.handshake()
        b.send(bytes.fromhex("170303002a") + b"BEACON-CHECKIN-" + f"{i:03d}".encode() + b"\x00" * 20)
        b.recv(bytes.fromhex("170303001e") + b"NOP" + b"\x00" * 24)
        b.close()
        p += b.pkts
        beacon_t += 60.0
    t = beacon_t + 5.0

    # (e) DNS tunneling: long base32-ish TXT lookups
    labels = [
        "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho",
        "nvqws3blorxxezjmzsw45dfoqqhk3tdn5sgs3thebqq",
        "orsxg5bnmrxxg5dbnzxw4z3fmqqhg33nfzxxo",
        "pfsxg5dbnzxw4z3fmftwk4tjmftg64tfeb2gk",
    ]
    labels = [l.encode("ascii", "ignore").decode() for l in labels]
    for i, lab in enumerate(labels):
        qn = f"{lab}.c2.evil-corp.xyz"
        q = Ether(src=VICTIM_MAC, dst=GW_MAC) / IP(src=victim, dst=DNS_SERVER) / \
            UDP(sport=53500 + i, dport=53) / DNS(id=0x7000 + i, rd=1,
                qd=DNSQR(qname=qn, qtype="TXT"))
        q.time = t; p.append(q); t += 0.03
        r = Ether(src=GW_MAC, dst=VICTIM_MAC) / IP(src=DNS_SERVER, dst=victim) / \
            UDP(sport=53, dport=53500 + i) / DNS(id=0x7000 + i, qr=1, rd=1, ra=1,
                qd=DNSQR(qname=qn, qtype="TXT"),
                an=DNSRR(rrname=qn, type="TXT", ttl=1, rdata="ok"))
        r.time = t; p.append(r); t += 1.5

    p.sort(key=lambda x: x.time)
    wrpcap(os.path.join(OUT, "traffic-analysis.pcap"), p)
    print(f"  traffic-analysis.pcap      {len(p):4d} pkts")


# ===========================================================================
# 5. networkminer.pcap -- rich parsing target: DNS, HTTP downloads (text +
#    image), FTP creds, HTTP Basic auth, distinct hostnames, OS-revealing UA.
# ===========================================================================
def build_networkminer():
    import base64
    p = []
    t = T0
    client = "10.14.0.55"          # a *different* host: 'Ellie-PC'
    cmac = "08:00:27:e1:11:e5"
    web = "203.0.113.42"

    # DHCP-ish hostname hint via NBNS would be ideal; keep it simple with DNS + UA.
    def dns(qname, ip, qid):
        nonlocal t
        q = Ether(src=cmac, dst=GW_MAC) / IP(src=client, dst=DNS_SERVER) / \
            UDP(sport=60000 + qid, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname))
        q.time = t; p.append(q); t += 0.04
        r = Ether(src=GW_MAC, dst=cmac) / IP(src=DNS_SERVER, dst=client) / \
            UDP(sport=53, dport=60000 + qid) / DNS(id=qid, qr=1, rd=1, ra=1,
                qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, type="A", ttl=600, rdata=ip))
        r.time = t; p.append(r); t += 0.3

    dns("intranet.acme-corp.com", web, 201)
    dns("files.acme-corp.com", web, 202)
    dns("telemetry.tracker-ads.net", "198.51.100.9", 203)

    # HTTP page with OS-revealing User-Agent
    s = Stream(cmac, GW_MAC, client, web, 55001, 80, t)
    s.handshake()
    s.send("GET / HTTP/1.1\r\nHost: intranet.acme-corp.com\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) "
           "Gecko/20100101 Firefox/115.0\r\n\r\n")
    s.recv(http_response("<html><title>ACME Intranet</title>"
                         "<body><a href='/report.pdf'>Q3 report</a>"
                         "<img src='http://files.acme-corp.com/banner.png'></body></html>\n"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # HTTP download: a "PDF" (just bytes) - NetworkMiner Files tab
    pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n" + b"ACME Q3 revenue: confidential\n" * 3 + b"%%EOF\n"
    s = Stream(cmac, GW_MAC, client, web, 55002, 80, t)
    s.handshake()
    s.send("GET /report.pdf HTTP/1.1\r\nHost: intranet.acme-corp.com\r\n\r\n")
    s.recv(http_response(pdf, ctype="application/pdf"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # HTTP download: a PNG image - NetworkMiner Images tab
    s = Stream(cmac, GW_MAC, client, web, 55003, 80, t)
    s.handshake()
    s.send("GET /banner.png HTTP/1.1\r\nHost: files.acme-corp.com\r\n\r\n")
    s.recv(http_response(png_1x1(), ctype="image/png"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # HTTP Basic auth  (ellie.myers : Autumn!Leaves#7)
    cr = base64.b64encode(b"ellie.myers:Autumn!Leaves#7").decode()
    s = Stream(cmac, GW_MAC, client, web, 55004, 80, t)
    s.handshake()
    s.send(f"GET /private/ HTTP/1.1\r\nHost: intranet.acme-corp.com\r\n"
           f"Authorization: Basic {cr}\r\n\r\n")
    s.recv(http_response("<html><body>private area</body></html>\n"))
    s.close()
    p += s.pkts
    t = s.t + 0.5

    # cleartext FTP creds  (ftpuser : Pr0d-FTP-2024)
    ftp = "203.0.113.77"
    fs = Stream(cmac, GW_MAC, client, ftp, 55010, 21, t)
    fs.handshake()
    fs.recv("220 ProFTPD Server ready.\r\n")
    fs.send("USER ftpuser\r\n"); fs.recv("331 Password required for ftpuser.\r\n")
    fs.send("PASS Pr0d-FTP-2024\r\n"); fs.recv("230 User ftpuser logged in.\r\n")
    fs.send("QUIT\r\n"); fs.recv("221 Goodbye.\r\n")
    fs.close()
    p += fs.pkts

    p.sort(key=lambda x: x.time)
    wrpcap(os.path.join(OUT, "networkminer.pcap"), p)
    print(f"  networkminer.pcap          {len(p):4d} pkts")


if __name__ == "__main__":
    print(f"[*] writing pcaps to {os.path.abspath(OUT)}")
    build_net_basics()
    build_wireshark_basics()
    build_packet_operations()
    build_traffic_analysis()
    build_networkminer()
    print("[+] done")
