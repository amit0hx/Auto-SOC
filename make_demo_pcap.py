"""Craft a synthetic pcap (normal + SYN flood + port scan) to test live_ids.py.
   Writing packets to a file needs NO Npcap/admin."""
from scapy.all import IP, TCP, wrpcap

pkts = []
t = 1000.0

# --- Normal HTTP: full handshake + data + close, a few clients ---
for i in range(5):
    c = f"192.168.1.{10+i}"
    s = "93.184.216.34"  # example.com
    syn  = IP(src=c, dst=s)/TCP(sport=40000+i, dport=80, flags="S")
    sa   = IP(src=s, dst=c)/TCP(sport=80, dport=40000+i, flags="SA")
    data = IP(src=c, dst=s)/TCP(sport=40000+i, dport=80, flags="PA")/("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    resp = IP(src=s, dst=c)/TCP(sport=80, dport=40000+i, flags="PA")/("HTTP/1.1 200 OK\r\n\r\n" + "x"*800)
    fin  = IP(src=c, dst=s)/TCP(sport=40000+i, dport=80, flags="FA")
    for p in (syn, sa, data, resp, fin):
        p.time = t; t += 0.05
        pkts.append(p)

# --- DoS: SYN flood, 160 half-open SYNs to one host:80 within ~1.5s, no reply ---
flood_t = 2000.0
for i in range(160):
    p = IP(src="10.0.0.66", dst="192.168.1.50")/TCP(sport=1024+i, dport=80, flags="S")
    p.time = flood_t + i*0.009
    pkts.append(p)

# --- Probe: port scan, one host hitting many ports, RST/no-reply ---
scan_t = 3000.0
for i, port in enumerate([21,22,23,25,53,80,110,135,139,143,443,445,3389,8080]):
    syn = IP(src="172.16.0.5", dst="192.168.1.70")/TCP(sport=55000+i, dport=port, flags="S")
    rej = IP(src="192.168.1.70", dst="172.16.0.5")/TCP(sport=port, dport=55000+i, flags="RA")
    syn.time = scan_t + i*0.03; rej.time = scan_t + i*0.03 + 0.005
    pkts.extend([syn, rej])

wrpcap("demo_capture.pcap", pkts)
print(f"[+] wrote demo_capture.pcap with {len(pkts)} packets")
