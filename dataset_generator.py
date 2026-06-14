import csv
import random
import os

def create_synthetic_data(num_samples=10000):
    """
    Generate synthetic network traffic data simulating 5 attack categories
    aligned with the NSL-KDD dataset standard:
    - Normal: Regular web/network traffic
    - DoS: Denial of Service (SYN floods, volumetric attacks)
    - Probe: Reconnaissance / Port scanning
    - R2L: Remote to Local (unauthorized remote access attempts)
    - U2R: User to Root (privilege escalation attempts)
    """
    random.seed(42)  # For reproducibility

    headers = [
        "duration", "protocol_type", "service", "src_bytes", "dst_bytes",
        "flag", "count", "srv_count", "dst_host_count", "dst_host_srv_count",
        "label"
    ]
    data = [headers]

    protocols = ["tcp", "udp", "icmp"]
    services_normal = ["http", "https", "dns", "smtp", "ftp", "ssh", "pop3", "imap"]
    services_attack = ["http", "ftp", "ssh", "telnet", "smtp", "private", "other"]
    flags_normal = ["SF", "SF", "SF", "RSTR"]  # Weighted towards SF (normal established)
    flags_dos = ["S0", "S0", "S0", "REJ", "S1", "S2", "S3"]
    flags_probe = ["REJ", "RSTO", "S0", "RSTOS0", "SH"]
    flags_r2l = ["SF", "S0", "REJ", "RSTR"]
    flags_u2r = ["SF", "SF", "RSTR"]

    for _ in range(num_samples):
        attack_roll = random.random()

        if attack_roll < 0.50:
            # --- Normal Traffic (50%) ---
            label = "Normal"
            duration = random.randint(0, 300)
            protocol = random.choice(["tcp", "udp"])
            service = random.choice(services_normal)
            src_bytes = random.randint(100, 12000)
            dst_bytes = random.randint(500, 30000)
            flag = random.choice(flags_normal)
            count = random.randint(1, 30)
            srv_count = random.randint(1, 20)
            dst_host_count = random.randint(1, 255)
            dst_host_srv_count = random.randint(1, 255)

        elif attack_roll < 0.70:
            # --- DoS Attack (20%) ---
            label = "DoS"
            duration = 0
            protocol = random.choice(["tcp", "icmp"])
            service = random.choice(["http", "private", "other", "telnet"])
            src_bytes = random.choice([0, 0, 0, random.randint(0, 50)])  # Mostly zero (SYN flood)
            dst_bytes = 0
            flag = random.choice(flags_dos)
            count = random.randint(100, 511)  # High connection count = flood indicator
            srv_count = random.randint(50, 511)
            dst_host_count = random.randint(200, 255)
            dst_host_srv_count = random.randint(1, 30)

        elif attack_roll < 0.85:
            # --- Probe / Reconnaissance (15%) ---
            label = "Probe"
            duration = random.randint(0, 5)
            protocol = random.choice(["tcp", "icmp", "udp"])
            service = random.choice(["private", "other", "ftp", "http", "telnet"])
            src_bytes = random.randint(0, 30)
            dst_bytes = 0
            flag = random.choice(flags_probe)
            count = random.randint(1, 50)
            srv_count = random.randint(1, 10)
            dst_host_count = random.randint(1, 255)
            dst_host_srv_count = random.randint(1, 50)

        elif attack_roll < 0.95:
            # --- R2L: Remote to Local (10%) ---
            label = "R2L"
            duration = random.randint(1, 500)  # Longer sessions (brute-force, login attempts)
            protocol = "tcp"
            service = random.choice(["ftp", "ssh", "telnet", "pop3", "imap", "smtp"])
            src_bytes = random.randint(200, 5000)  # Sending payloads
            dst_bytes = random.randint(0, 3000)
            flag = random.choice(flags_r2l)
            count = random.randint(1, 20)
            srv_count = random.randint(1, 15)
            dst_host_count = random.randint(1, 50)
            dst_host_srv_count = random.randint(1, 30)

        else:
            # --- U2R: User to Root (5%) ---
            label = "U2R"
            duration = random.randint(5, 1000)  # Long interactive sessions
            protocol = "tcp"
            service = random.choice(["ssh", "telnet", "ftp", "other"])
            src_bytes = random.randint(500, 20000)  # Large payload (exploit delivery)
            dst_bytes = random.randint(100, 8000)
            flag = random.choice(flags_u2r)
            count = random.randint(1, 10)
            srv_count = random.randint(1, 5)
            dst_host_count = random.randint(1, 20)
            dst_host_srv_count = random.randint(1, 10)

        data.append([
            duration, protocol, service, src_bytes, dst_bytes,
            flag, count, srv_count, dst_host_count, dst_host_srv_count,
            label
        ])

    # Save to CSV using standard Python lib (no pandas dependency needed)
    output_file = "network_logs.csv"
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)

    # Print distribution summary
    from collections import Counter
    labels = [row[-1] for row in data[1:]]
    dist = Counter(labels)
    print(f"[+] Generated {num_samples} simulated network logs -> {os.path.abspath(output_file)}")
    print(f"[+] Distribution:")
    for label, cnt in sorted(dist.items()):
        pct = (cnt / num_samples) * 100
        print(f"    {label:8s}: {cnt:5d} ({pct:.1f}%)")

if __name__ == "__main__":
    create_synthetic_data()
