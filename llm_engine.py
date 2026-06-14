import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

# We will try to load Gemini. If no API key, we return a mock playbook.
API_KEY = os.getenv("GEMINI_API_KEY")

if API_KEY:
    genai.configure(api_key=API_KEY)


# Severity mapping based on attack classification
SEVERITY_MAP = {
    "DoS":    {"level": "CRITICAL", "color": "🔴", "cvss_range": "7.5 - 9.0"},
    "R2L":    {"level": "HIGH",     "color": "🟠", "cvss_range": "6.0 - 8.5"},
    "U2R":    {"level": "CRITICAL", "color": "🔴", "cvss_range": "8.0 - 10.0"},
    "Probe":  {"level": "MEDIUM",   "color": "🟡", "cvss_range": "4.0 - 6.5"},
    "Normal": {"level": "INFO",     "color": "🟢", "cvss_range": "N/A"},
}


def get_severity(threat_class):
    """Return severity metadata for a given threat classification."""
    return SEVERITY_MAP.get(threat_class, SEVERITY_MAP["Normal"])


def generate_ir_playbook(log_data, threat_class):
    """
    Given a network log and the detected threat class, generate an Incident Response playbook.
    Uses Gemini API if available, otherwise returns attack-type-specific mock playbooks.
    """
    if "Normal" in threat_class:
        return "No action required. Traffic is normal."

    severity = get_severity(threat_class)

    prompt = f"""You are an expert Cybersecurity Incident Responder and Blue Team SOC Analyst.

Our ML-based Intrusion Detection System flagged the following network connection as a '{threat_class}' attack.

Severity: {severity['level']} (Estimated CVSS: {severity['cvss_range']})

Intercepted Log Data:
{log_data}

Write a precise, highly technical 4-point mitigation playbook for the System Administrator. Structure it as:
1. **Immediate Containment**: First 5-minute actions (firewall rules, IP blocking, service isolation)
2. **Investigation**: What to check in logs, PCAP analysis, correlation steps
3. **Remediation**: Patching, config hardening, rule updates
4. **Post-Incident**: Documentation, IOC extraction, SIEM rule creation

Reference MITRE ATT&CK techniques where applicable. Keep the total response under 150 words. Be specific to the attack type."""

    if API_KEY:
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            # Key invalid / quota / network down -> degrade gracefully to the
            # built-in offline playbook instead of surfacing a raw API error.
            # (Matches RUN_GUIDE: "Gemini API error -> offline playbooks are used".)
            note = f"> ⚠️ Gemini API unavailable ({str(e).splitlines()[0][:80]}). Using offline playbook.\n\n"
            return note + _mock_playbook(log_data, threat_class, severity)
    else:
        return _mock_playbook(log_data, threat_class, severity)


def _mock_playbook(log_data, threat_class, severity):
    """Generate attack-type-specific mock playbooks for offline/demo mode."""

    playbooks = {
        "DoS": f"""**{severity['color']} [{severity['level']}] DoS Attack — Incident Response Playbook**

1. **Immediate Containment:** Deploy rate-limiting on edge routers. Execute: `iptables -A INPUT -s <SRC_IP> -j DROP`. Enable SYN cookies: `sysctl -w net.ipv4.tcp_syncookies=1`. Activate DDoS scrubbing if CDN available.
2. **Investigation:** Analyze TCP flags — S0/REJ floods indicate SYN flood (MITRE T1498). Check `netstat -an | grep SYN_RECV` for half-open connections. Export PCAP via `tcpdump -w dos_capture.pcap`.
3. **Remediation:** Tune firewall connection limits. Configure `hashlimit` module for per-IP rate control. Update WAF rules to drop malformed TCP packets.
4. **Post-Incident:** Document source IP ranges. Create SIEM correlation rule for >100 SYN packets/sec from single source. Submit IOCs to threat intel feed.""",

        "Probe": f"""**{severity['color']} [{severity['level']}] Probe/Reconnaissance — Incident Response Playbook**

1. **Immediate Containment:** Block scanner IP: `iptables -A INPUT -s <SRC_IP> -j DROP`. Enable IDS alert mode for the target subnet. Check if any ports responded to the scan.
2. **Investigation:** Analyze scan pattern — sequential ports = nmap SYN scan (MITRE T1046). Check `/var/log/auth.log` for follow-up login attempts. Correlate with DNS logs for reverse lookups.
3. **Remediation:** Disable unnecessary services on scanned hosts. Implement port knocking for sensitive services. Deploy honeypots on commonly probed ports (22, 23, 3389).
4. **Post-Incident:** Map scanned port range. Update SIEM with scanner IP. Review network segmentation — ensure recon cannot reach critical assets.""",

        "R2L": f"""**{severity['color']} [{severity['level']}] R2L (Remote to Local) — Incident Response Playbook**

1. **Immediate Containment:** Force-terminate suspicious sessions: `ss -K dst <SRC_IP>`. Lock targeted accounts. Rotate credentials for compromised services (SSH/FTP/Telnet).
2. **Investigation:** Check auth logs: `grep 'Failed password' /var/log/auth.log | tail -50`. Look for brute-force patterns (MITRE T1110). Analyze payload bytes for exploit signatures.
3. **Remediation:** Enforce MFA on all remote access services. Implement fail2ban: `fail2ban-client set sshd banip <SRC_IP>`. Disable legacy protocols (Telnet, FTP) — migrate to SFTP/SSH.
4. **Post-Incident:** Audit all accounts accessed during the window. Check for persistence mechanisms (crontab, authorized_keys). Submit credentials to breach databases for verification.""",

        "U2R": f"""**{severity['color']} [{severity['level']}] U2R (Privilege Escalation) — Incident Response Playbook**

1. **Immediate Containment:** CRITICAL — Isolate the host from network immediately. Kill suspicious processes: `kill -9 <PID>`. Snapshot the filesystem for forensics before any changes.
2. **Investigation:** Check for SUID/SGID abuse: `find / -perm -4000 2>/dev/null`. Review `sudo` logs and `/var/log/kern.log` for kernel exploit traces (MITRE T1068). Analyze large src_bytes — possible exploit payload delivery.
3. **Remediation:** Patch kernel and all SUID binaries. Restrict sudo access: audit `/etc/sudoers`. Enable SELinux/AppArmor in enforce mode. Disable ptrace: `sysctl kernel.yama.ptrace_scope=3`.
4. **Post-Incident:** Full forensic image of compromised host. Check for rootkits: `chkrootkit` / `rkhunter`. Rebuild host from known-good image if root compromise confirmed.""",
    }

    return playbooks.get(threat_class, f"**[UNKNOWN ATTACK TYPE: {threat_class}]** — Manual investigation required. Block source IP and escalate to senior SOC analyst.")
