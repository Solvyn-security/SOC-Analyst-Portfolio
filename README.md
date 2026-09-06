# SOC Analyst Portfolio

Hands-on security investigations focused on network traffic analysis, SIEM, endpoint telemetry, threat detection, and incident response.

This portfolio documents selected investigations from controlled training labs and home-lab environments. The goal is to demonstrate **how I investigate**, not simply list completed exercises or disclose challenge answers.

## Core Skills

- Network traffic analysis with Wireshark
- DNS, HTTP/HTTPS, TLS, and SMTP investigation
- IOC identification and threat-intelligence validation
- Command-and-control and post-compromise traffic analysis
- Splunk / SPL investigation
- Windows and endpoint log analysis
- Incident timeline reconstruction
- Detection and response recommendations

## Featured Investigations

| Investigation | Focus | Tools |
| --- | --- | --- |
| [Carnage — Malicious Document & Cobalt Strike](Investigations/Carnage-Cobalt-Strike/) | PCAP analysis, payload delivery, TLS/SNI, C2, DNS, HTTP, SMTP | Wireshark, VirusTotal |

## Portfolio Structure

```text
SOC-Analyst-Portfolio/
├── README.md
├── Investigations/
│   └── Carnage-Cobalt-Strike/
│       ├── README.md
│       └── screenshots/
├── SIEM-Labs/
├── Detection-Labs/
└── Endpoint-Labs/
```

## About the Work

Each featured case study is written as a SOC investigation rather than a question-and-answer walkthrough. Reports emphasize:

1. Alert or incident context
2. Investigation methodology
3. Evidence and analyst pivots
4. Timeline reconstruction
5. Indicators of compromise
6. Assessment
7. Recommended response

Only selected labs that demonstrate meaningful analyst skills are included.

> **Note:** All investigations in this repository are performed in authorized training or home-lab environments. Any IP addresses, domains, files, or other indicators shown are included for educational documentation of historical lab traffic.
