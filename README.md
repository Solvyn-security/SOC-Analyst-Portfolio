# SOC Analyst Portfolio

**Hands-on SOC investigations | Network traffic analysis | Splunk | Windows forensics | Incident response**

This portfolio documents my analysis of authorized training and home-lab security incidents. Each report emphasizes **investigative reasoning, evidence correlation, findings, uncertainty, and defensive recommendations** rather than challenge-question walkthroughs.

## Featured Investigations

| Investigation | Main focus | Tools |
| --- | --- | --- |
| **[Zero Tolerance — Windows Intrusion & Lateral Movement](Investigations/Zero-Tolerance/)** | Malicious shortcut, Mshta, C2, Run-key persistence, credential dumping, PsExec/RDP, backup data staging | Splunk, Sysmon, Windows logs, KAPE |
| **[The Crown Jewel — MITM & DNS Exfiltration](Investigations/The-Crown-Jewel/)** | Reverse-shell alert, ARP spoofing, plaintext credential exposure, Jira activity, anomalous DNS | Splunk, Wireshark |
| **[Carnage — Malicious Document & Cobalt Strike](Investigations/Carnage-Cobalt-Strike/)** | Network infection chain, HTTP delivery, TLS/SNI, DNS, C2 and SMTP | Wireshark, VirusTotal |
| **[Warzone 1 — Malware Delivery & HTTP C2](Investigations/Warzone-1/)** | IDS pivoting, Base64 beacon decoding, MSI payload tracing | Wireshark, Brim, NetworkMiner, CyberChef |
| **[Warzone 2 — IDS Alert Triage](Investigations/Warzone-2/)** | Alert classification and triage methodology; concise case with evidence limitations | Network-monitoring lab |

## Skills demonstrated

- **Network investigations:** Wireshark filters, TCP/HTTP stream inspection, DNS, TLS SNI, ARP anomalies, SMTP and protocol-based IOCs.
- **SIEM and endpoint investigation:** Splunk SPL, Sysmon process creation and network events, Windows Security logon types, parent-child correlation, registry changes.
- **Digital forensics:** KAPE triage collection review, Windows filesystem artifacts, PowerShell script inspection and reconstruction of data staging.
- **Threat assessment:** C2 identification, payload delivery, persistence, credential access, lateral movement, exfiltration hypotheses, and MITRE ATT&CK mapping.
- **Incident documentation:** Executive summaries, evidence-backed timelines, confidence and limitations, selected IOCs, detection and remediation recommendations.

## How I investigate

1. **Validate the alert:** determine what the sensor detected and which observations are directly supported.
2. **Establish scope:** identify involved hosts, users, processes, and time windows.
3. **Pivot and correlate:** move between network captures, SIEM logs, endpoint artifacts, and process ancestry.
4. **Reconstruct behavior:** build a defensible chronological account; separate observed events from hypotheses.
5. **Recommend response:** prioritise containment, evidence preservation, hunting, credential protection, and root-cause remediation.

## Repository layout

```text
SOC-Analyst-Portfolio/
├── README.md
└── Investigations/
    ├── Carnage-Cobalt-Strike/
    │   ├── README.md
    │   └── screenshots/
    ├── The-Crown-Jewel/
    │   ├── README.md
│   └── screenshots/
    ├── Warzone-1/
    │   ├── README.md
│   └── screenshots/
    ├── Warzone-2/
    │   ├── README.md
│   └── screenshots/
    └── Zero-Tolerance/
        ├── README.md
        └── screenshots/
```

## Evidence and publication notes

These are **controlled educational lab** investigations, not claims of employment-based incident response. Lab-only IOCs should not be treated as universally malicious outside their historical context. The reports avoid publishing live malicious payloads, passwords, or private forensic evidence.

Carnage includes nine original investigation screenshots. Zero Tolerance includes ten evidence figures, The Crown Jewel six, and Warzone 1 six, recovered from the original investigation discussion. Warzone 2 retains one scenario-context image, explicitly distinguished from investigative evidence. Captions state what each image supports; the plaintext-password screenshot is omitted. Incomplete evidence is identified explicitly rather than filled in with assumptions.

**Portfolio identity:** Solvyn

