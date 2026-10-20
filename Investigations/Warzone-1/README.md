# Warzone 1 — Malware Delivery and HTTP C2 Triage

**Environment:** Authorized TryHackMe network-analysis lab  
**Tools:** Wireshark, Brim/Zeek, NetworkMiner, CyberChef  
**Skills:** Alert validation, HTTP object analysis, base64 decoding, endpoint attribution, IOC extraction

## Summary
I investigated suspicious PCAP traffic, correlated an IDS alert with HTTP activity, reconstructed a likely malware-download sequence, and decoded an HTTP beacon parameter to identify victim context. The goal was to develop an evidence-backed account rather than copy challenge answers.

## Investigation

### Identify the affected system and alert
The internal host `172.16.1.102` communicated with `169.239.128.11:80`, associated in the lab with `fidufagios.com`. Brim exposed an **ET MALWARE MirrorBlast CnC Activity** alert (signature ID `2034023`, reported severity 1). I pivoted from the alert to the corresponding HTTP transactions.

### Decode the beacon
Suspicious requests used Base64-encoded URI parameters. CyberChef decoding exposed:

```text
name=STOCKITFORUS\dwight.morales&os=10.0&arch=x86&build=1.0.2
```

The observed User-Agent included `REBOL View 2.7.8.3.1`. These fields supplied useful host/user and tooling context, but alone do not prove a specific malware family.

### Reconstruct delivery activity
Traffic showed an earlier `feedproxy.google.com` redirect and subsequent requests for Windows Installer payloads. Notable downloaded files were:

| File | Download endpoint | Size observed |
| --- | --- | --- |
| `filter.msi` | `185.10.68.235` | 188,416 bytes |
| `10opd3r_load.msi` | `192.36.27.92` | 561,152 bytes |

The installer-related telemetry exposed paths including `C:\ProgramData\001\arab.bin`, `C:\ProgramData\001\arab.exe`, `C:\ProgramData\Local\Google\rebol-view-278_3_1.exe`, and `C:\ProgramData\Local\Google\exemple.rb`. These are **observed artifact/path references**, not proof that each file executed.

## Selected IOCs

| Type | Indicator | Role in lab |
| --- | --- | --- |
| Victim IP | `172.16.1.102` | Internal endpoint |
| IP/port | `169.239.128.11:80` | C2-associated HTTP |
| Domain | `fidufagios.com` | HTTP host |
| File | `filter.msi` | Downloaded installer |
| File | `10opd3r_load.msi` | Downloaded installer |
| User-Agent | `REBOL View 2.7.8.3.1` | Suspicious client metadata |

## Methodology and lessons
1. Start with IDS alert context, then pivot to matching conversations.
2. Use Wireshark/Brim to inspect HTTP metadata and reconstruct request order.
3. Decode suspicious parameters only after capturing the raw values.
4. Distinguish an installer’s embedded strings from confirmed installed/executed artifacts.
5. For a production case, preserve installers and analyze them safely offline; relying only on `tcp contains` string searches is incomplete.

## Response recommendations
Isolate the affected endpoint, preserve PCAP and endpoint logs, block verified malicious destinations, examine MSI execution/installation traces, hunt for related process names, and validate persistence and lateral movement.

**Scope:** Controlled training environment. No executable malware or raw credentials are included.
