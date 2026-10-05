# SOC Alert Investigations

Investigation reports from SOC simulation platforms, written as case reports rather than walkthroughs. Each entry covers one incident from the alert that triggered it through to the verdict and the response actions taken.

The focus here is the reasoning: what was checked, what each piece of evidence ruled in or out, and why the alert was finally classified the way it was.

**Platform answers and flags are redacted throughout.** These reports document analysis methodology, not exercise solutions.

---

## Incidents

<!-- INCIDENTS:START -->

| # | Incident | Platform | Severity | Category | Date | Report |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Click Fix phishing results in PowerShell execution and an outbound payload request | LetsDefend | Critical | Phishing | 03/13/25 | [Read](soc338-lumma-stealer-dll-sideloading/report.md) |
| 2 | Log4Shell Exploitation of a Minecraft Server on the Internal Network | LetsDefend | Critical | Web Attack (Exploitation of a Public Facing Application) | 11/12/21 | [Read](soc161-log4j-rce-exploit/report.md) |
| 3 | Pass the Hash Attack Detected on an Internet Facing Windows Server | LetsDefend | Critical | Malware / Credential Access | 18/04/23 | [Read](soc188-pass-the-hash-attack-detected/report.md) |
| 4 | Akira ransomware executed on an internal server after an invoice themed phishing email | LetsDefend | High | Malware (Ransomware) | 02/10/24 | [Read](soc328-akira-ransomware-ioc's-detected/report.md) |
| 5 | Base64 decoding of a credential file after a successful SSH brute force | LetsDefend | High | Unauthorized Access | 17/07/24 | [Read](soc302-suspicious-base64-encoding-decoding-commands-detected(high)/report.md) |
| 6 | Data Exfiltration to an External FTP Server After an RDP Brute Force | LetsDefend | High | Data Exfiltration | 25/06/24 | [Read](soc295-potential-data-exfiltration-detected-via-ftp/report.md) |
| 7 | Lazarus (APT38) ClickFix phishing results in payload download and VBScript execution on the endpoint | LetsDefend | High | Phishing | 06/03/25 | [Read](soc337-lazarus-phishing-campaign-detected(APT38)/report.md) |
| 8 | Phishing Attachment Leads to System Discovery and Exfiltration Over Pastebin | LetsDefend | High | Data Exfiltration | 26/06/24 | [Read](soc293-exfiltration-over-pastebin-detected/report.md) |
| 9 | DLL Side Loading via ISO Attachment | LetsDefend | Medium | Malware | 09/09/24 | [Read](soc319-suspicious-dll-execution-detected/report.md) |
| 10 | Executable Disguised as a Text File Using a Unicode Override Character | LetsDefend | Medium | Malware | 11/07/24 | [Read](soc300-right-to-left-override-detected/report.md) |
| 11 | SSH Account Compromise Leading to Encoded Exfiltration of System Account Data | LetsDefend | Medium | Brute Force / Data Exfiltration | 07/08/24 | [Read](soc302-suspicious-base64-encoding-decoding-commands-detected(medium)/report.md) |

<!-- INCIDENTS:END -->

---

## Repository Layout

```
.
├── README.md
├── generate_readme.py
└── <incident-slug>/
    ├── report.md
    └── screenshots/
```

One folder per incident, named with a short lowercase slug. Every folder holds a `report.md` and its own `screenshots/` directory. Alerts belonging to the same incident are covered in a single report rather than split across folders.

---

## Author

**Christopher Gilbert** — GitHub [@cristophergilbert27-ux](https://github.com/cristophergilbert27-ux)

Related: [CTF-Writeup](https://github.com/cristophergilbert27-ux/CTF-Writeup) — TryHackMe room write-ups.
