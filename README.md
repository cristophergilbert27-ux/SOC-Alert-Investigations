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
| 2 | Akira ransomware executed on an internal server after an invoice themed phishing email | LetsDefend | High | Malware (Ransomware) | 02/10/24 | [Read](soc328-akira-ransomware-ioc's-detected/report.md) |
| 3 | Base64 decoding of a credential file after a successful SSH brute force | LetsDefend | High | Unauthorized Access | 17/07/24 | [Read](soc302-suspicious-base64-encoding-decoding-commands-detected(high)/report.md) |
| 4 | Lazarus (APT38) ClickFix phishing results in payload download and VBScript execution on the endpoint | LetsDefend | High | Phishing | 06/03/25 | [Read](soc337-lazarus-phishing-campaign-detected(APT38)/report.md) |
| 5 | DLL Side Loading via ISO Attachment | LetsDefend | Medium | Malware | 09/09/24 | [Read](soc319-suspicious-dll-execution-detected/report.md) |
| 6 | SSH Account Compromise Leading to Encoded Exfiltration of System Account Data | LetsDefend | Medium | Brute Force / Data Exfiltration | 07/08/24 | [Read](soc302-suspicious-base64-encoding-decoding-commands-detected(medium)/report.md) |

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
