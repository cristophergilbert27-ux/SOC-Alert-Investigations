# SOC Alert Investigations

Investigation reports from SOC simulation platforms, written as case reports rather than walkthroughs. Each entry covers one incident from the alert that triggered it through to the verdict and the response actions taken.

The focus here is the reasoning: what was checked, what each piece of evidence ruled in or out, and why the alert was finally classified the way it was.

**Platform answers and flags are redacted throughout.** These reports document analysis methodology, not exercise solutions.

---

## Incidents

<!-- INCIDENTS:START -->

| # | Incident | Platform | Severity | Category | Date | Report |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Phishing email leads to user executed PowerShell and an outbound payload request | LetsDefend | Critical | Phishing | 03/13/25 | [Read](soc338-lumma-stealer-dll-sideloading/report.md) |

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
