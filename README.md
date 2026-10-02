# SOC Alert Investigations

Investigation reports from SOC simulation platforms, written as case reports rather than walkthroughs. Each entry covers one incident from the alert that triggered it through to the verdict and the response actions taken.

The focus here is the reasoning: what was checked, what each piece of evidence ruled in or out, and why the alert was finally classified the way it was.

**Platform answers and flags are redacted throughout.** These reports document analysis methodology, not exercise solutions.

---

## Incidents

<!-- INCIDENTS:START -->

_No incident reports yet._

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

## Adding a Report

1. Create a new folder named with a short lowercase slug for the incident, holding a `report.md` and a `screenshots/` directory. Copying the most recent incident folder and clearing it out is the quickest way.
2. Fill in the metadata header at the top of `report.md` — `Incident`, `Platform`, `Severity`, `Category`, and `Date` are what the README table is built from.
3. Drop the images into `screenshots/`, with any flags or answers blacked out before committing.
4. Run the generator and commit:

```bash
python generate_readme.py
git add .
git commit -m "Add <incident name> investigation"
git push
```

The script rewrites the table between the marker comments above, sorted by severity. It skips `TEMPLATE/` and any folder without a `report.md`.

---

## Author

**Christopher Gilbert** — GitHub [@cristophergilbert27-ux](https://github.com/cristophergilbert27-ux)

Related: [CTF-Writeup](https://github.com/cristophergilbert27-ux/CTF-Writeup) — TryHackMe room write-ups.
