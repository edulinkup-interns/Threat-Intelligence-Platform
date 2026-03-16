A full stack security vulnerability dashboard that ingests Nessus scan files, enriches findings with live CVE data from the National Vulnerability Database, calculates composite risk scores for every asset, and generates professional PDF reports.

**Live Demo:** https://compliance-xi.vercel.app

> **Note:** The deployed version uses PostgreSQL on Railway and Vercel's free tier. Cold starts may take 30–60 seconds on first load. Scan uploads and NVD enrichment may also take longer than local due to free tier resource limits. Please be patient — it is working.

## What it does
- Upload a Nessus CSV scan file and parse all assets, vulnerabilities, and findings automatically
- Calculate a composite risk score for every asset using CVSS scores, severity weights, and a configurable criticality factor
- Enrich every CVE in the background using the NVD API — pulls CVSS scores, CWE classifications, patch availability, and official descriptions
- View assets ranked by exposure with per-finding CVE breakdowns in a slide-out drawer
- Adjust asset criticality scores in real time and watch rankings update instantly
- Export a full multi-page PDF report with cover page, executive summary, severity charts, ranked asset table, detailed findings, and auto-generated recommendations

## Tech Stack
**Backend**
- FastAPI
- SQLAlchemy
- SQLite (local) / PostgreSQL (production)
- ReportLab (PDF generation)
- NVD API 2.0 (CVE enrichment)

**Frontend**
- React + Vite
- Plain CSS variables (no Tailwind, no component library)
- Chart.js (severity donut chart)
- Syne + JetBrains Mono fonts

**Deployment**
- Backend → Railway
- Frontend → Vercel
- Database → Railway PostgreSQL
  
## Risk Scoring Formula

```
finding_score  = cvss_score × severity_weight
asset_score    = sum(finding_scores) × criticality_factor
```

Severity weights:
- Critical → 2.0
- High → 1.5
- Medium → 1.0
- Low → 0.5

Criticality factor is configurable per asset (0.1 – 5.0, default 1.0).
