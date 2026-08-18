# Master Walkthrough Document: Cloud Access Anomaly Detection & UEBA SIEM Platform

## 1. Executive Summary & System Overview
This project delivers a comprehensive, local-first **Cloud Access Anomaly Detection and User Behavior Analytics (UEBA) SIEM Platform**. It addresses high-volume cloud access logs, alert fatigue, and identity drift across AWS CloudTrail, Azure/Entra ID, GCP Audit, and Okta environments.

---

## 2. Complete Scope & Architecture Highlights

```mermaid
flowchart LR
    subgraph Multi-Cloud Ingestion
        A1[AWS CloudTrail] --> B[OCSF / ECS Normalizer]
        A2[Azure SigninLogs] --> B
        A3[GCP Audit Logs] --> B
        A4[Uploaded .json / .csv] --> B
    end

    subgraph Rulebook & Topology Engine
        B --> C[18-Rule Detection Engine: rulebook_config.json]
        C --> D[30m Sliding Window Sessionizer]
        D --> E[90-Day Behavioral Baseline]
        E --> F[SQLite Topology DB: caad_topology.db]
        F --> G[5-Hop Recursive CTE Blast Radius Calculation]
        G --> H[GenAI Incident Synthesizer]
    end

    subgraph Interactive Interface & SOC Deliverables
        H --> I[4-Platform SIEM Download Center]
        H --> J[Interactive Visual Blast Radius Canvas Node Graph]
        H --> K[Explainable AI Log Summarizer]
        H --> L[Model Detection Accuracy & Satisfaction Count Engine]
        H --> M[Dark & Light Mode Theme Switcher]
    </div>
```

---

## 3. Core Deliverables & File Directory

### A. Configurable Detection Rulebook (`rulebook_config.json`)
- **[`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json)**: Expanded **18-rule detection catalog** comprising:
  - **5 False Positive Operational Rules** (`FP-RULE-001` through `005` covering non-malicious baselines, CI/CD deployment bots, vulnerability scanners, maintenance patching windows, and synthetic health monitors).
  - **13 Threat Anomaly Rules** (`THREAT-RULE-001` through `013` covering Impossible Travel, MFA Push Spamming, Dormant Admin Activation, Mass Exfiltration, CloudTrail Log Erasure, Password Spraying, KMS Encryption Key Access, Cross-Account Assumption, S3 Public Access Removal, Azure Vault Secret Exports, Root Access without Hardware MFA, TOR Exit Node Sign-Ins, and Off-Hours API Access).

---

### B. Pre-Evaluated Telemetry Sample Events (15 Events)
Pre-populated with **15 multi-cloud sample events** across AWS, Azure, GCP, and Okta pre-evaluated against the 18 detection rules in `rulebook_config.json`:
1. `OCSF-UEBA-2026-001`: Impossible Travel Velocity (`CRITICAL`, AWS)
2. `OCSF-UEBA-2026-002`: MFA Fatigue Push Prompt Spamming (`HIGH`, Azure)
3. `OCSF-UEBA-2026-003`: Dormant Admin Account Reactivation (`CRITICAL`, AWS)
4. `OCSF-UEBA-2026-004`: Mass Cloud Storage Exfiltration (`HIGH`, GCP)
5. `OCSF-UEBA-2026-005`: Audit Trail Log Tampering & Deletion (`CRITICAL`, AWS)
6. `OCSF-UEBA-2026-006`: Cloud Password Spraying Attack Burst (`HIGH`, Azure)
7. `OCSF-UEBA-2026-007`: Unassigned KMS Master Encryption Key Access (`CRITICAL`, AWS)
8. `OCSF-UEBA-2026-008`: Cross-Account IAM Role Assumption Drift (`HIGH`, AWS)
9. `OCSF-UEBA-2026-009`: S3 Bucket Public Access Block Removal (`CRITICAL`, AWS)
10. `OCSF-UEBA-2026-010`: Azure Key Vault Bulk Secret Export Burst (`HIGH`, Azure)
11. `OCSF-UEBA-2026-011`: Root Account Authentication without Hardware MFA (`CRITICAL`, AWS)
12. `OCSF-UEBA-2026-012`: Anonymized Proxy & TOR Exit Node Access (`HIGH`, Okta)
13. `OCSF-UEBA-2026-013`: Authorized Vulnerability Scanner (`FALSE POSITIVE`, AWS)
14. `OCSF-UEBA-2026-014`: Scheduled CI/CD Deployment Bot (`FALSE POSITIVE`, AWS)
15. `OCSF-UEBA-2026-015`: Automated Synthetic Health Check Monitor (`FALSE POSITIVE`, GCP)

---

### C. Enterprise Topology SQLite Database (`caad_topology.db`)
- **[`caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db)**: SQLite database pre-seeded with **1,050 connected enterprise entities** (AWS EC2, Azure VMs, GCP Compute, S3 buckets, Key Vaults, databases, IAM users & roles), **2,593 relationship edges**, and **789 IAM permissions**.
- **[`scratch/build_topology_db.py`](file:///c:/antiProjects/CAAD/scratch/build_topology_db.py)**: Python generator script.
- **[`scratch/query_blast_radius.py`](file:///c:/antiProjects/CAAD/scratch/query_blast_radius.py)**: Python script executing 5-hop recursive CTE graph queries.

---

### D. Interactive Web Dashboard Components
- **[`index.html`](file:///c:/antiProjects/CAAD/index.html)**:
  - Header bar with Theme Switcher (`☀️ Light Mode` / `🌙 Dark Mode`) and AI Configuration modal trigger.
  - Metrics banner with **Model Detection Accuracy (%)** and **Satisfaction Count** KPI card.
  - 8 interactive tabs: `🚨 Anomaly Triage`, `📊 Behavioral Baseline Profiler`, `🕸️ 1,000+ System Topology`, `💾 SQLite DB Analysis`, `📥 SIEM Download Center`, `📤 SIEM Upload & Ingestion`, `⚡ Attack Simulator`, `📚 Data Sources Catalog`.
  - Triage Table with **Detection Accuracy & Feedback** column (`👍 Confirmed` / `👎 False Positive`) and severity dropdown supporting **`FALSE POSITIVE`**.
  - Inspect Modal with tabs for **`🤖 AI English Summary`**, **`🛡️ MITRE ATT&CK Path & Defense`**, and **`📄 Raw User Logs (JSON)`**.
- **[`styles.css`](file:///c:/antiProjects/CAAD/styles.css)**:
  - Dual-theme CSS custom variables (`:root` dark SOC slate & `[data-theme="light"]` clean light theme).
  - Badge styles including `.badge-false-positive`.
  - Print/PDF report stylesheet for executive reporting.
- **[`app.js`](file:///c:/antiProjects/CAAD/app.js)**:
  - Universal SIEM file parser for `.json` and `.csv` drag-and-drop uploads.
  - Rulebook False Positive auto-classification engine (`normalizeSiemRecord`).
  - Analyst feedback tracking (`👍 Confirmed` / `👎 False Positive`) and real-time **Model Detection Accuracy** and **Satisfaction Count** calculator.
  - SQLite DB Telemetry Analysis Screen (`renderDbAnalysisScreen`).
  - HTML5 Canvas **Blast Radius Visual Node Graph Engine** with radial layout, color-coded node taxonomy, and hover tooltips.
  - GenAI Incident Summarizer & Easy English MITRE ATT&CK/D3FEND Countermeasures generator.

---

## 4. GitHub Repository Integration

- **Target Repository**: [https://github.com/ramknathchn/SIEM-Analysis](https://github.com/ramknathchn/SIEM-Analysis)
- **Branch**: `main`
- **Latest Commit**: Expanded 18-rule detection catalog, 15 pre-evaluated sample events, SQLite DB analysis screen, and theme switching.
