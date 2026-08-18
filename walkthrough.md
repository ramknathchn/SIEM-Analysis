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

    subgraph Analytics & Topology Engine
        B --> C[30m Sliding Window Sessionizer]
        C --> D[90-Day Behavioral Baseline]
        C --> E[Real-Time Feature Delta]
        D & E --> F[SQLite Topology DB: caad_topology.db]
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

### A. Data Engineering & Benchmarks Catalog
- **[`data_sources_guide.md`](file:///c:/antiProjects/CAAD/data_sources_guide.md)**: Detailed documentation of public benchmarks (flaws.cloud, Splunk BOTS v1–v3, CMU CERT r4.2/r6.2, LANL Cyber1, Microsoft Defender datasets, Stratus Red Team), OCSF/ECS/CIM/KQL schema specifications, sliding window sessionization algorithms, and PII anonymization rules.
- **SQLite Database Specifications (`caad_topology.db`)**: Full schema documentation for `entities`, `relationships`, and `identity_privileges` tables, along with the 5-Hop Recursive CTE query.

---

### B. Multi-Platform SIEM Sample Datasets (`data/`)
Pre-populated with 5 realistic cloud anomaly scenarios (Impossible Travel, MFA Push Fatigue Spamming, Dormant Admin Account Activation, Mass S3 Exfiltration, and Audit Log Erasure) across 4 major SIEM standards in both `.json` and `.csv`:
- **Generic OCSF UEBA**: [`sample_generic_ueba_siem.json`](file:///c:/antiProjects/CAAD/data/sample_generic_ueba_siem.json) & [`sample_generic_ueba_siem.csv`](file:///c:/antiProjects/CAAD/data/sample_generic_ueba_siem.csv)
- **Microsoft Sentinel (KQL)**: [`sample_microsoft_sentinel.json`](file:///c:/antiProjects/CAAD/data/sample_microsoft_sentinel.json) & [`sample_microsoft_sentinel.csv`](file:///c:/antiProjects/CAAD/data/sample_microsoft_sentinel.csv)
- **Splunk CIM / RBA**: [`sample_splunk_cim.json`](file:///c:/antiProjects/CAAD/data/sample_splunk_cim.json) & [`sample_splunk_cim.csv`](file:///c:/antiProjects/CAAD/data/sample_splunk_cim.csv)
- **Elastic Security & Wazuh**: [`sample_elastic_wazuh.json`](file:///c:/antiProjects/CAAD/data/sample_elastic_wazuh.json) & [`sample_elastic_wazuh.csv`](file:///c:/antiProjects/CAAD/data/sample_elastic_wazuh.csv)

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
  - 7 interactive tabs: `🚨 Anomaly Triage`, `📊 Behavioral Baseline Profiler`, `🕸️ 1,000+ System Topology`, `📥 SIEM Download Center`, `📤 SIEM Upload & Ingestion`, `⚡ Attack Simulator`, `📚 Data Sources Catalog`.
  - Triage Table with **Detection Accuracy & Feedback** column (`👍 Confirmed` / `👎 False Positive`) and severity dropdown supporting **`FALSE POSITIVE`**.
  - Inspect Modal with tabs for **`🤖 AI English Summary`**, **`🛡️ MITRE ATT&CK Path & Defense`**, and **`📄 Raw User Logs (JSON)`**.
- **[`styles.css`](file:///c:/antiProjects/CAAD/styles.css)**:
  - Dual-theme CSS custom variables (`:root` dark SOC slate & `[data-theme="light"]` clean light theme).
  - Badge styles including `.badge-false-positive`.
  - Print/PDF report stylesheet for executive reporting.
- **[`app.js`](file:///c:/antiProjects/CAAD/app.js)**:
  - Universal drag-and-drop SIEM file upload parser for `.json` and `.csv`.
  - User feedback tracking, **Model Detection Accuracy (%)**, and **Satisfaction Count** calculator.
  - Automatic severity update to `FALSE POSITIVE` upon analyst disagreement feedback.
  - HTML5 Canvas **Blast Radius Visual Node Graph Engine** with radial layout, color-coded node taxonomy, and hover tooltips.
  - GenAI Incident Summarizer & Easy English MITRE ATT&CK/D3FEND Countermeasures generator.

---

## 4. Key Feature Walkthroughs & User Guide

### 1. Theme Switcher (Dark & Light Modes)
- Click **`☀️ Light Mode`** or **`🌙 Dark Mode`** in the top header bar to toggle the UI theme instantly.
- Theme preferences are saved to local storage, and all Chart.js graphs and Canvas node visuals automatically adjust contrast.

### 2. Detection Accuracy & Satisfaction Count Tracking
- In **`🚨 Anomaly Triage`**, click **`👍 Confirmed`** (True Positive) or **`👎 False Positive`** on any row.
- Clicking **`👎 False Positive`** updates the anomaly's severity badge to **`FALSE POSITIVE`** so analysts immediately see the situation.
- The top banner metric **Model Detection Accuracy** and **Satisfaction Count** automatically recalculates:
  $$\text{Model Detection Accuracy} = \left( \frac{\text{Confirmed True Positives}}{\text{Total Analyst Reviews}} \right) \times 100\%$$
  $$\text{Satisfaction Count} = \text{Total Thumbs-Up Likes}$$

### 3. Interactive Visual Blast Radius Node Graph
- Navigate to **`🕸️ 1,000+ System Topology`**.
- Select any compromised identity (e.g. `USER_ALEX_MORGAN` or `USER_SARAH_CHEN`).
- The HTML5 Canvas renders an interactive node-link graph displaying downstream roles, Key Vaults, databases, and compute nodes color-coded by entity type with hover inspection tooltips.

### 4. Inspect Modal: AI English Summary & Easy MITRE ATT&CK Path
- Click **`Inspect`** on any triage anomaly row.
- View **`🤖 AI English Summary`** for a 3-sentence plain English incident report.
- Switch to **`🛡️ MITRE ATT&CK Path & Defense`** for an easy English breakdown of **What the Attacker Did**, **Why It Matters**, and **How to Fix & Defend**, alongside mapped MITRE D3FEND countermeasures.

### 5. SIEM File Upload & Ingestion
- Navigate to **`📤 SIEM Upload & Ingestion`**.
- Drag & drop any `.json` or `.csv` SIEM export file onto the dropzone box to auto-parse, normalize, and merge events into the active triage dashboard.

---

## 5. GitHub Repository Integration

- **Target Repository**: [https://github.com/ramknathchn/SIEM-Analysis](https://github.com/ramknathchn/SIEM-Analysis)
- **Branch**: `main`
- **Latest Commit**: Added Detection Accuracy metrics, Satisfaction Count tracking, FALSE POSITIVE severity level, theme switching, SQLite topology DB, and visual Blast Radius Node Graph Canvas.
