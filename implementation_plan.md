# Master Implementation Plan: Cloud Access Anomaly Detection & UEBA SIEM Platform

## Project Overview
This project delivers an end-to-end **Cloud Access Anomaly Detection and User Behavior Analytics (UEBA)** solution. It addresses the challenge of high-volume cloud access logs, alert fatigue, and lack of context in conventional SIEM tools by combining:
1. **Public Data Sources & Engineering Pipelines**: Standardized ingestion of AWS CloudTrail, Azure/Entra ID, GCP Audit, and Okta logs with OCSF normalization and sessionization.
2. **All 4 SIEM Report Formats**: Downloadable datasets in JSON and CSV for Generic/OCSF, Microsoft Sentinel (KQL), Splunk (CIM/RBA), and Elastic/Wazuh (ECS).
3. **Multi-Perspective Strategic Enhancements**:
   - **Explainable AI Root-Cause Narratives**: Human-readable plain English incident summaries with confidence metrics.
   - **Identity Threat Detection & Response (ITDR)**: Dormant privilege drift and 5-hop recursive CTE blast-radius impact analysis.
   - **MITRE ATT&CK Cloud Matrix Alignment**: TTP chaining across Initial Access, Persistence, Privilege Escalation, and Exfiltration.
   - **1-Click SOC Remediation Playbooks**: Automated CLI/PowerShell commands to isolate accounts and revoke session tokens.
4. **Universal SIEM File Ingestion & Drag-and-Drop Parser**: Automatic normalization of uploaded `.json` and `.csv` SIEM log exports.
5. **1,000+ System Enterprise Topology & SQLite Database**: Embedded SQLite database (`caad_topology.db`) storing 1,050 entities, 2,593 relationship edges, and 789 IAM privileges.
6. **Interactive Visual Blast Radius Node Graph**: Real-time canvas node-link visualizer rendering 5-hop asset connections, criticality weights, and edge relationships.

---

## User Review Required

> [!IMPORTANT]
> **Data Format Standard**: All 4 SIEM platforms (Generic OCSF, Microsoft Sentinel, Splunk CIM, Elastic/Wazuh) are pre-populated with realistic cloud anomaly scenarios (Impossible Travel, MFA Fatigue, Dormant IAM Backdoors, Mass S3 Exfiltration, and Audit Log Deletion) and available in both `.json` and `.csv` formats.

> [!NOTE]
> The dashboard operates locally with zero external backend dependencies using Vanilla HTML5/CSS3/ES6, Canvas-based Node Graph Visualizer, and client-side Chart.js visualizations.

---

## Implementation Roadmap & Architecture

```mermaid
flowchart LR
    subgraph Data & Ingestion Layer
        A1[AWS CloudTrail] --> B[OCSF / ECS Normalization]
        A2[Azure SigninLogs] --> B
        A3[GCP Audit Logs] --> B
        A4[Uploaded SIEM .json/.csv] --> B
    end

    subgraph Topology & UEBA Engine
        B --> C[30m Window Sessionization]
        C --> D[90-Day Behavioral Baseline]
        C --> E[Real-Time Feature Delta]
        D & E --> F[SQLite 1,000+ Topology DB: caad_topology.db]
        F --> G[5-Hop Recursive CTE Blast Radius Scoring]
        G --> H[GenAI Context & Plain English Synthesizer]
    end

    subgraph Deliverables & Interactive UI
        H --> I[SIEM Download Center: JSON / CSV / PDF]
        H --> J[Interactive SOC Web Dashboard]
        H --> K[Visual Blast Radius Node Graph Canvas]
        H --> L[1-Click SOC CLI Playbooks]
    end
```

---

## Proposed Changes & File Structure

### 1. Data Sources & Schema Engineering Catalog
- [`data_sources_guide.md`](file:///c:/antiProjects/CAAD/data_sources_guide.md)
  - Detailed directory of public benchmarks (flaws.cloud, Splunk BOTS v1–v3, CMU CERT r4.2/r6.2, LANL Cyber1, Microsoft Defender datasets, Stratus Red Team).
  - Normalization specifications for OCSF 1.1, Elastic Common Schema (ECS), Splunk CIM 5.0, and Azure Log Analytics KQL tables.
  - Sessionization algorithm, feature vector definitions, and PII anonymization / tokenization rules.
  - **SQLite Database Specifications (`caad_topology.db`)**: `entities` (1,050 nodes), `relationships` (2,593 edges), `identity_privileges` (789 permissions), and 5-hop recursive CTE graph traversal query.

---

### 2. Multi-Platform SIEM Sample Report Datasets
Located in [`data/`](file:///c:/antiProjects/CAAD/data):

- **Platform 1: Generic / Multi-Cloud OCSF UEBA**
  - [`sample_generic_ueba_siem.json`](file:///c:/antiProjects/CAAD/data/sample_generic_ueba_siem.json)
  - [`sample_generic_ueba_siem.csv`](file:///c:/antiProjects/CAAD/data/sample_generic_ueba_siem.csv)

- **Platform 2: Microsoft Sentinel / Azure Monitor**
  - [`sample_microsoft_sentinel.json`](file:///c:/antiProjects/CAAD/data/sample_microsoft_sentinel.json)
  - [`sample_microsoft_sentinel.csv`](file:///c:/antiProjects/CAAD/data/sample_microsoft_sentinel.csv)

- **Platform 3: Splunk Enterprise & Cloud**
  - [`sample_splunk_cim.json`](file:///c:/antiProjects/CAAD/data/sample_splunk_cim.json)
  - [`sample_splunk_cim.csv`](file:///c:/antiProjects/CAAD/data/sample_splunk_cim.csv)

- **Platform 4: Elastic Security & Wazuh SIEM**
  - [`sample_elastic_wazuh.json`](file:///c:/antiProjects/CAAD/data/sample_elastic_wazuh.json)
  - [`sample_elastic_wazuh.csv`](file:///c:/antiProjects/CAAD/data/sample_elastic_wazuh.csv)

---

### 3. Enterprise Topology & SQLite Database
- [`caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db): SQLite DB pre-seeded with 1,050 systems & IAM accounts and 2,593 graph edges.
- [`scratch/build_topology_db.py`](file:///c:/antiProjects/CAAD/scratch/build_topology_db.py): Seed script generating 1,000+ connected topology nodes and edges.
- [`scratch/query_blast_radius.py`](file:///c:/antiProjects/CAAD/scratch/query_blast_radius.py): Python script executing 5-hop CTE recursive graph queries.

---

### 4. Interactive Web Application (Modern SOC Dashboard & Downloader)
- [`index.html`](file:///c:/antiProjects/CAAD/index.html)
  - Top SOC metrics bar (Critical/High alerts, analyzed sessions count, ML confidence).
  - Header AI configuration button (`⚙️ AI Config`).
  - 7-tab structure: Anomaly Triage, Behavioral Baseline Profiler, 1,000+ System Topology & Visual Node Graph, SIEM Download Center, SIEM Upload & Ingestion, Attack Simulator, Data Sources Catalog.
  - Modals for AI Log Summarization on Inspect, 1-Click Remediation Playbooks, and AI Engine Configuration.
- [`styles.css`](file:///c:/antiProjects/CAAD/styles.css)
  - Cyber-slate SOC theme (`#06090e`), JetBrains Mono & Inter typography, responsive dropzones, node graph canvas containers, and printable PDF report stylesheet.
- [`app.js`](file:///c:/antiProjects/CAAD/app.js)
  - Universal SIEM file parser for `.json` and `.csv` drag-and-drop uploads.
  - GenAI Incident Summarizer synthesizing plain English reports for inspected users.
  - HTML5 Canvas interactive **Blast Radius Node Graph Visualizer** with color-coded node types, directed edge lines, hop labels, and node hover inspection.
  - Client-side Blob file download generator for JSON & CSV across all 4 platforms.

---

## Verification Plan

### Automated & Structural Checks
1. Validate JSON and CSV file syntax across all 4 platforms in `data/`.
2. Confirm SQLite `caad_topology.db` queries execute without errors.

### Manual / Browser Verification
1. Open `http://localhost:8080` in the browser.
2. Navigate to **`🕸️ 1,000+ System Topology`** and verify the interactive **Blast Radius Visual Node Graph**.
3. Click **Inspect** on any user anomaly in **`🚨 Anomaly Triage`** to verify AI Plain English Log Summarization.
4. Drag & drop a `.json` or `.csv` SIEM file in **`📤 SIEM Upload & Ingestion`** to test auto-parsing.
5. Trigger the Adversarial Attack Simulator and verify real-time chart and metric updates.
