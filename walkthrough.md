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
        H --> M[Filtered Telemetry Export with Inspection Content]
        H --> N[Dark & Light Mode Theme Switcher]
    </div>
```

---

## 3. Core Deliverables & File Directory

### A. Filtered Anomaly Telemetry Export Feature
- **`📊 Export Telemetry Report` Button**: Added to **`🚨 Anomaly Triage`** header and filter bar.
- **Filter-Aware Export**: Exports only anomaly records matching active search terms, severity filters (`CRITICAL`, `HIGH`, `FALSE POSITIVE`), and cloud provider filters (`AWS`, `Azure`, `GCP`).
- **Tabulated Structure**: Includes a master tabulated summary table listing all matching events.
- **Complete Inspect Content Export**: Includes full inspection details for EVERY filtered event:
  - 🤖 **Plain English AI Summary & Baseline Delta Analysis**.
  - ⛓️ **Technical MITRE ATT&CK Execution Path Stepper** (Steps 1–5).
  - 🛡️ **Mapped MITRE D3FEND Countermeasures & NIST SP 800-53 Controls Table**.
  - ⚡ **SOC 1-Click Remediation Playbook CLI / PowerShell Commands**.
- **Dual Export Modes**: Generates a `.html` Blob download and opens an interactive printable PDF export window (`window.print()`).

---

### B. Configurable Detection Rulebook (`rulebook_config.json`)
- **[`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json)**: Expanded **18-rule detection catalog** comprising 5 False Positive operational rules and 13 Threat Anomaly rules.

---

### C. Pre-Evaluated Telemetry Sample Events (15 Events)
Pre-populated with **15 multi-cloud sample events** across AWS, Azure, GCP, and Okta pre-evaluated against the 18 detection rules in `rulebook_config.json`.

---

### D. Enterprise Topology SQLite Database (`caad_topology.db`)
- **[`caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db)**: SQLite database pre-seeded with **1,050 connected enterprise entities**, **2,593 relationship edges**, and **789 IAM permissions**.

---

### E. Interactive Web Dashboard Components
- **[`index.html`](file:///c:/antiProjects/CAAD/index.html)** & **[`app.js`](file:///c:/antiProjects/CAAD/app.js)**:
  - 8-tab structure (`Triage`, `Baseline`, `Topology`, `SQLite DB Analysis`, `SIEM Download`, `Upload`, `Simulator`, `Catalog`).
  - `exportFilteredTelemetryReport()` implementation.
  - HTML5 Canvas **Blast Radius Visual Node Graph Visualizer**.
  - Dark & Light Mode Theme Switcher.

---

## 4. GitHub Repository Integration

- **Target Repository**: [https://github.com/ramknathchn/SIEM-Analysis](https://github.com/ramknathchn/SIEM-Analysis)
- **Branch**: `main`
- **Latest Commit**: Filtered telemetry export feature with full inspect content, 18-rule catalog, SQLite DB analysis screen, and theme switching.
