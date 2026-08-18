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
        H --> M[In-Report Interactive Filters for Exported Document]
        H --> N[Dark & Light Mode Theme Switcher]
    </div>
```

---

## 3. Core Deliverables & File Directory

### A. In-Report Interactive Filtering for Exported Reports
- **6 Dedicated Field Filters embedded directly in the exported HTML document**:
  1. **Event ID Filter**: Search box targeting specific Event IDs (e.g., `OCSF-UEBA-2026-001`).
  2. **Cloud Provider Filter**: Dropdown selector (`AWS`, `Azure`, `GCP`, `Okta`).
  3. **Identity / User Filter**: Search box targeting user accounts (e.g., `alex.morgan`, `sarah.chen`).
  4. **Country Filter**: Search box targeting origin IP countries (e.g., `Germany`, `Russia`, `China`).
  5. **Scenario Trigger Filter**: Search box targeting attack scenario names (e.g., `Impossible Travel`, `MFA Fatigue`).
  6. **Severity Filter**: Dropdown selector (`CRITICAL`, `HIGH`, `MEDIUM`, `FALSE POSITIVE`).
- **Synchronized Row & Inspection Filtering**: Real-time JavaScript execution dynamically shows/hides both the master summary table rows AND corresponding inspection cards while updating a visible count badge (`X / Y Visible`).

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
  - `exportFilteredTelemetryReport()` implementation with embedded client-side filtering script.
  - HTML5 Canvas **Blast Radius Visual Node Graph Visualizer**.
  - Dark & Light Mode Theme Switcher.

---

## 4. GitHub Repository Integration

- **Target Repository**: [https://github.com/ramknathchn/SIEM-Analysis](https://github.com/ramknathchn/SIEM-Analysis)
- **Branch**: `main`
- **Latest Commit**: In-report interactive filter feature for exported HTML documents (Event ID, Cloud, User, Country, Scenario, Severity), 18-rule catalog, SQLite DB analysis screen, and theme switching.
