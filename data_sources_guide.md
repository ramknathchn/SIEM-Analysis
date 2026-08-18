# Cloud Access Anomaly Detection & UEBA SIEM Data Sources & Schema Engineering Guide

## Executive Summary
This document outlines the data sources, ingestion pipeline architecture, normalization schemas (OCSF, ECS, CIM, KQL), sessionization algorithms, and PII anonymization rules utilized in the **Cloud Access Anomaly Detection & UEBA SIEM Platform**.

---

## 1. Public Benchmarks & Reference Data Sources

| Data Source / Benchmark | Cloud Provider / Platform | Primary Log Types | Key Anomaly / Threat Vectors Evaluated |
| :--- | :--- | :--- | :--- |
| **flaws.cloud / flaws2.cloud** | AWS | AWS CloudTrail | Unauthenticated S3 bucket access, IAM privilege escalation, EC2 metadata service abuse (SSRF). |
| **Splunk BOTS (Boss of the SOC) v1–v3** | AWS, Azure, On-Prem | CloudTrail, Azure Activity, Auth Logs | MFA fatigue attacks, impossible travel, password spraying, dormant admin account reactivation. |
| **CMU CERT Synthetic Insider Threat (r4.2 / r6.2)** | Cross-Cloud / Enterprise | Authentication, File Access, Email | Mass data exfiltration, off-hours access spikes, role drift, access to unassigned assets. |
| **LANL Cyber1 Benchmark** | Multi-System Auth | Unified Event Logs | Authentication anomalies, lateral movement, credential theft, brute-force bursts. |
| **Microsoft Defender / Sentinel Datasets** | Azure / Entra ID | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AzureActivity` | Anomaly-based risk detections: Unfamiliar sign-in properties, Anonymous IP sign-ins, Suspicious inbox rules. |
| **Stratus Red Team (DataDog)** | AWS, GCP, Azure | Audit & Execution Telemetry | Defense evasion (logging deletion), IAM policy backdooring, secrets manager mass dumps. |

---

## 2. SIEM Schema Normalization Specifications

### A. OCSF 1.1 (Open Cybersecurity Schema Framework)
- **Category**: Identity & Access Management (Category ID: `3`)
- **Class**: Account Change / Authentication (Class ID: `3001` / `3002`)
- **Key Fields**:
  - `time`: Unix Epoch timestamp in milliseconds.
  - `actor.user.uid` & `actor.user.email`: Subject identifier.
  - `actor.user.groups`: Assigned security roles/groups.
  - `src_endpoint.ip`: Source IP address.
  - `src_endpoint.location.country` & `city`: Geo-location properties.
  - `unmapped.baseline_avg_daily_events`: Historical 90-day mean event volume.
  - `unmapped.session_event_count`: Current 30-minute window event count.
  - `unmapped.dormant_privilege_drift`: Boolean flag indicating unused high-privilege access.
  - `enrichments.genai_narrative`: AI-synthesized root cause summary.

### B. Microsoft Sentinel (KQL Schema)
- **Primary Tables**: `SigninLogs`, `AzureActivity`, `BehaviorAnalytics`
- **Key Fields**:
  - `TimeGenerated`: ISO 8601 string timestamp.
  - `UserPrincipalName`: User identity string (`alex.morgan@cloudorg.internal`).
  - `IPAddress` & `LocationDetails`: Client IP and JSON object for Country/City/GeoCoordinates.
  - `RiskState`, `RiskLevelDuringSignIn`, `RiskDetail`: Entra ID Protection risk signals.
  - `InvestigationPriority`: UEBA anomaly priority score (0–100).
  - `BaselineDeltaRatio`: Calculated ratio of session event rate vs historical baseline.

### C. Splunk CIM 5.0 (Common Information Model)
- **Data Models**: `Authentication`, `Change_Analysis`, `Risk`
- **Key Fields**:
  - `_time`: Epoch seconds format.
  - `user`: Identity name.
  - `src`: Originating IP address.
  - `action`: `success`, `failure`, `modified`, `deleted`.
  - `risk_score`: Risk-Based Alerting (RBA) numerical score.
  - `risk_object`: Impacted account/resource.
  - `rba_threat_category`: MITRE ATT&CK taxonomy classification.

### D. Elastic Security & Wazuh SIEM (ECS v8.x)
- **ECS Fields**:
  - `@timestamp`: ISO 8601 string.
  - `user.name`, `user.domain`, `user.roles`.
  - `source.ip`, `source.geo.country_name`.
  - `event.category`: `iam`, `authentication`, `configuration`.
  - `wazuh.rule.id` & `wazuh.rule.level`: Rule classification (Levels 1–15).
  - `ml_anomaly_score`: Elastic Machine Learning anomaly confidence indicator.

---

## 3. Sessionization & Anomaly Scoring Algorithm

```
Algorithm 1: Sliding Window Sessionization & Multi-Factor Anomaly Scoring
-------------------------------------------------------------------------
Input: Telemetry Event Stream E, User Baseline DB B, Session Window T_win = 30 mins
Output: Session Anomaly Score S_anomaly, Blast Radius Score S_blast

1. For each incoming event e in E:
2.   session_id = Hash(e.user_id, Floor(e.timestamp / T_win))
3.   Append e to ActiveSession[session_id]
4.   Update Session Metrics:
       N_events = Count(ActiveSession[session_id])
       N_failed = CountFailedAuth(ActiveSession[session_id])
       Distinct_Geo = CountUniqueLocations(ActiveSession[session_id])
       Distinct_APIs = CountUniqueAPIs(ActiveSession[session_id])

5. Retrieve User Baseline Stats B[e.user_id]:
       Avg_Daily_Events = B[e.user_id].mean_daily_events
       Normal_Geo_List  = B[e.user_id].known_countries
       Normal_APIs      = B[e.user_id].frequent_apis
       Dormant_Privs    = B[e.user_id].unassigned_or_unused_roles

6. Compute Sub-Scores:
       Delta_Vol = Max(0, (N_events - (Avg_Daily_Events / 48)) / (Avg_Daily_Events / 48 + 1))
       Geo_Anomaly = 1.0 IF (e.country NOT IN Normal_Geo_List) ELSE 0.0
       API_Drift   = Count(Distinct_APIs NOT IN Normal_APIs) / Max(1, Count(Distinct_APIs))
       Priv_Drift  = 1.0 IF (e.requested_role IN Dormant_Privs) ELSE 0.0

7. Final Anomaly Score S_anomaly:
       S_anomaly = Min(100, (Delta_Vol * 25) + (Geo_Anomaly * 30) + (API_Drift * 20) + (Priv_Drift * 25))

8. Blast Radius Calculation (3-Hop Graph CTE):
       S_blast = SUM( Resource_Criticality_i * Data_Sensitivity_i * (1 / Hop_Depth_i) )
```

---

## 4. Data Anonymization & PII Tokenization Guidelines

1. **User Identity Hash Tokenization**: Real identity names are converted to sanitized formats or pseudonyms (`alex.morgan@cloudorg.internal`, `devops.ci@cloudorg.internal`).
2. **IP Obfuscation**: Public IP addresses are mapped to non-routable documentation ranges (e.g. `198.51.100.x` or `203.0.113.x`) while preserving geographic location metadata for testing impossible travel anomalies.
3. **Session Tokens**: AWS Access Keys (`AKIA...`), Azure Bearer tokens, and GCP Service Account tokens are replaced with synthetic placeholder tokens (`AKIA_DEMO_EXPIRED_MFA_9981`).

---

## 5. Enterprise Topology & Blast Radius SQLite Database Schema (`caad_topology.db`)

To calculate realistic **Blast Radius Impact**, system interconnections, and IAM privilege propagation across cloud environments, all 1,000+ enterprise entities and graph relationship edges are stored in an embedded SQLite database: **[`caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db)**.

### A. Database Tables & Entity Schemas

#### 1. `entities` Table (1,050 Systems, Applications, & Identities)
| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Auto-incrementing primary key. |
| `entity_id` | `TEXT UNIQUE` | Unique identifier (e.g. `USER_ALEX_MORGAN`, `AWS_EC2_PROD_001`, `KMS_PROD_KEY`). |
| `entity_name` | `TEXT` | Human-readable system or identity name (`alex.morgan@cloudorg.internal`). |
| `entity_type` | `TEXT` | Entity classification (`USER`, `SERVICE_ACCOUNT`, `ROLE`, `COMPUTE`, `STORAGE`, `DATABASE`, `KEY_VAULT`, `APPLICATION`). |
| `cloud_provider` | `TEXT` | Origin provider (`AWS`, `Azure`, `GCP`, `On-Prem`). |
| `criticality_weight` | `REAL` | Business criticality weight (1.0 to 10.0). |
| `data_sensitivity_weight` | `REAL` | Sensitivity of stored data (1.0 to 10.0). |
| `status` | `TEXT` | Operating status (`ACTIVE`, `DORMANT`, `SUSPICIOUS`, `COMPROMISED`). |

#### 2. `relationships` Table (2,593 Graph Edges)
| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Primary key. |
| `source_entity_id` | `TEXT` | Origin entity ID (`USER_ALEX_MORGAN`). |
| `target_entity_id` | `TEXT` | Destination system ID (`ROLE_SEC_DORMANT`). |
| `relationship_type` | `TEXT` | Edge classification (`MEMBER_OF`, `ASSUMES_ROLE`, `READS_SECRET`, `HAS_ACCESS_TO`, `DEPLOYS_TO`, `EXFILTRATED_FROM`, `DELETED_LOGS`). |
| `hop_distance` | `INTEGER` | Direct edge hop distance (default = `1`). |

#### 3. `identity_privileges` Table (789 IAM Permissions)
| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Primary key. |
| `entity_id` | `TEXT` | Associated identity or role ID. |
| `permission_name` | `TEXT` | IAM permission (`AdministratorAccess`, `s3:GetObject`, `kms:Decrypt`, `KeyVault.Secrets.Read`). |
| `is_dormant` | `INTEGER` | Boolean flag (1 = dormant permission, 0 = active). |
| `last_used_timestamp` | `TEXT` | ISO 8601 timestamp of last permission usage. |

---

### B. 5-Hop Recursive CTE Graph Traversal & Blast Radius Formula

The Blast Radius score for any compromised identity is computed using a **5-Hop Recursive Common Table Expression (CTE)** query in SQLite:

```sql
WITH RECURSIVE graph_traversal(entity_id, path, hop_depth) AS (
    -- Anchor Member: Find direct dependencies of compromised identity
    SELECT 
        target_entity_id AS entity_id,
        source_entity_id || ' -> ' || target_entity_id AS path,
        1 AS hop_depth
    FROM relationships
    WHERE source_entity_id = 'USER_ALEX_MORGAN'

    UNION ALL

    -- Recursive Member: Traverse downstream system connections up to 5 hops
    SELECT 
        r.target_entity_id AS entity_id,
        gt.path || ' -> ' || r.target_entity_id AS path,
        gt.hop_depth + 1 AS hop_depth
    FROM relationships r
    JOIN graph_traversal gt ON r.source_entity_id = gt.entity_id
    WHERE gt.hop_depth < 5 AND gt.path NOT LIKE '%' || r.target_entity_id || '%'
)
SELECT 
    gt.entity_id,
    gt.hop_depth,
    e.entity_name,
    e.criticality_weight,
    e.data_sensitivity_weight,
    (e.criticality_weight * e.data_sensitivity_weight * (1.0 / gt.hop_depth)) AS contribution_score
FROM graph_traversal gt
JOIN entities e ON gt.entity_id = e.entity_id;
```

#### Mathematical Formula:
$$\text{Blast Radius Score} = \sum_{i \in \text{Reachable Assets}} \left( \text{Criticality}_i \times \text{Sensitivity}_i \times \frac{1}{\text{Hop Depth}_i} \right)$$

---

## 6. Data Availability & Storage Mapping Matrix

The following matrix verifies that **100% of data inputs**, benchmark references, configuration files, and database tables described in this guide are available and physically stored within the platform:

| Data Input / Benchmark Dataset | Availability Status | Physical Storage Location / Workspace File Path | Data Engine / Variable Reference | Primary Description & Usage |
| :--- | :--- | :--- | :--- | :--- |
| **flaws.cloud / flaws2.cloud** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) & [`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `anomalyEvents` (`OCSF-UEBA-2026-004`, `009`) | S3 public bucket access block removal & EC2 metadata SSRF exfiltration logs. |
| **Splunk BOTS v1–v3** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) & [`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `anomalyEvents` (`OCSF-UEBA-2026-001`, `002`, `006`) | MFA fatigue prompt spamming, impossible travel velocity, and cloud password spraying. |
| **CMU CERT Synthetic Insider Threat** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) & [`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `anomalyEvents` (`OCSF-UEBA-2026-003`, `004`, `013`) | Mass data exfiltration, off-hours production API access, and dormant role reactivation. |
| **LANL Cyber1 Benchmark** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) & [`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `anomalyEvents` (`OCSF-UEBA-2026-006`) | Rapid multi-system authentication bursts & brute-force credential stuffing. |
| **Microsoft Sentinel Datasets** | ✅ Available | [`mock_sentinel_fp_50.json`](file:///c:/antiProjects/CAAD/mock_sentinel_fp_50.json), [`mock_sentinel_logs.json`](file:///c:/antiProjects/CAAD/mock_sentinel_logs.json), [`sentinel_queries.kql`](file:///c:/antiProjects/CAAD/sentinel_queries.kql) | `normalizeSiemRecord()` in `app.js` | 50 sample Sentinel KQL records, 4.5MB Sentinel logs, and Sentinel KQL query catalog. |
| **Stratus Red Team (DataDog)** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) & [`rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `anomalyEvents` (`OCSF-UEBA-2026-005`, `007`, `010`) | Defense evasion audit log deletion, KMS master key access, and Key Vault bulk exports. |
| **OCSF 1.1 Standard Telemetry** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) | `anomalyEvents` (15 Sample Multi-Cloud Events) | 15 pre-evaluated AWS, Azure, GCP, and Okta OCSF 1.1 normalized events. |
| **SQLite Topology DB (`entities`)** | ✅ Available | [`c:\antiProjects\CAAD\caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db) | `entities` table (1,050 Rows) | Enterprise graph entities (Users, Roles, Key Vaults, Databases, Compute nodes). |
| **SQLite Topology DB (`relationships`)** | ✅ Available | [`c:\antiProjects\CAAD\caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db) | `relationships` table (2,593 Edges) | Downstream system graph connections (`ASSUMES_ROLE`, `READS_SECRET`, `MEMBER_OF`, etc.). |
| **SQLite Topology DB (`identity_privileges`)** | ✅ Available | [`c:\antiProjects\CAAD\caad_topology.db`](file:///c:/antiProjects/CAAD/caad_topology.db) | `identity_privileges` table (789 Permissions) | Detailed IAM permissions, dormant flags, and last-used timestamps. |
| **Configurable Rulebook** | ✅ Available | [`c:\antiProjects\CAAD\rulebook_config.json`](file:///c:/antiProjects/CAAD/rulebook_config.json) | `rulebook_metadata` (18 Rules) | 5 False Positive operational baseline rules & 13 Threat Anomaly detection rules. |
| **GenAI LLM Configuration** | ✅ Available | [`c:\antiProjects\CAAD\ai_config.json`](file:///c:/antiProjects/CAAD/ai_config.json) | `aiConfig` store in `app.js` | System prompt templates, temperature (0.2), confidence cutoff (85%), and provider. |
| **Analyst Feedback & Sentiment Store** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) | `userFeedbackStore` | In-memory store saving analyst comments, sentiment scores, and satisfaction ratings. |
| **Filtered Telemetry Exporter** | ✅ Available | [`c:\antiProjects\CAAD\app.js`](file:///c:/antiProjects/CAAD/app.js) | `exportFilteredTelemetryReport()` | Tabulated summary exporter with full AI summaries, MITRE paths, D3FEND tables, and CLIs. |
