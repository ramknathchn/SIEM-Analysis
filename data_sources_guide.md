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
