// Global AI Engine Configuration (backed by ai_config.json)
let aiConfig = {
  provider: "Built-In Synthesizer",
  model_name: "gemini-1.5-pro",
  api_endpoint: "http://localhost:11434/api/generate",
  temperature: 0.2,
  confidence_threshold: 85.0,
  language: "English",
  summary_style: "SOC Incident Report (Executive + Technical)"
};

function openAiConfigModal() {
  document.getElementById("cfg-ai-provider").value = aiConfig.provider;
  document.getElementById("cfg-ai-model").value = aiConfig.model_name;
  document.getElementById("cfg-ai-endpoint").value = aiConfig.api_endpoint;
  document.getElementById("cfg-ai-lang").value = aiConfig.language;
  document.getElementById("cfg-ai-confidence").value = aiConfig.confidence_threshold;
  document.getElementById("modal-ai-config").classList.add("active");
}

function saveAiConfigFromUi() {
  aiConfig.provider = document.getElementById("cfg-ai-provider").value;
  aiConfig.model_name = document.getElementById("cfg-ai-model").value;
  aiConfig.api_endpoint = document.getElementById("cfg-ai-endpoint").value;
  aiConfig.language = document.getElementById("cfg-ai-lang").value;
  aiConfig.confidence_threshold = parseFloat(document.getElementById("cfg-ai-confidence").value) || 85.0;
}

// Initial Anomaly Telemetry Dataset
let anomalyEvents = [
  {
    event_id: "OCSF-UEBA-2026-001",
    timestamp: "2026-08-18T08:14:22Z",
    category_name: "Identity & Access Management",
    class_name: "Authentication & Session Drift",
    cloud_provider: "AWS",
    actor: {
      user_name: "alex.morgan@cloudorg.internal",
      user_arn: "arn:aws:iam::123456789012:user/alex.morgan",
      assigned_roles: ["DeveloperAccess", "SecurityAnalyst-Dormant"]
    },
    src_endpoint: {
      ip: "198.51.100.45",
      country: "Germany",
      city: "Frankfurt",
      isp: "CloudHosting-DE"
    },
    anomaly_details: {
      scenario: "Impossible Travel Velocity",
      severity: "CRITICAL",
      risk_score: 94.5,
      blast_radius_score: 88.0,
      baseline_90d_avg_daily_events: 45,
      session_30m_event_count: 310,
      baseline_delta_ratio: 6.88,
      mitre_attack: {
        technique_id: "T1078.004",
        technique_name: "Valid Accounts: Cloud Accounts",
        tactic: "Initial Access & Privilege Escalation"
      },
      genai_explanation: "User alex.morgan authenticated from Frankfurt 14 minutes after active session in New York (travel speed 3,800 mph). Session volume spiked 6.8x above 90-day baseline with access to unassigned production KMS keys.",
      remediation_playbook: {
        action: "Isolate Identity & Revoke Tokens",
        cli_command: "aws iam revoke-security-credentials --user-name alex.morgan && aws ec2 stop-instances --instance-ids i-089a1b2c"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-002",
    timestamp: "2026-08-18T09:30:15Z",
    category_name: "Identity & Access Management",
    class_name: "MFA Spamming & Session Hijack",
    cloud_provider: "Azure / Entra ID",
    actor: {
      user_name: "sarah.chen@cloudorg.internal",
      user_arn: "entra://cloudorg.onmicrosoft.com/users/sarah.chen",
      assigned_roles: ["Global Administrator"]
    },
    src_endpoint: {
      ip: "203.0.113.88",
      country: "Russia",
      city: "Moscow",
      isp: "VPN-Proxy-Net"
    },
    anomaly_details: {
      scenario: "MFA Fatigue Prompt Spamming",
      severity: "HIGH",
      risk_score: 87.2,
      blast_radius_score: 92.5,
      baseline_90d_avg_daily_events: 120,
      session_30m_event_count: 480,
      baseline_delta_ratio: 4.00,
      mitre_attack: {
        technique_id: "T1621",
        technique_name: "Multi-Factor Authentication Request Generation",
        tactic: "Credential Access"
      },
      genai_explanation: "Account experienced 32 consecutive denied MFA push notifications in 4 minutes before approval from an untrusted Moscow IP. User immediately requested Azure Key Vault secret export.",
      remediation_playbook: {
        action: "Disable User & Reset MFA Credentials",
        cli_command: "Update-MgUser -UserId 'sarah.chen@cloudorg.internal' -AccountEnabled $false && Revoke-MgUserSignInSession -UserId 'sarah.chen@cloudorg.internal'"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-003",
    timestamp: "2026-08-18T10:05:00Z",
    category_name: "Resource Access & IAM",
    class_name: "Dormant IAM Privilege Drift",
    cloud_provider: "AWS",
    actor: {
      user_name: "svc_ci_deployer",
      user_arn: "arn:aws:iam::123456789012:user/svc_ci_deployer",
      assigned_roles: ["FullAdministratorAccess-Dormant"]
    },
    src_endpoint: {
      ip: "198.51.100.102",
      country: "United States",
      city: "Ashburn",
      isp: "AWS-EC2-Compute"
    },
    anomaly_details: {
      scenario: "Dormant Admin Account Reactivation",
      severity: "CRITICAL",
      risk_score: 96.8,
      blast_radius_score: 98.0,
      baseline_90d_avg_daily_events: 0,
      session_30m_event_count: 890,
      baseline_delta_ratio: 890.00,
      mitre_attack: {
        technique_id: "T1098.001",
        technique_name: "Account Manipulation: Additional Cloud Credentials",
        tactic: "Persistence & Privilege Escalation"
      },
      genai_explanation: "Service account dormant for 142 days suddenly invoked PutUserPolicy creating an unrestricted inline admin policy. New access key generated and attached to secondary EC2 instance.",
      remediation_playbook: {
        action: "Delete Access Keys & Detach Policies",
        cli_command: "aws iam delete-access-key --user-name svc_ci_deployer --access-key-id AKIA_SUSPECT_ID && aws iam delete-user-policy --user-name svc_ci_deployer --policy-name BackdoorAdmin"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-004",
    timestamp: "2026-08-18T11:12:40Z",
    category_name: "Data Storage Telemetry",
    class_name: "Mass Cloud Data Exfiltration",
    cloud_provider: "GCP",
    actor: {
      user_name: "devops.lead@cloudorg.internal",
      user_arn: "serviceAccount:devops-lead@cloudorg-proj.iam.gserviceaccount.com",
      assigned_roles: ["Storage Object Viewer", "BigQuery Admin"]
    },
    src_endpoint: {
      ip: "203.0.113.199",
      country: "China",
      city: "Beijing",
      isp: "Unassigned-AS-Net"
    },
    anomaly_details: {
      scenario: "Mass Cloud Storage Exfiltration",
      severity: "HIGH",
      risk_score: 89.4,
      blast_radius_score: 91.2,
      baseline_90d_avg_daily_events: 85,
      session_30m_event_count: 1420,
      baseline_delta_ratio: 16.71,
      mitre_attack: {
        technique_id: "T1567.002",
        technique_name: "Exfiltration to Cloud Storage",
        tactic: "Exfiltration"
      },
      genai_explanation: "High-volume call burst executing storage.objects.get across 18 sensitive customer backup buckets. Total egress payload exceeded 48 GB in 12 minutes.",
      remediation_playbook: {
        action: "Revoke Service Account Keys & Block IP",
        cli_command: "gcloud iam service-accounts keys delete KEY_ID --iam-account=devops-lead@cloudorg-proj.iam.gserviceaccount.com"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-005",
    timestamp: "2026-08-18T11:45:10Z",
    category_name: "Audit Logging",
    class_name: "Defense Evasion & Audit Trail Erasure",
    cloud_provider: "AWS",
    actor: {
      user_name: "secops.automation",
      user_arn: "arn:aws:iam::123456789012:user/secops.automation",
      assigned_roles: ["CloudWatchAdmin"]
    },
    src_endpoint: {
      ip: "198.51.100.220",
      country: "Brazil",
      city: "Sao Paulo",
      isp: "Anon-Proxy-BR"
    },
    anomaly_details: {
      scenario: "Audit Trail Log Tampering & Deletion",
      severity: "CRITICAL",
      risk_score: 98.1,
      blast_radius_score: 95.0,
      baseline_90d_avg_daily_events: 30,
      session_30m_event_count: 195,
      baseline_delta_ratio: 6.50,
      mitre_attack: {
        technique_id: "T1562.001",
        technique_name: "Impair Defenses: Disable Cloud Logs",
        tactic: "Defense Evasion"
      },
      genai_explanation: "CloudTrail logging disabled (StopLogging) followed by deletion of S3 audit log bucket policy. Operations originated from unverified IP address in Brazil.",
      remediation_playbook: {
        action: "Re-enable CloudTrail & Reapply S3 Bucket Locks",
        cli_command: "aws cloudtrail start-logging --name prod-security-trail && aws s3api put-bucket-policy --bucket cloudtrail-logs-org --policy file://secure-policy.json"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-006",
    timestamp: "2026-08-18T12:02:15Z",
    category_name: "Identity & Access Management",
    class_name: "Credential Access & Password Spraying",
    cloud_provider: "Azure / Entra ID",
    actor: {
      user_name: "external_attacker_net",
      user_arn: "entra://cloudorg.onmicrosoft.com/users/spray_target",
      assigned_roles: ["MultipleUserTargets"]
    },
    src_endpoint: {
      ip: "198.51.100.89",
      country: "Romania",
      city: "Bucharest",
      isp: "Datacenter-Hosts"
    },
    anomaly_details: {
      scenario: "Cloud Password Spraying Attack Burst",
      severity: "HIGH",
      risk_score: 84.5,
      blast_radius_score: 75.0,
      baseline_90d_avg_daily_events: 10,
      session_30m_event_count: 540,
      baseline_delta_ratio: 54.00,
      mitre_attack: {
        technique_id: "T1110.003",
        technique_name: "Brute Force: Password Spraying",
        tactic: "Credential Access"
      },
      genai_explanation: "Rapid automated sign-in attempts against 140 distinct user accounts using single passwords per iteration to evade smart lockout thresholds.",
      remediation_playbook: {
        action: "Enforce Smart Lockout & Block IP",
        cli_command: "New-MgPolicyConditionalAccessPolicy -DisplayName 'Block Spray IP Range' -State 'Enabled'"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-007",
    timestamp: "2026-08-18T12:15:30Z",
    category_name: "Resource Access & IAM",
    class_name: "Privilege Escalation & KMS Access",
    cloud_provider: "AWS",
    actor: {
      user_name: "contractor.dev@cloudorg.internal",
      user_arn: "arn:aws:iam::123456789012:user/contractor.dev",
      assigned_roles: ["ContractorRole"]
    },
    src_endpoint: {
      ip: "203.0.113.111",
      country: "Ukraine",
      city: "Kyiv",
      isp: "ISP-Global-Transit"
    },
    anomaly_details: {
      scenario: "Unassigned KMS Master Encryption Key Access",
      severity: "CRITICAL",
      risk_score: 93.2,
      blast_radius_score: 96.0,
      baseline_90d_avg_daily_events: 5,
      session_30m_event_count: 140,
      baseline_delta_ratio: 28.00,
      mitre_attack: {
        technique_id: "T1552.004",
        technique_name: "Unsecured Credentials: Private Keys",
        tactic: "Credential Access"
      },
      genai_explanation: "Contractor account accessed production KMS decryption keys outside baseline entitlement policy.",
      remediation_playbook: {
        action: "Revoke KMS Key Policy Permissions",
        cli_command: "aws kms put-key-policy --key-id kms-prod-data-key --policy-name default --policy file://restricted.json"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-008",
    timestamp: "2026-08-18T12:30:00Z",
    category_name: "Identity & Access Management",
    class_name: "Cross-Account IAM Role Assumption",
    cloud_provider: "AWS",
    actor: {
      user_name: "partner.auditor@externalorg.com",
      user_arn: "arn:aws:sts::123456789012:assumed-role/PartnerAuditRole/session-01",
      assigned_roles: ["PartnerAuditRole"]
    },
    src_endpoint: {
      ip: "198.51.100.23",
      country: "Netherlands",
      city: "Amsterdam",
      isp: "Equinix-NL"
    },
    anomaly_details: {
      scenario: "Cross-Account IAM Role Assumption Drift",
      severity: "HIGH",
      risk_score: 88.0,
      blast_radius_score: 89.5,
      baseline_90d_avg_daily_events: 2,
      session_30m_event_count: 85,
      baseline_delta_ratio: 42.50,
      mitre_attack: {
        technique_id: "T1078.004",
        technique_name: "Valid Accounts: Cloud Accounts",
        tactic: "Privilege Escalation"
      },
      genai_explanation: "External partner role assumed cross-account session without ExternalId validation.",
      remediation_playbook: {
        action: "Update Trust Policy & Require ExternalId",
        cli_command: "aws iam update-assume-role-policy --role-name PartnerAuditRole --policy-document file://strict-trust.json"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-009",
    timestamp: "2026-08-18T12:45:10Z",
    category_name: "Data Storage Telemetry",
    class_name: "Public Storage Exposure",
    cloud_provider: "AWS",
    actor: {
      user_name: "app.builder@cloudorg.internal",
      user_arn: "arn:aws:iam::123456789012:user/app.builder",
      assigned_roles: ["S3Developer"]
    },
    src_endpoint: {
      ip: "203.0.113.55",
      country: "India",
      city: "Bengaluru",
      isp: "Airtel-IN"
    },
    anomaly_details: {
      scenario: "S3 Bucket Public Access Block Removal",
      severity: "CRITICAL",
      risk_score: 95.4,
      blast_radius_score: 97.5,
      baseline_90d_avg_daily_events: 20,
      session_30m_event_count: 95,
      baseline_delta_ratio: 4.75,
      mitre_attack: {
        technique_id: "T1530",
        technique_name: "Data from Cloud Storage Object",
        tactic: "Exfiltration"
      },
      genai_explanation: "Public access block removed from production S3 customer database backup bucket.",
      remediation_playbook: {
        action: "Re-enable Public Access Block",
        cli_command: "aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-010",
    timestamp: "2026-08-18T13:00:22Z",
    category_name: "Resource Access & IAM",
    class_name: "Key Vault Secret Extraction",
    cloud_provider: "Azure / Entra ID",
    actor: {
      user_name: "finance.analyst@cloudorg.internal",
      user_arn: "entra://cloudorg.onmicrosoft.com/users/finance.analyst",
      assigned_roles: ["KeyVaultReader"]
    },
    src_endpoint: {
      ip: "198.51.100.77",
      country: "United Kingdom",
      city: "London",
      isp: "BT-Group-UK"
    },
    anomaly_details: {
      scenario: "Azure Key Vault Bulk Secret Export Burst",
      severity: "HIGH",
      risk_score: 89.1,
      blast_radius_score: 91.0,
      baseline_90d_avg_daily_events: 15,
      session_30m_event_count: 220,
      baseline_delta_ratio: 14.67,
      mitre_attack: {
        technique_id: "T1555.006",
        technique_name: "Credentials from Password Stores",
        tactic: "Credential Access"
      },
      genai_explanation: "High-volume secret reading burst downloading 42 database passwords and SSL certificates.",
      remediation_playbook: {
        action: "Rotate Vault Secrets & Revoke Key Vault Access",
        cli_command: "az keyvault purge --name financial-secrets-vault"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-011",
    timestamp: "2026-08-18T13:10:05Z",
    category_name: "Identity & Access Management",
    class_name: "Root Account Console Access",
    cloud_provider: "AWS",
    actor: {
      user_name: "root",
      user_arn: "arn:aws:iam::123456789012:root",
      assigned_roles: ["AccountOwner"]
    },
    src_endpoint: {
      ip: "203.0.113.201",
      country: "Poland",
      city: "Warsaw",
      isp: "Orange-PL"
    },
    anomaly_details: {
      scenario: "Root Account Authentication without Hardware MFA",
      severity: "CRITICAL",
      risk_score: 97.8,
      blast_radius_score: 100.0,
      baseline_90d_avg_daily_events: 0,
      session_30m_event_count: 45,
      baseline_delta_ratio: 45.00,
      mitre_attack: {
        technique_id: "T1078.001",
        technique_name: "Valid Accounts: Default Accounts",
        tactic: "Initial Access"
      },
      genai_explanation: "AWS Root account logged into management console without physical hardware FIDO2 key requirement.",
      remediation_playbook: {
        action: "Lock Root Credentials & Enforce Hardware FIDO2",
        cli_command: "aws iam create-virtual-mfa-device --mfa-device-name RootHardwareKey"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-012",
    timestamp: "2026-08-18T13:18:40Z",
    category_name: "Identity & Access Management",
    class_name: "TOR Exit Node Sign-In",
    cloud_provider: "Okta / Cloud",
    actor: {
      user_name: "support.engineer@cloudorg.internal",
      user_arn: "okta://cloudorg.okta.com/users/support.engineer",
      assigned_roles: ["SupportTier2"]
    },
    src_endpoint: {
      ip: "185.220.101.5",
      country: "Germany",
      city: "Berlin",
      isp: "TOR-Exit-Node-DE"
    },
    anomaly_details: {
      scenario: "Anonymized Proxy & TOR Exit Node Access",
      severity: "HIGH",
      risk_score: 86.4,
      blast_radius_score: 80.0,
      baseline_90d_avg_daily_events: 40,
      session_30m_event_count: 110,
      baseline_delta_ratio: 2.75,
      mitre_attack: {
        technique_id: "T1090.003",
        technique_name: "Proxy: Multi-hop Proxy",
        tactic: "Command & Control"
      },
      genai_explanation: "Authentication request routed through verified active TOR exit node IP address.",
      remediation_playbook: {
        action: "Enforce Anonymized Network Blocking Policy",
        cli_command: "Okta-Zone-Update -ZoneId 'TOR_Block_Zone' -AddIp '185.220.101.5'"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-013",
    timestamp: "2026-08-18T13:25:00Z",
    category_name: "Security Auditing",
    class_name: "Authorized Security Audit",
    cloud_provider: "AWS",
    actor: {
      user_name: "qualys_auditor_bot",
      user_arn: "arn:aws:iam::123456789012:user/qualys_auditor_bot",
      assigned_roles: ["SecurityAudit"]
    },
    src_endpoint: {
      ip: "64.39.96.10",
      country: "United States",
      city: "Redwood City",
      isp: "Qualys-Inc"
    },
    anomaly_details: {
      scenario: "Authorized Vulnerability & Compliance Security Scanner",
      severity: "FALSE POSITIVE",
      original_severity: "LOW",
      risk_score: 22.1,
      blast_radius_score: 30.0,
      baseline_90d_avg_daily_events: 500,
      session_30m_event_count: 480,
      baseline_delta_ratio: 0.96,
      mitre_attack: {
        technique_id: "T1595",
        technique_name: "Active Scanning",
        tactic: "Reconnaissance"
      },
      genai_explanation: "Automated vulnerability scanner checking security configurations. Verified non-malicious operational baseline.",
      remediation_playbook: {
        action: "No Action Required - Approved Security Scanner",
        cli_command: "# Approved Operational Baseline"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-014",
    timestamp: "2026-08-18T13:30:12Z",
    category_name: "DevOps Pipeline",
    class_name: "CI/CD Deployment Job",
    cloud_provider: "AWS",
    actor: {
      user_name: "github_actions_bot",
      user_arn: "arn:aws:iam::123456789012:role/GitHubActionsRunner",
      assigned_roles: ["DeployerRole"]
    },
    src_endpoint: {
      ip: "140.82.112.4",
      country: "United States",
      city: "Seattle",
      isp: "GitHub-Inc"
    },
    anomaly_details: {
      scenario: "Scheduled CI/CD Deployment Service Account",
      severity: "FALSE POSITIVE",
      original_severity: "LOW",
      risk_score: 18.5,
      blast_radius_score: 25.0,
      baseline_90d_avg_daily_events: 250,
      session_30m_event_count: 240,
      baseline_delta_ratio: 0.96,
      mitre_attack: {
        technique_id: "T1072",
        technique_name: "Software Deployment Tools",
        tactic: "Execution"
      },
      genai_explanation: "Scheduled GitHub Actions workflow updating microservice container images in EKS cluster. Verified non-malicious operational baseline.",
      remediation_playbook: {
        action: "No Action Required - Approved CI/CD Pipeline",
        cli_command: "# Approved Operational Baseline"
      }
    }
  },
  {
    event_id: "OCSF-UEBA-2026-015",
    timestamp: "2026-08-18T13:35:45Z",
    category_name: "Infrastructure Management",
    class_name: "Maintenance Window Patching",
    cloud_provider: "GCP",
    actor: {
      user_name: "datadog_agent_svc",
      user_arn: "serviceAccount:datadog-agent@cloudorg.iam.gserviceaccount.com",
      assigned_roles: ["MonitoringViewer"]
    },
    src_endpoint: {
      ip: "34.201.20.12",
      country: "United States",
      city: "Ashburn",
      isp: "Google-Cloud Platform"
    },
    anomaly_details: {
      scenario: "Automated Synthetic Health Check Monitor",
      severity: "FALSE POSITIVE",
      original_severity: "LOW",
      risk_score: 15.0,
      blast_radius_score: 18.0,
      baseline_90d_avg_daily_events: 1200,
      session_30m_event_count: 1180,
      baseline_delta_ratio: 0.98,
      mitre_attack: {
        technique_id: "T1082",
        technique_name: "System Information Discovery",
        tactic: "Discovery"
      },
      genai_explanation: "Synthetic Datadog health check querying application status endpoints. Verified non-malicious operational baseline.",
      remediation_playbook: {
        action: "No Action Required - Approved Health Monitor",
        cli_command: "# Approved Operational Baseline"
      }
    }
  }
];

// Analyst Feedback & Agreement Tracking Store
let userFeedbackStore = {
  "OCSF-UEBA-2026-001": true,
  "OCSF-UEBA-2026-002": true,
  "OCSF-UEBA-2026-003": true,
  "OCSF-UEBA-2026-004": true,
  "OCSF-UEBA-2026-005": true,
  "OCSF-UEBA-2026-006": true,
  "OCSF-UEBA-2026-007": true,
  "OCSF-UEBA-2026-008": true,
  "OCSF-UEBA-2026-009": true,
  "OCSF-UEBA-2026-010": true,
  "OCSF-UEBA-2026-011": true,
  "OCSF-UEBA-2026-012": true,
  "OCSF-UEBA-2026-013": false,
  "OCSF-UEBA-2026-014": false,
  "OCSF-UEBA-2026-015": false
};

// Theme Switcher Handler (Dark vs Light)
function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("caad_theme", newTheme);
  
  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (toggleBtn) {
    toggleBtn.textContent = newTheme === "dark" ? "☀️ Light Mode" : "🌙 Dark Mode";
  }

  // Re-render charts for theme contrast
  renderCharts();
  renderTopologyGraph();
}

// Record Analyst Feedback for Detection Accuracy & False Positives
function recordAnalystFeedback(eventId, isAgreed) {
  userFeedbackStore[eventId] = isAgreed;

  const evt = anomalyEvents.find(e => e.event_id === eventId);
  if (evt) {
    if (!evt.anomaly_details.original_severity) {
      evt.anomaly_details.original_severity = evt.anomaly_details.severity;
    }

    if (isAgreed === false) {
      // User flags as False Positive -> update severity to FALSE POSITIVE
      evt.anomaly_details.severity = "FALSE POSITIVE";
    } else {
      // User confirms prediction -> restore original severity
      evt.anomaly_details.severity = evt.anomaly_details.original_severity || "CRITICAL";
    }
  }

  renderMetrics();
  renderTriageTable(anomalyEvents);
  renderCharts();
}

// Calculate and Render Top Banner Metrics
function renderMetrics() {
  const criticalCount = anomalyEvents.filter(e => e.anomaly_details.severity === "CRITICAL").length;
  const highCount = anomalyEvents.filter(e => e.anomaly_details.severity === "HIGH").length;
  const avgRisk = (anomalyEvents.reduce((acc, curr) => acc + curr.anomaly_details.risk_score, 0) / anomalyEvents.length).toFixed(1);

  // Calculate Model Detection Accuracy & AI User Satisfaction Index
  const feedbackEntries = Object.values(userFeedbackStore);
  const totalVerified = feedbackEntries.length;

  let totalAgreed = 0;
  let satisfactionSumPct = 0;

  feedbackEntries.forEach(item => {
    if (item === true) {
      totalAgreed += 1;
      satisfactionSumPct += 100;
    } else if (item === false) {
      satisfactionSumPct += 0;
    } else if (typeof item === "object") {
      if (item.agree || item.category === "POSITIVE") totalAgreed += 1;
      satisfactionSumPct += (item.satisfaction_pct !== undefined ? item.satisfaction_pct : (item.agree ? 100 : 0));
    }
  });

  const accuracyRate = totalVerified > 0 ? ((totalAgreed / totalVerified) * 100).toFixed(1) : "100.0";
  const overallSatisfactionPct = totalVerified > 0 ? (satisfactionSumPct / totalVerified).toFixed(1) : "100.0";

  const accuracyEl = document.getElementById("metric-accuracy");
  if (accuracyEl) accuracyEl.textContent = `${accuracyRate}%`;
  
  const countEl = document.getElementById("metric-satisfaction-count");
  if (countEl) countEl.textContent = `Satisfaction Index: ${overallSatisfactionPct}% (${totalAgreed} Positive / ${totalVerified} Reviews)`;

  const criticalEl = document.getElementById("metric-critical");
  if (criticalEl) criticalEl.textContent = criticalCount;

  const highEl = document.getElementById("metric-high");
  if (highEl) highEl.textContent = highCount;

  const riskEl = document.getElementById("metric-risk");
  if (riskEl) riskEl.textContent = `${avgRisk} / 100`;
}

// Global Chart References
let severityChart = null;
let baselineChart = null;
let blastRadiusChart = null;

// Initialize Application on Load
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  renderMetrics();
  renderTriageTable(anomalyEvents);
  renderCharts();
  renderTopologyGraph();
  renderDbAnalysisScreen();
  renderBaselineProfilerScreen();
});

// Render SQLite DB Analysis & Rulebook Inspector Screen
function renderDbAnalysisScreen() {
  const select = document.getElementById("db-table-select");
  if (!select) return;

  const tableType = select.value;
  const titleEl = document.getElementById("db-table-title");
  const countEl = document.getElementById("db-table-count");
  const container = document.getElementById("db-table-container");

  if (tableType === "ingested_logs") {
    titleEl.textContent = "SQLite Table: Ingested Telemetry Logs & Auto-Classifications";
    countEl.textContent = `${anomalyEvents.length} Ingested Logs`;
    
    let html = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Event ID</th>
            <th>Event Timestamp</th>
            <th>Ingestion Date & Time</th>
            <th>Cloud</th>
            <th>Identity / User</th>
            <th>Scenario Trigger</th>
            <th>Risk Score</th>
            <th>Severity Classification</th>
          </tr>
        </thead>
        <tbody>
    `;

    anomalyEvents.forEach(e => {
      const sevClass = `badge-${e.anomaly_details.severity.toLowerCase().replace(/\s+/g, '-')}`;
      const ingTime = e.ingestion_timestamp || e.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19);
      html += `
        <tr>
          <td><code style="color:var(--text-cyber)">${e.event_id}</code></td>
          <td style="font-size:0.75rem">${e.timestamp}</td>
          <td style="font-size:0.75rem; color:var(--text-muted)">${ingTime}</td>
          <td>${e.cloud_provider}</td>
          <td class="table-user">${e.actor.user_name}</td>
          <td>${e.anomaly_details.scenario}</td>
          <td style="font-weight:700">${e.anomaly_details.risk_score}</td>
          <td><span class="badge ${sevClass}">${e.anomaly_details.severity}</span></td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;

  } else if (tableType === "entities") {
    titleEl.textContent = "SQLite Table: System Entities & IAM Identities (1,050 Rows)";
    countEl.textContent = "1,050 Rows";
    
    const sampleEntities = [
      { id: "USER_ALEX_MORGAN", name: "alex.morgan@cloudorg.internal", type: "USER", provider: "AWS", crit: 8.5, sens: 9.0, status: "COMPROMISED" },
      { id: "USER_SARAH_CHEN", name: "sarah.chen@cloudorg.internal", type: "USER", provider: "Azure", crit: 9.8, sens: 10.0, status: "COMPROMISED" },
      { id: "ROLE_SEC_DORMANT", name: "SecurityAnalyst-Dormant-Role", type: "ROLE", provider: "AWS", crit: 9.5, sens: 9.5, status: "DORMANT" },
      { id: "KMS_PROD_KEY_01", name: "kms-prod-data-encryption-key", type: "KEY_VAULT", provider: "AWS", crit: 10.0, sens: 10.0, status: "ACTIVE" },
      { id: "AWS_COMPUTE_DEVOPS_0012", name: "devops-compute-0012.cloudorg.internal", type: "COMPUTE", provider: "AWS", crit: 7.5, sens: 6.5, status: "ACTIVE" },
      { id: "AZURE_DB_FINANCE_0004", name: "finance-db-0004.cloudorg.internal", type: "DATABASE", provider: "Azure", crit: 9.9, sens: 10.0, status: "ACTIVE" }
    ];

    let html = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Entity ID</th>
            <th>Name</th>
            <th>Type</th>
            <th>Provider</th>
            <th>Criticality</th>
            <th>Sensitivity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
    `;

    sampleEntities.forEach(n => {
      html += `
        <tr>
          <td><code>${n.id}</code></td>
          <td class="table-user">${n.name}</td>
          <td><span style="color:var(--border-accent)">${n.type}</span></td>
          <td>${n.provider}</td>
          <td>${n.crit}</td>
          <td>${n.sens}</td>
          <td><span class="badge ${n.status === 'COMPROMISED' ? 'badge-critical' : (n.status === 'DORMANT' ? 'badge-medium' : 'badge-low')}">${n.status}</span></td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;

  } else if (tableType === "relationships") {
    titleEl.textContent = "SQLite Table: Topology Relationship Edges (2,593 Rows)";
    countEl.textContent = "2,593 Rows";

    const sampleRels = [
      { src: "USER_ALEX_MORGAN", tgt: "ROLE_SEC_DORMANT", rel: "ASSUMES_ROLE", hop: 1 },
      { src: "ROLE_SEC_DORMANT", tgt: "KMS_PROD_KEY_01", rel: "READS_SECRET", hop: 1 },
      { src: "USER_SARAH_CHEN", tgt: "ROLE_AZURE_GLOBAL_ADMIN", rel: "MEMBER_OF", hop: 1 },
      { src: "ROLE_AZURE_GLOBAL_ADMIN", tgt: "KEYVAULT_FINANCIAL_SECRETS", rel: "READS_SECRET", hop: 1 },
      { src: "USER_SECOPS_AUTOMATION", tgt: "CLOUDTRAIL_AUDIT_TRAIL", rel: "DELETED_LOGS", hop: 1 }
    ];

    let html = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Source Entity ID</th>
            <th>Target Entity ID</th>
            <th>Relationship Type</th>
            <th>Hop Distance</th>
          </tr>
        </thead>
        <tbody>
    `;

    sampleRels.forEach(r => {
      html += `
        <tr>
          <td class="table-user">${r.src}</td>
          <td style="color:var(--text-cyber)">${r.tgt}</td>
          <td><code>${r.rel}</code></td>
          <td>${r.hop}</td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;

  } else if (tableType === "identity_privileges") {
    titleEl.textContent = "SQLite Table: IAM Privileges & Role Entitlements (789 Rows)";
    countEl.textContent = "789 Rows";

    const samplePrivs = [
      { id: "USER_ALEX_MORGAN", perm: "kms:Decrypt", dormant: 1, last: "2026-08-18T08:14:00Z" },
      { id: "USER_SARAH_CHEN", perm: "KeyVault.Secrets.Read", dormant: 0, last: "2026-08-18T09:30:00Z" },
      { id: "USER_SVC_CI_DEPLOYER", perm: "iam:PutUserPolicy", dormant: 1, last: "2026-08-18T10:05:00Z" },
      { id: "USER_DEVOPS_LEAD", perm: "storage.objects.get", dormant: 0, last: "2026-08-18T11:12:00Z" }
    ];

    let html = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Identity / Role ID</th>
            <th>Permission Name</th>
            <th>Dormant Privilege Flag</th>
            <th>Last Used Timestamp</th>
          </tr>
        </thead>
        <tbody>
    `;

    samplePrivs.forEach(p => {
      html += `
        <tr>
          <td class="table-user">${p.id}</td>
          <td><code>${p.perm}</code></td>
          <td><span class="badge ${p.dormant === 1 ? 'badge-medium' : 'badge-low'}">${p.dormant === 1 ? 'DORMANT' : 'ACTIVE'}</span></td>
          <td style="font-size:0.75rem">${p.last}</td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;

  } else if (tableType === "rulebook") {
    titleEl.textContent = "Configurable SIEM Log Detection Rulebook (rulebook_config.json)";
    countEl.textContent = "18 Active Rules Catalog";

    container.innerHTML = `
      <pre class="code-block" style="max-height:400px; font-size:0.8rem">{
  "rulebook_metadata": {
    "name": "Cloud Access Anomaly & Threat Detection Rulebook",
    "version": "2.5.0",
    "total_rules": 18
  },
  "false_positive_rules": [
    { "rule_id": "FP-RULE-001", "name": "Verified Non-Malicious Operational Baseline" },
    { "rule_id": "FP-RULE-002", "name": "Scheduled CI/CD Deployment Service Account" },
    { "rule_id": "FP-RULE-003", "name": "Authorized Vulnerability & Compliance Security Scanner" },
    { "rule_id": "FP-RULE-004", "name": "Approved Maintenance Window Infrastructure Update" },
    { "rule_id": "FP-RULE-005", "name": "Automated Synthetic Health Check Monitor" }
  ],
  "threat_anomaly_rules": [
    { "rule_id": "THREAT-RULE-001", "name": "Impossible Travel Velocity Threshold", "mitre": "T1078.004", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-002", "name": "MFA Push Fatigue Prompt Spamming", "mitre": "T1621", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-003", "name": "Dormant Administrative Account Reactivation", "mitre": "T1098.001", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-004", "name": "Mass Cloud Data Storage Exfiltration", "mitre": "T1567.002", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-005", "name": "Audit Log Deletion & Defense Evasion", "mitre": "T1562.001", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-006", "name": "Cloud Password Spraying Attack Burst", "mitre": "T1110.003", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-007", "name": "Unassigned KMS Master Encryption Key Access", "mitre": "T1552.004", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-008", "name": "Cross-Account IAM Role Assumption Drift", "mitre": "T1078.004", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-009", "name": "S3 Bucket Public Access Block Removal", "mitre": "T1530", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-010", "name": "Azure Key Vault Bulk Secret Export Burst", "mitre": "T1555.006", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-011", "name": "Root Account Authentication without Hardware MFA", "mitre": "T1078.001", "severity": "CRITICAL" },
    { "rule_id": "THREAT-RULE-012", "name": "Anonymized Proxy & TOR Exit Node Access", "mitre": "T1090.003", "severity": "HIGH" },
    { "rule_id": "THREAT-RULE-013", "name": "Unusual Off-Hours Production API Access", "mitre": "T1078", "severity": "MEDIUM" }
  ]
}</pre>
    `;
  }
}

// Render Enterprise Topology Graph & Blast Radius CTE Calculator
function renderTopologyGraph() {
  const select = document.getElementById("topology-entity-select");
  if (!select) return;

  const entityId = select.value;
  const nodeList = document.getElementById("topology-node-list");
  const summaryBox = document.getElementById("topology-blast-summary");

  // Sample topology connections simulated from caad_topology.db
  const topologyData = {
    "USER_ALEX_MORGAN": {
      blast_score: 3878.74,
      reachable_count: 357,
      nodes: [
        { id: "ROLE_SEC_DORMANT", type: "ROLE", hop: 1, rel: "ASSUMES_ROLE", crit: 9.5, sens: 9.5 },
        { id: "KMS_PROD_KEY_01", type: "KEY_VAULT", hop: 2, rel: "READS_SECRET", crit: 10.0, sens: 10.0 },
        { id: "AWS_DB_FINANCE_001", type: "DATABASE", hop: 3, rel: "HAS_ACCESS_TO", crit: 9.8, sens: 10.0 },
        { id: "AWS_STORAGE_BACKUP_005", type: "STORAGE", hop: 4, rel: "CONNECTS_TO", crit: 8.5, sens: 9.0 },
        { id: "AWS_COMPUTE_DEVOPS_012", type: "COMPUTE", hop: 5, rel: "DEPLOYS_TO", crit: 7.0, sens: 6.5 }
      ]
    },
    "USER_SARAH_CHEN": {
      blast_score: 4120.50,
      reachable_count: 412,
      nodes: [
        { id: "ROLE_AZURE_GLOBAL_ADMIN", type: "ROLE", hop: 1, rel: "MEMBER_OF", crit: 10.0, sens: 10.0 },
        { id: "KEYVAULT_FINANCIAL_SECRETS", type: "KEY_VAULT", hop: 2, rel: "READS_SECRET", crit: 10.0, sens: 10.0 },
        { id: "APP_PAYMENT_GATEWAY", type: "APPLICATION", hop: 3, rel: "CONNECTS_TO", crit: 9.5, sens: 9.8 },
        { id: "AZURE_DB_PAYMENTS_002", type: "DATABASE", hop: 4, rel: "READS_SECRET", crit: 9.9, sens: 10.0 },
        { id: "AZURE_STORAGE_LOGS_088", type: "STORAGE", hop: 5, rel: "CONNECTS_TO", crit: 6.0, sens: 5.0 }
      ]
    },
    "USER_SVC_CI_DEPLOYER": {
      blast_score: 4890.10,
      reachable_count: 489,
      nodes: [
        { id: "ROLE_BACKDOOR_ADMIN", type: "ROLE", hop: 1, rel: "ASSUMES_ROLE", crit: 10.0, sens: 10.0 },
        { id: "EC2_DEVOPS_CI_RUNNER", type: "COMPUTE", hop: 2, rel: "HAS_ACCESS_TO", crit: 7.5, sens: 6.0 },
        { id: "AWS_APPLICATION_DEPLOYER", type: "APPLICATION", hop: 3, rel: "DEPLOYS_TO", crit: 9.0, sens: 8.5 },
        { id: "AWS_KMS_MASTER_KEY_001", type: "KEY_VAULT", hop: 4, rel: "READS_SECRET", crit: 10.0, sens: 10.0 },
        { id: "AWS_STORAGE_CONTAINER_99", type: "STORAGE", hop: 5, rel: "CONNECTS_TO", crit: 8.0, sens: 8.0 }
      ]
    },
    "USER_DEVOPS_LEAD": {
      blast_score: 3950.25,
      reachable_count: 382,
      nodes: [
        { id: "GCP_BUCKET_CUSTOMER_BACKUPS", type: "STORAGE", hop: 1, rel: "EXFILTRATED_FROM", crit: 9.5, sens: 9.5 },
        { id: "BIGQUERY_ANALYTICS_DB", type: "DATABASE", hop: 2, rel: "HAS_ACCESS_TO", crit: 9.8, sens: 10.0 },
        { id: "GCP_SERVICE_ACCT_ANALYTICS", type: "SERVICE_ACCOUNT", hop: 3, rel: "MEMBER_OF", crit: 8.5, sens: 8.5 },
        { id: "GCP_COMPUTE_ENGINE_04", type: "COMPUTE", hop: 4, rel: "CONNECTS_TO", crit: 7.0, sens: 6.0 },
        { id: "GCP_KMS_ENCRYPTION_KEY", type: "KEY_VAULT", hop: 5, rel: "READS_SECRET", crit: 10.0, sens: 10.0 }
      ]
    },
    "USER_SECOPS_AUTOMATION": {
      blast_score: 5100.80,
      reachable_count: 512,
      nodes: [
        { id: "CLOUDTRAIL_AUDIT_TRAIL", type: "APPLICATION", hop: 1, rel: "DELETED_LOGS", crit: 10.0, sens: 10.0 },
        { id: "S3_AUDIT_LOG_BUCKET", type: "STORAGE", hop: 2, rel: "CONNECTS_TO", crit: 10.0, sens: 10.0 },
        { id: "AWS_ROLE_SECURITY_ADMIN", type: "ROLE", hop: 3, rel: "MEMBER_OF", crit: 10.0, sens: 10.0 },
        { id: "AWS_EC2_SECURITY_NODE_01", type: "COMPUTE", hop: 4, rel: "DEPLOYS_TO", crit: 8.5, sens: 8.0 },
        { id: "AWS_DATABASE_AUDIT_REPLICAS", type: "DATABASE", hop: 5, rel: "HAS_ACCESS_TO", crit: 9.5, sens: 9.5 }
      ]
    }
  };

  const current = topologyData[entityId] || topologyData["USER_ALEX_MORGAN"];

  // Render Table
  let html = `
    <table class="soc-table">
      <thead>
        <tr>
          <th>Hop</th>
          <th>Entity ID</th>
          <th>Type</th>
          <th>Edge Relationship</th>
          <th>Criticality x Sensitivity</th>
        </tr>
      </thead>
      <tbody>
  `;

  current.nodes.forEach(n => {
    html += `
      <tr>
        <td><span class="badge badge-info">Hop ${n.hop}</span></td>
        <td class="table-user">${n.id}</td>
        <td><span style="color:var(--border-accent)">${n.type}</span></td>
        <td><code>${n.rel}</code></td>
        <td style="color:var(--text-primary); font-weight:700">${n.crit} x ${n.sens}</td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  if (nodeList) nodeList.innerHTML = html;

  // Render Summary
  if (summaryBox) {
    summaryBox.innerHTML = `
      <strong>Target Identity:</strong> <code>${entityId}</code><br>
      <strong>Total Connected 1,000+ Systems:</strong> <span style="color:var(--border-accent); font-weight:700">${current.reachable_count} entities reachable in 5 hops</span><br>
      <strong>Calculated Blast Radius Score:</strong> <span style="color:var(--severity-critical); font-size:1.4rem; font-weight:800">${current.blast_score}</span><br>
      <p style="font-size:0.8rem; color:var(--text-muted); margin-top:0.5rem">
        Traversed via SQLite 5-Hop Recursive CTE algorithm in <code>caad_topology.db</code>. Score is weighted by criticality, data sensitivity, and hop distance attenuation.
      </p>
    `;
  }

  // Render Visual Node Graph Canvas
  drawNodeGraphCanvas(entityId, current);
}

// Interactive HTML5 Canvas Node Graph Engine for Blast Radius
let activeGraphNodes = [];

function drawNodeGraphCanvas(entryEntityId, currentData) {
  const canvas = document.getElementById("blast-node-canvas");
  if (!canvas) return;

  // Use setTimeout to ensure DOM reflow has completed if tab was just switched
  setTimeout(() => {
    const parent = canvas.parentElement;
    const parentWidth = parent ? parent.clientWidth : 0;
    const parentHeight = parent ? parent.clientHeight : 0;
    const rect = canvas.getBoundingClientRect();
    
    canvas.width = (rect.width && rect.width > 100) ? rect.width : (parentWidth > 100 ? parentWidth : 800);
    canvas.height = (rect.height && rect.height > 100) ? rect.height : (parentHeight > 100 ? parentHeight : 380);

    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;

    ctx.clearRect(0, 0, width, height);

    // Define Nodes Array with Coordinates
    activeGraphNodes = [];

    // Entry Node (Center)
    const entryNode = {
      id: entryEntityId,
      label: entryEntityId.replace("USER_", ""),
      type: "ENTRY",
      x: centerX,
      y: centerY,
      radius: 22,
      color: "#ef4444",
      crit: 10.0,
      sens: 10.0,
      hop: 0
    };
    activeGraphNodes.push(entryNode);

    // Downstream Radial Layout for Hops
    const nodes = currentData.nodes;
    const totalHopNodes = nodes.length;
    
    nodes.forEach((n, idx) => {
      const angle = (idx / totalHopNodes) * Math.PI * 2 - Math.PI / 2;
      const distance = 85 + (n.hop * 48); // Radial distance based on hop depth
      const nx = centerX + Math.cos(angle) * distance;
      const ny = centerY + Math.sin(angle) * distance;

      let ncolor = "#3b82f6";
      if (n.type === "ROLE") ncolor = "#eab308";
      else if (n.type === "KEY_VAULT") ncolor = "#00f0ff";
      else if (n.type === "DATABASE") ncolor = "#10b981";
      else if (n.type === "STORAGE") ncolor = "#a855f7";

      activeGraphNodes.push({
        id: n.id,
        label: n.id,
        type: n.type,
        rel: n.rel,
        x: nx,
        y: ny,
        radius: 14 - (n.hop * 1),
        color: ncolor,
        crit: n.crit,
        sens: n.sens,
        hop: n.hop
      });
    });

    // Draw Edge Connection Lines
    for (let i = 1; i < activeGraphNodes.length; i++) {
      const targetNode = activeGraphNodes[i];
      const prevNode = i === 1 ? activeGraphNodes[0] : activeGraphNodes[i - 1];

      ctx.beginPath();
      ctx.moveTo(prevNode.x, prevNode.y);
      ctx.lineTo(targetNode.x, targetNode.y);
      ctx.strokeStyle = "rgba(0, 240, 255, 0.4)";
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Edge Label
      const midX = (prevNode.x + targetNode.x) / 2;
      const midY = (prevNode.y + targetNode.y) / 2;
      ctx.fillStyle = "#64748b";
      ctx.font = "9px 'JetBrains Mono', monospace";
      ctx.fillText(targetNode.rel || "CONNECTS_TO", midX, midY);
    }

    // Draw Nodes
    activeGraphNodes.forEach(n => {
      // Glow effect
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius + 4, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0, 240, 255, 0.25)";
      ctx.fill();

      // Solid Circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.shadowColor = n.color;
      ctx.shadowBlur = 10;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Border
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Node Label
      ctx.fillStyle = "#f8fafc";
      ctx.font = n.hop === 0 ? "bold 11px 'Inter', sans-serif" : "10px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.fillText(n.label, n.x, n.y + n.radius + 14);
    });

    // Setup Canvas Hover Interaction
    canvas.onmousemove = function(e) {
      const mouseX = e.offsetX;
      const mouseY = e.offsetY;
      let hovered = false;

      activeGraphNodes.forEach(n => {
        const dist = Math.hypot(mouseX - n.x, mouseY - n.y);
        if (dist <= n.radius + 5) {
          canvas.style.cursor = "pointer";
          hovered = true;
          
          // Draw Tooltip
          ctx.fillStyle = "rgba(11, 16, 27, 0.95)";
          ctx.strokeStyle = "#00f0ff";
          ctx.lineWidth = 1;
          ctx.fillRect(mouseX + 10, mouseY + 10, 220, 75);
          ctx.strokeRect(mouseX + 10, mouseY + 10, 220, 75);

          ctx.fillStyle = "#00f0ff";
          ctx.font = "bold 11px sans-serif";
          ctx.textAlign = "left";
          ctx.fillText(`${n.id}`, mouseX + 18, mouseY + 28);

          ctx.fillStyle = "#f8fafc";
          ctx.font = "10px sans-serif";
          ctx.fillText(`Type: ${n.type} | Hop Depth: ${n.hop}`, mouseX + 18, mouseY + 44);
          ctx.fillText(`Crit: ${n.crit} | Sensitivity: ${n.sens}`, mouseX + 18, mouseY + 58);
          ctx.fillText(`Edge Rel: ${n.rel || 'ENTRY_POINT'}`, mouseX + 18, mouseY + 72);
        }
      });

      if (!hovered) {
        canvas.style.cursor = "default";
      }
    };
  }, 50);
}

// Global Tab Switching Engine
function switchTab(tabId) {
  try {
    const tabs = document.querySelectorAll(".tab-btn");
    const panes = document.querySelectorAll(".tab-pane");

    tabs.forEach(t => {
      if (t.dataset.tab === tabId) {
        t.classList.add("active");
      } else {
        t.classList.remove("active");
      }
    });

    panes.forEach(p => {
      if (p.id === tabId) {
        p.classList.add("active");
        p.style.display = "block";
      } else {
        p.classList.remove("active");
        p.style.display = "none";
      }
    });

    // Trigger tab rendering after DOM layout updates
    setTimeout(() => {
      try {
        if (tabId === "topology") {
          renderTopologyGraph();
        } else if (tabId === "db-analysis") {
          renderDbAnalysisScreen();
        } else if (tabId === "baseline") {
          renderBaselineProfilerScreen();
        }
      } catch (e) {
        console.error("Tab content render error:", e);
      }
    }, 10);
  } catch (err) {
    console.error(`Error switching to tab ${tabId}:`, err);
  }
}

function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", (e) => {
      e.preventDefault();
      switchTab(tab.dataset.tab);
    });
  });
}

// Global Chart References for Baseline Profiler
let baselineProfilerChart = null;
let profilerMatrixChart = null;

// Render Behavioral Baseline Profiler Screen
function renderBaselineProfilerScreen() {
  const userSelect = document.getElementById("baseline-user-select");
  if (!userSelect) return;

  // Populate User Options if empty
  if (userSelect.children.length === 0) {
    let optionsHtml = "";
    anomalyEvents.forEach(e => {
      optionsHtml += `<option value="${e.event_id}">${e.actor.user_name} (${e.cloud_provider} - ${e.anomaly_details.scenario})</option>`;
    });
    userSelect.innerHTML = optionsHtml;
  }

  const selectedEvtId = userSelect.value || anomalyEvents[0].event_id;
  const evt = anomalyEvents.find(e => e.event_id === selectedEvtId) || anomalyEvents[0];

  const baseMean = evt.anomaly_details.baseline_90d_avg_daily_events || 45;
  const sessionVol = evt.anomaly_details.session_30m_event_count || 310;
  const deltaRatio = evt.anomaly_details.baseline_delta_ratio || (sessionVol / Math.max(1, baseMean)).toFixed(2);
  const anomalyCutoff = Math.round(baseMean * 2.5);

  const baseMeanEl = document.getElementById("prof-base-mean");
  if (baseMeanEl) baseMeanEl.textContent = baseMean;

  const sessionVolEl = document.getElementById("prof-session-vol");
  if (sessionVolEl) sessionVolEl.textContent = sessionVol;

  const deltaRatioEl = document.getElementById("prof-delta-ratio");
  if (deltaRatioEl) deltaRatioEl.textContent = `${deltaRatio}x`;

  const cutoffEl = document.getElementById("prof-cutoff");
  if (cutoffEl) cutoffEl.textContent = `${anomalyCutoff} events/day`;

  // Render Chart.js Profiler Chart
  const ctx = document.getElementById("chart-baseline-profiler");
  if (ctx && typeof Chart !== "undefined") {
    if (baselineProfilerChart) baselineProfilerChart.destroy();

    baselineProfilerChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["90-Day Baseline Daily Mean", "Upper Anomaly Cutoff (+3σ)", "Observed 30-Min Burst"],
        datasets: [{
          label: "Event Volume Count",
          data: [baseMean, anomalyCutoff, sessionVol],
          backgroundColor: [
            "rgba(59, 130, 246, 0.6)",
            "rgba(234, 179, 8, 0.6)",
            "rgba(239, 68, 68, 0.8)"
          ],
          borderColor: ["#3b82f6", "#eab308", "#ef4444"],
          borderWidth: 1.5,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }

  // Render Hourly Access Profile Distribution Table
  const hourlyContainer = document.getElementById("prof-hourly-container");
  if (hourlyContainer) {
    const hourlyData = [
      { hour: "00:00 - 04:00 (Off-Hours)", typical: "2 - 5 events", observed: `${Math.round(sessionVol * 0.4)} events`, status: "ANOMALOUS SPIKE", isSpike: true },
      { hour: "04:00 - 08:00 (Early Shift)", typical: "5 - 10 events", observed: "8 events", status: "NORMAL", isSpike: false },
      { hour: "08:00 - 12:00 (Core Hours)", typical: "20 - 45 events", observed: "32 events", status: "NORMAL", isSpike: false },
      { hour: "12:00 - 16:00 (Core Hours)", typical: "15 - 40 events", observed: "28 events", status: "NORMAL", isSpike: false },
      { hour: "16:00 - 20:00 (Evening Shift)", typical: "5 - 15 events", observed: "11 events", status: "NORMAL", isSpike: false },
      { hour: "20:00 - 24:00 (Night Hours)", typical: "1 - 5 events", observed: `${Math.round(sessionVol * 0.6)} events`, status: "ANOMALOUS SPIKE", isSpike: true }
    ];

    let html = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Time Window</th>
            <th>Typical 90-Day Baseline</th>
            <th>Observed Window Events</th>
            <th>Status Evaluation</th>
          </tr>
        </thead>
        <tbody>
    `;

    hourlyData.forEach(row => {
      html += `
        <tr>
          <td><strong style="color:var(--text-primary)">${row.hour}</strong></td>
          <td style="color:var(--text-secondary)">${row.typical}</td>
          <td style="font-weight:700; color:${row.isSpike ? '#ef4444' : '#38bdf8'}">${row.observed}</td>
          <td><span class="badge ${row.isSpike ? 'badge-critical' : 'badge-low'}">${row.status}</span></td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    hourlyContainer.innerHTML = html;
  }

  // Render Chart 3: Risk Score vs Blast Radius Quadrant Matrix Scatter Plot
  const ctxMatrix = document.getElementById("chart-prof-risk-blast");
  if (ctxMatrix && typeof Chart !== "undefined") {
    if (profilerMatrixChart) profilerMatrixChart.destroy();

    const scatterPoints = anomalyEvents.map(e => ({
      x: e.anomaly_details.risk_score,
      y: e.anomaly_details.blast_radius_score,
      user: e.actor.user_name,
      severity: e.anomaly_details.severity
    }));

    profilerMatrixChart = new Chart(ctxMatrix, {
      type: "scatter",
      data: {
        datasets: [{
          label: "Identity Telemetry Anomalies",
          data: scatterPoints,
          backgroundColor: scatterPoints.map(p => {
            if (p.severity === "CRITICAL") return "#ef4444";
            if (p.severity === "HIGH") return "#f97316";
            if (p.severity === "FALSE POSITIVE") return "#c084fc";
            return "#eab308";
          }),
          pointRadius: 7,
          pointHoverRadius: 10
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (context) => {
                const pt = context.raw;
                return `${pt.user}: Risk ${pt.x} | Blast ${pt.y} (${pt.severity})`;
              }
            }
          }
        },
        scales: {
          x: {
            title: { display: true, text: "UEBA ML Risk Score (0 - 100)", color: "#38bdf8" },
            ticks: { color: "#94a3b8" },
            grid: { color: "rgba(255,255,255,0.05)" },
            min: 0,
            max: 100
          },
          y: {
            title: { display: true, text: "Blast Radius Score (0 - 100)", color: "#38bdf8" },
            ticks: { color: "#94a3b8" },
            grid: { color: "rgba(255,255,255,0.05)" },
            min: 0,
            max: 100
          }
        }
      }
    });
  }

  // Render Quadrant Classification Table
  const matrixContainer = document.getElementById("prof-matrix-table-container");
  if (matrixContainer) {
    let tableHtml = `
      <table class="soc-table">
        <thead>
          <tr>
            <th>Identity / User</th>
            <th>ML Risk</th>
            <th>Blast Score</th>
            <th>Quadrant Classification</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
    `;

    anomalyEvents.forEach(e => {
      const risk = e.anomaly_details.risk_score;
      const blast = e.anomaly_details.blast_radius_score;
      let quadrant = "";
      let quadBadge = "";
      let action = "";

      if (risk >= 50 && blast >= 50) {
        quadrant = "CRITICAL THREAT ZONE";
        quadBadge = "badge-critical";
        action = "Immediate Isolation & Revoke Tokens";
      } else if (risk < 50 && blast >= 50) {
        quadrant = "HIGH ENTITLEMENT RISK";
        quadBadge = "badge-high";
        action = "Audit Dormant Admin Permissions";
      } else if (risk >= 50 && blast < 50) {
        quadrant = "ISOLATED ANOMALY";
        quadBadge = "badge-medium";
        action = "Reset User MFA & Password";
      } else {
        quadrant = "OPERATIONAL BASELINE";
        quadBadge = "badge-false-positive";
        action = "Verify Operational Baseline";
      }

      tableHtml += `
        <tr>
          <td class="table-user">${e.actor.user_name}</td>
          <td style="font-weight:700">${risk}</td>
          <td style="font-weight:700">${blast}</td>
          <td><span class="badge ${quadBadge}">${quadrant}</span></td>
          <td style="font-size:0.75rem">${action}</td>
        </tr>
      `;
    });

    tableHtml += `</tbody></table>`;
    matrixContainer.innerHTML = tableHtml;
  }
}

// Render Triage Table with Filter and Search Support
function renderTriageTable(events) {
  const tbody = document.getElementById("triage-tbody");
  if (!tbody) return;
  
  tbody.innerHTML = "";
  
  events.forEach(evt => {
    const tr = document.createElement("tr");
    const severityClass = `badge-${evt.anomaly_details.severity.toLowerCase().replace(/\s+/g, '-')}`;
    const feedbackStatus = userFeedbackStore[evt.event_id];
    
    let agreementHtml = "";
    if (feedbackStatus === true) {
      agreementHtml = `<span class="badge badge-info" style="cursor:pointer" onclick="recordAnalystFeedback('${evt.event_id}', false)" title="Confirmed Prediction - Click to mark False Positive">👍 Confirmed</span>`;
    } else if (feedbackStatus === false) {
      agreementHtml = `<span class="badge badge-false-positive" style="cursor:pointer" onclick="recordAnalystFeedback('${evt.event_id}', true)" title="Flagged False Positive - Click to confirm">👎 False Positive</span>`;
    } else {
      agreementHtml = `
        <button class="btn" style="padding:0.2rem 0.5rem; font-size:0.75rem" onclick="recordAnalystFeedback('${evt.event_id}', true)" title="Agree / Confirm">👍</button>
        <button class="btn" style="padding:0.2rem 0.5rem; font-size:0.75rem" onclick="recordAnalystFeedback('${evt.event_id}', false)" title="Disagree / False Positive">👎</button>
      `;
    }

    const ingestionTime = evt.ingestion_timestamp || evt.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19);

    tr.innerHTML = `
      <td><span class="badge ${severityClass}">${evt.anomaly_details.severity}</span></td>
      <td><span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace">${ingestionTime}</span></td>
      <td class="table-user">${evt.actor.user_name}</td>
      <td><span style="color:var(--text-cyber)">${evt.cloud_provider}</span></td>
      <td>${evt.anomaly_details.scenario}</td>
      <td><code>${evt.src_endpoint.ip}</code> (${evt.src_endpoint.country})</td>
      <td style="font-weight:700; color:${evt.anomaly_details.severity === 'FALSE POSITIVE' ? '#c084fc' : (evt.anomaly_details.risk_score > 90 ? '#ef4444' : '#f97316')}">${evt.anomaly_details.risk_score}</td>
      <td>${agreementHtml}</td>
      <td>
        <button class="btn btn-primary" onclick="openRemediationModal('${evt.event_id}')">Playbook</button>
        <button class="btn" onclick="openDetailModal('${evt.event_id}')">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Helper to get currently filtered anomaly events
function getFilteredEvents() {
  const query = (document.getElementById("search-input") ? document.getElementById("search-input").value : "").toLowerCase();
  const severityFilter = document.getElementById("severity-select") ? document.getElementById("severity-select").value : "ALL";
  const providerFilter = document.getElementById("provider-select") ? document.getElementById("provider-select").value : "ALL";

  return anomalyEvents.filter(evt => {
    const matchesQuery = evt.actor.user_name.toLowerCase().includes(query) ||
                         evt.anomaly_details.scenario.toLowerCase().includes(query) ||
                         evt.src_endpoint.ip.includes(query) ||
                         evt.src_endpoint.country.toLowerCase().includes(query);
    const matchesSeverity = severityFilter === "ALL" || evt.anomaly_details.severity === severityFilter;
    const matchesProvider = providerFilter === "ALL" || evt.cloud_provider.includes(providerFilter);

    return matchesQuery && matchesSeverity && matchesProvider;
  });
}

// Filter Events based on search bar & dropdowns
function filterEvents() {
  const filtered = getFilteredEvents();
  renderTriageTable(filtered);
}

// Export Filtered Telemetry Table with Full Inspect Content & In-Report Interactive Filters
function exportFilteredTelemetryReport() {
  const filtered = getFilteredEvents();
  if (!filtered || filtered.length === 0) {
    alert("No anomaly records match the active filter criteria to export.");
    return;
  }

  const query = document.getElementById("search-input") ? document.getElementById("search-input").value : "None";
  const severityFilter = document.getElementById("severity-select") ? document.getElementById("severity-select").value : "ALL";
  const providerFilter = document.getElementById("provider-select") ? document.getElementById("provider-select").value : "ALL";
  const timestamp = new Date().toISOString();

  // Calculate Filtered Summary Metrics
  const avgRisk = (filtered.reduce((acc, curr) => acc + curr.anomaly_details.risk_score, 0) / filtered.length).toFixed(1);
  const criticalCount = filtered.filter(e => e.anomaly_details.severity === "CRITICAL").length;
  const highCount = filtered.filter(e => e.anomaly_details.severity === "HIGH").length;
  const fpCount = filtered.filter(e => e.anomaly_details.severity === "FALSE POSITIVE").length;

  // Build Tabulated Telemetry Rows with Data Attributes for In-Report Filtering
  let summaryRowsHtml = filtered.map(e => `
    <tr class="exp-table-row"
        data-event-id="${e.event_id}"
        data-cloud="${e.cloud_provider}"
        data-user="${e.actor.user_name}"
        data-country="${e.src_endpoint.country}"
        data-scenario="${e.anomaly_details.scenario}"
        data-severity="${e.anomaly_details.severity}">
      <td style="font-family:monospace; font-weight:bold">${e.event_id}</td>
      <td style="font-size:0.8rem">${e.timestamp}</td>
      <td style="font-size:0.8rem; color:#64748b; font-family:monospace">${e.ingestion_timestamp || e.timestamp}</td>
      <td><strong>${e.cloud_provider}</strong></td>
      <td style="font-family:monospace; color:#0284c7">${e.actor.user_name}</td>
      <td>${e.anomaly_details.scenario}</td>
      <td style="font-family:monospace">${e.src_endpoint.ip} (${e.src_endpoint.country})</td>
      <td style="font-weight:bold; text-align:center">${e.anomaly_details.risk_score}</td>
      <td style="font-weight:bold; text-align:center">${e.anomaly_details.blast_radius_score}</td>
      <td style="text-align:center"><span class="badge badge-${e.anomaly_details.severity.toLowerCase().replace(/\s+/g, '-')}">${e.anomaly_details.severity}</span></td>
    </tr>
  `).join("");

  // Build Detailed Inspect Content Sections with Data Attributes for In-Report Filtering
  let inspectSectionsHtml = filtered.map((e, index) => {
    const aiSummaryText = e.anomaly_details.genai_explanation;
    const mitreViewHtml = buildMitreDefenseView(e);

    return `
      <div class="exp-inspect-card"
           data-event-id="${e.event_id}"
           data-cloud="${e.cloud_provider}"
           data-user="${e.actor.user_name}"
           data-country="${e.src_endpoint.country}"
           data-scenario="${e.anomaly_details.scenario}"
           data-severity="${e.anomaly_details.severity}"
           style="page-break-inside:avoid; border:1px solid #cbd5e1; border-radius:8px; padding:1.25rem; margin-bottom:1.5rem; background:#ffffff; box-shadow:0 2px 8px rgba(0,0,0,0.05)">
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #0284c7; padding-bottom:0.5rem; margin-bottom:1rem">
          <h3 style="margin:0; color:#0f172a; font-size:1.1rem">
            #${index + 1} Inspection Details: <span style="color:#0284c7">${e.event_id}</span> - ${e.actor.user_name}
          </h3>
          <span class="badge badge-${e.anomaly_details.severity.toLowerCase().replace(/\s+/g, '-')}">${e.anomaly_details.severity}</span>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem; margin-bottom:1rem; font-size:0.85rem">
          <div>
            <strong>Cloud Provider:</strong> ${e.cloud_provider}<br>
            <strong>Category / Class:</strong> ${e.category_name} / ${e.class_name}<br>
            <strong>Origin Endpoint:</strong> ${e.src_endpoint.ip} (${e.src_endpoint.city}, ${e.src_endpoint.country})<br>
            <strong>ISP Provider:</strong> ${e.src_endpoint.isp}
          </div>
          <div>
            <strong>UEBA ML Risk Score:</strong> ${e.anomaly_details.risk_score} / 100<br>
            <strong>Blast Radius Score:</strong> ${e.anomaly_details.blast_radius_score} / 100<br>
            <strong>30m Session Velocity Spike:</strong> ${e.anomaly_details.session_30m_event_count} events (${e.anomaly_details.baseline_delta_ratio}x baseline)<br>
            <strong>90-Day Daily Baseline:</strong> ${e.anomaly_details.baseline_90d_avg_daily_events} events/day
          </div>
        </div>

        <!-- AI Plain English Summary -->
        <div style="background:#f8fafc; border-left:4px solid #0284c7; padding:0.75rem 1rem; margin-bottom:1rem; border-radius:0 6px 6px 0">
          <strong style="color:#0284c7; font-size:0.85rem">🤖 AI Plain English Incident Summary & Baseline Delta Analysis:</strong>
          <p style="margin:0.4rem 0 0 0; font-size:0.88rem; line-height:1.5; color:#334155">${aiSummaryText}</p>
        </div>

        <!-- MITRE ATT&CK & D3FEND Content -->
        <div style="margin-bottom:1rem">
          ${mitreViewHtml}
        </div>

        <!-- 1-Click SOC Remediation Playbook -->
        <div style="background:#0f172a; color:#f8fafc; border-radius:6px; padding:0.75rem 1rem">
          <strong style="color:#38bdf8; font-size:0.85rem">⚡ SOC Remediation Action: ${e.anomaly_details.remediation_playbook.action}</strong>
          <pre style="margin:0.4rem 0 0 0; font-family:monospace; font-size:0.8rem; background:#020617; padding:0.5rem; border-radius:4px; color:#4ade80; overflow-x:auto">${e.anomaly_details.remediation_playbook.cli_command}</pre>
        </div>
      </div>
    `;
  }).join("");

  // Complete Interactive HTML Document String
  const reportHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Interactive Cloud Anomaly Telemetry & Inspection Report</title>
  <style>
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 2rem; }
    h1 { color: #0284c7; margin-bottom: 0.2rem; font-size: 1.6rem; }
    .header-sub { color: #64748b; font-size: 0.88rem; margin-bottom: 1.5rem; }
    .meta-box { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; display: flex; gap: 2rem; font-size: 0.88rem; }
    
    /* Interactive Filter Bar Styles inside Exported Document */
    .report-filter-bar { background: #ffffff; border: 2px solid #0284c7; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.08); }
    .filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.75rem; margin-top: 0.5rem; }
    .filter-group { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8rem; font-weight: bold; color: #334155; }
    .filter-input { padding: 0.45rem 0.6rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.82rem; outline: none; }
    .filter-input:focus { border-color: #0284c7; box-shadow: 0 0 0 2px rgba(2, 132, 199, 0.2); }

    .table-container { width: 100%; overflow-x: auto; margin-bottom: 2rem; }
    table { width: 100%; border-collapse: collapse; background: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #cbd5e1; font-size: 0.85rem; }
    th { background: #f1f5f9; color: #334155; padding: 0.75rem; text-align: left; border-bottom: 2px solid #cbd5e1; }
    td { padding: 0.65rem 0.75rem; border-bottom: 1px solid #e2e8f0; }
    .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
    .badge-critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
    .badge-high { background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; }
    .badge-medium { background: #fef9c3; color: #ca8a04; border: 1px solid #fde047; }
    .badge-false-positive { background: #f3e8ff; color: #9333ea; border: 1px solid #d8b4fe; }
    .badge-info { background: #e0f2fe; color: #0284c7; border: 1px solid #7dd3fc; }
    @media print {
      body { padding: 0; background: #ffffff; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>

  <div class="no-print" style="margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center">
    <button onclick="window.print()" style="background:#0284c7; color:#fff; border:none; padding:0.6rem 1.25rem; border-radius:6px; font-weight:bold; cursor:pointer">🖨️ Print / Save as PDF</button>
    <span style="font-size:0.85rem; color:#64748b">Cloud Access Anomaly Detection & UEBA SIEM Platform</span>
  </div>

  <h1>📊 Active Cloud Access Anomaly Telemetry Report</h1>
  <div class="header-sub">Interactive Filter-Enabled Telemetry Report with Full AI Inspection & MITRE ATT&CK/D3FEND Breakdown</div>

  <div class="meta-box">
    <div>
      <strong>Report Generated:</strong> ${timestamp}<br>
      <strong>Master Export Filter:</strong> ${query}<br>
      <strong>Severity Filter:</strong> ${severityFilter}
    </div>
    <div>
      <strong>Cloud Provider Filter:</strong> ${providerFilter}<br>
      <strong>Total Exported Records:</strong> ${filtered.length} Record(s)<br>
      <strong>Average ML Risk Score:</strong> ${avgRisk} / 100
    </div>
    <div>
      <strong>Critical Alerts:</strong> ${criticalCount}<br>
      <strong>High Risk Anomalies:</strong> ${highCount}<br>
      <strong>False Positives:</strong> ${fpCount}
    </div>
  </div>

  <!-- Interactive Document Filter Bar -->
  <div class="report-filter-bar no-print">
    <div style="display:flex; justify-content:space-between; align-items:center">
      <strong style="color:#0284c7; font-size:0.95rem">🔍 IN-REPORT INTERACTIVE TELEMETRY FILTERS</strong>
      <span id="exp-visible-count" class="badge badge-info">${filtered.length} / ${filtered.length} Visible</span>
    </div>
    <div class="filter-grid">
      <div class="filter-group">
        <label for="exp-filter-event-id">Event ID:</label>
        <input type="text" id="exp-filter-event-id" class="filter-input" placeholder="e.g. OCSF-UEBA-2026-001" onkeyup="filterReportRows()">
      </div>
      <div class="filter-group">
        <label for="exp-filter-cloud">Cloud Provider:</label>
        <select id="exp-filter-cloud" class="filter-input" onchange="filterReportRows()">
          <option value="ALL">All Cloud Providers</option>
          <option value="AWS">AWS</option>
          <option value="Azure">Azure / Entra ID</option>
          <option value="GCP">GCP</option>
          <option value="Okta">Okta / Cloud</option>
        </select>
      </div>
      <div class="filter-group">
        <label for="exp-filter-user">Identity / User:</label>
        <input type="text" id="exp-filter-user" class="filter-input" placeholder="e.g. alex.morgan" onkeyup="filterReportRows()">
      </div>
      <div class="filter-group">
        <label for="exp-filter-country">Country:</label>
        <input type="text" id="exp-filter-country" class="filter-input" placeholder="e.g. Germany, Russia" onkeyup="filterReportRows()">
      </div>
      <div class="filter-group">
        <label for="exp-filter-scenario">Scenario Trigger:</label>
        <input type="text" id="exp-filter-scenario" class="filter-input" placeholder="e.g. Impossible Travel" onkeyup="filterReportRows()">
      </div>
      <div class="filter-group">
        <label for="exp-filter-severity">Severity:</label>
        <select id="exp-filter-severity" class="filter-input" onchange="filterReportRows()">
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="FALSE POSITIVE">FALSE POSITIVE</option>
        </select>
      </div>
    </div>
  </div>

  <h2>1. Tabulated Anomaly Telemetry Master Table</h2>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Event ID</th>
          <th>Event Timestamp</th>
          <th>Ingestion Date & Time</th>
          <th>Cloud</th>
          <th>Identity / User</th>
          <th>Scenario Trigger</th>
          <th>Origin IP (Country)</th>
          <th>ML Risk</th>
          <th>Blast Score</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody id="exp-tbody">
        ${summaryRowsHtml}
      </tbody>
    </table>
  </div>

  <h2>2. Detailed Telemetry Inspection & MITRE ATT&CK/D3FEND Breakdown</h2>
  <div id="exp-inspect-container">
    ${inspectSectionsHtml}
  </div>

  <!-- Client-Side Filter Script for Exported Document -->
  <script>
    function filterReportRows() {
      const eid = (document.getElementById('exp-filter-event-id').value || '').toLowerCase().trim();
      const cloud = document.getElementById('exp-filter-cloud').value;
      const user = (document.getElementById('exp-filter-user').value || '').toLowerCase().trim();
      const country = (document.getElementById('exp-filter-country').value || '').toLowerCase().trim();
      const scenario = (document.getElementById('exp-filter-scenario').value || '').toLowerCase().trim();
      const severity = document.getElementById('exp-filter-severity').value;

      const rows = document.querySelectorAll('.exp-table-row');
      const inspects = document.querySelectorAll('.exp-inspect-card');
      let visibleCount = 0;

      rows.forEach(r => {
        const rEid = (r.getAttribute('data-event-id') || '').toLowerCase();
        const rCloud = r.getAttribute('data-cloud') || '';
        const rUser = (r.getAttribute('data-user') || '').toLowerCase();
        const rCountry = (r.getAttribute('data-country') || '').toLowerCase();
        const rScenario = (r.getAttribute('data-scenario') || '').toLowerCase();
        const rSeverity = r.getAttribute('data-severity') || '';

        const matchEid = !eid || rEid.includes(eid);
        const matchCloud = cloud === 'ALL' || rCloud.includes(cloud);
        const matchUser = !user || rUser.includes(user);
        const matchCountry = !country || rCountry.includes(country);
        const matchScenario = !scenario || rScenario.includes(scenario);
        const matchSeverity = severity === 'ALL' || rSeverity === severity;

        const isMatch = matchEid && matchCloud && matchUser && matchCountry && matchScenario && matchSeverity;
        r.style.display = isMatch ? '' : 'none';
        if (isMatch) visibleCount++;
      });

      inspects.forEach(c => {
        const cEid = (c.getAttribute('data-event-id') || '').toLowerCase();
        const cCloud = c.getAttribute('data-cloud') || '';
        const cUser = (c.getAttribute('data-user') || '').toLowerCase();
        const cCountry = (c.getAttribute('data-country') || '').toLowerCase();
        const cScenario = (c.getAttribute('data-scenario') || '').toLowerCase();
        const cSeverity = c.getAttribute('data-severity') || '';

        const matchEid = !eid || cEid.includes(eid);
        const matchCloud = cloud === 'ALL' || cCloud.includes(cloud);
        const matchUser = !user || cUser.includes(user);
        const matchCountry = !country || cCountry.includes(country);
        const matchScenario = !scenario || cScenario.includes(scenario);
        const matchSeverity = severity === 'ALL' || cSeverity === severity;

        c.style.display = (matchEid && matchCloud && matchUser && matchCountry && matchScenario && matchSeverity) ? '' : 'none';
      });

      const countBadge = document.getElementById('exp-visible-count');
      if (countBadge) {
        countBadge.textContent = visibleCount + ' / ' + rows.length + ' Visible';
      }
    }
  </script>

</body>
</html>`;

  // Trigger Blob Download for filtered telemetry report
  const blob = new Blob([reportHtml], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `filtered_anomaly_telemetry_report_${new Date().toISOString().slice(0,10)}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  // Also open report in new printable window
  const printWindow = window.open("", "_blank");
  if (printWindow) {
    printWindow.document.write(reportHtml);
    printWindow.document.close();
  }
}

// Render Interactive Chart.js Visualizations
function renderCharts() {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js library is uninitialized or offline; skipping canvas charts.");
    return;
  }

  // Chart 1: Severity Bar Chart
  const ctxSeverity = document.getElementById("chart-severity");
  if (ctxSeverity) {
    if (severityChart) severityChart.destroy();
    
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    anomalyEvents.forEach(e => {
      if (severityCounts[e.anomaly_details.severity] !== undefined) {
        severityCounts[e.anomaly_details.severity]++;
      }
    });

    severityChart = new Chart(ctxSeverity, {
      type: "bar",
      data: {
        labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        datasets: [{
          label: "Active Threats",
          data: [severityCounts.CRITICAL, severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW],
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }

  // Chart 2: Baseline vs Session Events Radar Chart
  const ctxBaseline = document.getElementById("chart-baseline");
  if (ctxBaseline) {
    if (baselineChart) baselineChart.destroy();

    const labels = anomalyEvents.map(e => e.actor.user_name.split("@")[0]);
    const baselineData = anomalyEvents.map(e => e.anomaly_details.baseline_90d_avg_daily_events);
    const sessionData = anomalyEvents.map(e => e.anomaly_details.session_30m_event_count);

    baselineChart = new Chart(ctxBaseline, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "90-Day Daily Baseline",
            data: baselineData,
            backgroundColor: "rgba(59, 130, 246, 0.5)",
            borderColor: "#3b82f6",
            borderWidth: 1
          },
          {
            label: "30-Min Session Volume",
            data: sessionData,
            backgroundColor: "rgba(239, 68, 68, 0.7)",
            borderColor: "#ef4444",
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#f8fafc" } } },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }

  // Chart 3: Blast Radius Scatter Plot
  const ctxBlast = document.getElementById("chart-blast");
  if (ctxBlast) {
    if (blastRadiusChart) blastRadiusChart.destroy();

    const scatterData = anomalyEvents.map(e => ({
      x: e.anomaly_details.risk_score,
      y: e.anomaly_details.blast_radius_score,
      r: Math.min(25, Math.max(8, e.anomaly_details.baseline_delta_ratio * 2)),
      user: e.actor.user_name
    }));

    blastRadiusChart = new Chart(ctxBlast, {
      type: "bubble",
      data: {
        datasets: [{
          label: "Risk vs Blast Radius Impact",
          data: scatterData,
          backgroundColor: "rgba(0, 240, 255, 0.6)",
          borderColor: "#00f0ff"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          tooltip: {
            callbacks: {
              label: (ctx) => `${ctx.raw.user}: Risk ${ctx.raw.x}, Blast ${ctx.raw.y}`
            }
          },
          legend: { labels: { color: "#f8fafc" } }
        },
        scales: {
          x: { title: { display: true, text: "Anomaly Risk Score", color: "#94a3b8" }, ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: { title: { display: true, text: "Blast Radius Score", color: "#94a3b8" }, ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }
}

// Open Remediation Modal with Playbook Commands
function openRemediationModal(eventId) {
  const evt = anomalyEvents.find(e => e.event_id === eventId);
  if (!evt) return;

  const modal = document.getElementById("modal-remediation");
  document.getElementById("modal-user").textContent = evt.actor.user_name;
  document.getElementById("modal-scenario").textContent = evt.anomaly_details.scenario;
  document.getElementById("modal-action").textContent = evt.anomaly_details.remediation_playbook.action;
  document.getElementById("modal-command").textContent = evt.anomaly_details.remediation_playbook.cli_command;
  
  modal.classList.add("active");
}

let currentInspectedEventId = null;

// Open Detail & AI Summarizer Modal
function openDetailModal(eventId) {
  currentInspectedEventId = eventId;
  const evt = anomalyEvents.find(e => e.event_id === eventId);
  if (!evt) return;

  // Find all events for this user identity
  const userEvents = anomalyEvents.filter(e => e.actor.user_name === evt.actor.user_name);
  
  // Render Raw JSON view
  document.getElementById("modal-user-event-count").textContent = `${userEvents.length} Event(s)`;
  document.getElementById("modal-detail-json").textContent = JSON.stringify(userEvents.length === 1 ? evt : userEvents, null, 2);

  // Load existing analyst comment and sentiment output if present
  const fb = userFeedbackStore[eventId];
  const commentEl = document.getElementById("modal-analyst-comment");
  const resultBox = document.getElementById("modal-sentiment-result-box");
  const badgeEl = document.getElementById("modal-sentiment-badge");
  const valEl = document.getElementById("modal-sentiment-val");

  if (fb) {
    if (typeof fb === "object") {
      if (commentEl) commentEl.value = fb.text || "";
      if (badgeEl) {
        badgeEl.className = `badge ${fb.category === 'POSITIVE' ? 'badge-info' : (fb.category === 'NEGATIVE' ? 'badge-false-positive' : 'badge-medium')}`;
        badgeEl.textContent = `Sentiment: ${fb.category} (${fb.satisfaction_pct}%)`;
      }
      if (valEl) {
        valEl.textContent = `${fb.score > 0 ? '+' : ''}${fb.score} (${fb.satisfaction_pct}% Satisfaction)`;
      }
      if (resultBox) {
        resultBox.style.display = "block";
        document.getElementById("modal-sentiment-title").textContent = `AI Sentiment Engine (${fb.category})`;
        document.getElementById("modal-sentiment-text").textContent = `Analyst Comment: "${fb.text}"`;
      }
    } else {
      if (commentEl) commentEl.value = fb === true ? "Confirmed Detections (Thumbs Up)" : "Flagged False Positive (Thumbs Down)";
      if (badgeEl) {
        badgeEl.className = `badge ${fb === true ? 'badge-info' : 'badge-false-positive'}`;
        badgeEl.textContent = fb === true ? "Sentiment: POSITIVE (100%)" : "Sentiment: NEGATIVE (0%)";
      }
      if (valEl) valEl.textContent = fb === true ? "+1.0 (100% Satisfaction)" : "-1.0 (0% Satisfaction)";
      if (resultBox) resultBox.style.display = "none";
    }
  } else {
    if (commentEl) commentEl.value = "";
    if (badgeEl) {
      badgeEl.className = "badge badge-info";
      badgeEl.textContent = "Awaiting Feedback";
    }
    if (valEl) valEl.textContent = "N/A";
    if (resultBox) resultBox.style.display = "none";
  }

  // Switch to Summary Tab & Run AI Summarizer
  switchModalTab('summary');
  triggerAiSummarization();

  document.getElementById("modal-detail").classList.add("active");
}

// AI Sentiment Analysis Engine for Analyst Feedback
function analyzeAnalystSentiment(text) {
  if (!text || text.trim().length === 0) {
    return {
      score: 0.0,
      satisfaction_pct: 50,
      category: "NEUTRAL",
      summary: "No comment provided."
    };
  }

  const lower = text.toLowerCase();
  
  // Lexicon scoring weights
  const posTerms = ["accurate", "great", "helpful", "fast", "good", "useful", "correct", "excellent", "saved time", "solid", "isolated", "satisfied", "thumbs up", "agree", "nice", "clear", "perfect", "valuable", "remediated", "love", "spot on", "effective"];
  const negTerms = ["false positive", "wrong", "noisy", "useless", "bad", "slow", "incorrect", "poor", "junk", "broken", "mistake", "dissatisfied", "waste", "unhelpful", "terrible", "disagree", "annoying", "flawed", "fail"];

  let score = 0.0;

  posTerms.forEach(t => {
    if (lower.includes(t)) score += 0.35;
  });

  negTerms.forEach(t => {
    if (lower.includes(t)) score -= 0.45;
  });

  // Clamp score between -1.0 and +1.0
  score = Math.max(-1.0, Math.min(1.0, score));

  // Convert Sentiment Score to User Satisfaction Percentage (0% - 100%)
  const satisfaction_pct = Math.round(((score + 1.0) / 2.0) * 100);

  let category = "NEUTRAL";
  let summary = "";

  if (score >= 0.25) {
    category = "POSITIVE";
    summary = `Positive Sentiment (Score: +${score.toFixed(2)} | Satisfaction: ${satisfaction_pct}%). Analyst confirmed detection accuracy and praised response playbooks.`;
  } else if (score <= -0.25) {
    category = "NEGATIVE";
    summary = `Negative Sentiment (Score: ${score.toFixed(2)} | Satisfaction: ${satisfaction_pct}%). Analyst flagged false positive drift or alert noise requiring baseline tuning.`;
  } else {
    category = "NEUTRAL";
    summary = `Neutral Sentiment (Score: ${score.toFixed(2)} | Satisfaction: ${satisfaction_pct}%). Analyst provided standard operational feedback.`;
  }

  return {
    score: parseFloat(score.toFixed(2)),
    satisfaction_pct,
    category,
    summary
  };
}

// Submit Analyst Text Feedback & Run AI Sentiment Analysis
function submitAnalystFeedbackWithAiSentiment() {
  if (!currentInspectedEventId) return;

  const commentEl = document.getElementById("modal-analyst-comment");
  const commentText = commentEl ? commentEl.value : "";

  if (!commentText || commentText.trim().length === 0) {
    alert("Please enter a text analysis comment before submitting for AI sentiment analysis.");
    return;
  }

  // Run AI Sentiment Analysis
  const sentiment = analyzeAnalystSentiment(commentText);

  // Store in userFeedbackStore
  const agreeBool = sentiment.category !== "NEGATIVE";
  userFeedbackStore[currentInspectedEventId] = {
    agree: agreeBool,
    text: commentText,
    score: sentiment.score,
    satisfaction_pct: sentiment.satisfaction_pct,
    category: sentiment.category,
    timestamp: new Date().toISOString()
  };

  // Render Sentiment Output inside Inspect Modal
  const badgeEl = document.getElementById("modal-sentiment-badge");
  if (badgeEl) {
    badgeEl.className = `badge ${sentiment.category === 'POSITIVE' ? 'badge-info' : (sentiment.category === 'NEGATIVE' ? 'badge-false-positive' : 'badge-medium')}`;
    badgeEl.textContent = `Sentiment: ${sentiment.category} (${sentiment.satisfaction_pct}%)`;
  }

  const valEl = document.getElementById("modal-sentiment-val");
  if (valEl) {
    valEl.textContent = `${sentiment.score > 0 ? '+' : ''}${sentiment.score} (${sentiment.satisfaction_pct}% Satisfaction)`;
    valEl.style.color = sentiment.category === 'POSITIVE' ? '#38bdf8' : (sentiment.category === 'NEGATIVE' ? '#c084fc' : '#eab308');
  }

  const resultBox = document.getElementById("modal-sentiment-result-box");
  const resultTitle = document.getElementById("modal-sentiment-title");
  const resultText = document.getElementById("modal-sentiment-text");
  const resultTime = document.getElementById("modal-sentiment-time");

  if (resultBox && resultTitle && resultText) {
    resultBox.style.display = "block";
    resultTitle.textContent = `AI Sentiment Engine (${sentiment.category})`;
    resultTitle.style.color = sentiment.category === 'POSITIVE' ? '#38bdf8' : (sentiment.category === 'NEGATIVE' ? '#c084fc' : '#eab308');
    resultText.textContent = sentiment.summary;
    if (resultTime) resultTime.textContent = new Date().toLocaleTimeString();
  }

  // Recalculate Metrics Banner and Update Triage Table
  renderMetrics();
  renderTriageTable(getFilteredEvents());
}

// Switch between AI Summary, MITRE Defense, and Raw JSON tabs inside Modal
function switchModalTab(tabName) {
  const summaryBtn = document.getElementById("modal-tab-summary-btn");
  const mitreBtn = document.getElementById("modal-tab-mitre-btn");
  const jsonBtn = document.getElementById("modal-tab-json-btn");

  const summaryView = document.getElementById("modal-view-summary");
  const mitreView = document.getElementById("modal-view-mitre");
  const jsonView = document.getElementById("modal-view-json");

  summaryBtn.className = "btn";
  mitreBtn.className = "btn";
  jsonBtn.className = "btn";

  summaryView.style.display = "none";
  mitreView.style.display = "none";
  jsonView.style.display = "none";

  if (tabName === 'summary') {
    summaryBtn.className = "btn btn-primary";
    summaryView.style.display = "block";
  } else if (tabName === 'mitre') {
    mitreBtn.className = "btn btn-primary";
    mitreView.style.display = "block";
    renderMitreDefenseView();
  } else {
    jsonBtn.className = "btn btn-primary";
    jsonView.style.display = "block";
  }
}

// Render MITRE ATT&CK Path Details & Related D3FEND Defense Mechanisms
function renderMitreDefenseView() {
  if (!currentInspectedEventId) return;
  const evt = anomalyEvents.find(e => e.event_id === currentInspectedEventId);
  if (!evt) return;

  const mitreContainer = document.getElementById("modal-mitre-content");
  mitreContainer.innerHTML = buildMitreDefenseView(evt);
}

// Build Detailed MITRE ATT&CK Path & D3FEND Defense Table
function buildMitreDefenseView(evt) {
  const techId = evt.anomaly_details.mitre_attack.technique_id;
  const techName = evt.anomaly_details.mitre_attack.technique_name;
  const tactic = evt.anomaly_details.mitre_attack.tactic;
  const provider = evt.cloud_provider;
  const scenario = evt.anomaly_details.scenario;
  const user = evt.actor.user_name;
  const ip = evt.src_endpoint.ip;
  const country = evt.src_endpoint.country;

  // Easy English Explanations based on Scenario
  let easyAttackExplanation = "";
  let easyImpactExplanation = "";
  let easyDefenseExplanation = "";

  if (scenario.toLowerCase().includes("travel")) {
    easyAttackExplanation = `An attacker obtained valid login credentials for <code>${user}</code> and logged in from ${country} (${ip}) while the real user was active somewhere else.`;
    easyImpactExplanation = "This allowed the attacker to pretend to be an authorized employee and access sensitive company cloud keys.";
    easyDefenseExplanation = "Require physical hardware security keys (FIDO2) and block login attempts originating from unauthorized foreign countries.";
  } else if (scenario.toLowerCase().includes("mfa") || scenario.toLowerCase().includes("fatigue")) {
    easyAttackExplanation = `The attacker repeatedly spammed <code>${user}</code>'s phone with login push notifications until the user accidentally or out of fatigue pressed 'Approve'.`;
    easyImpactExplanation = "The attacker bypassed multi-factor authentication and gained full administrator control over company accounts.";
    easyDefenseExplanation = "Disable mobile push notifications, switch to hardware keys or number-matching MFA, and automatically terminate active user sessions when spamming is detected.";
  } else if (scenario.toLowerCase().includes("dormant") || scenario.toLowerCase().includes("admin") || scenario.toLowerCase().includes("backdoor")) {
    easyAttackExplanation = `An inactive service account (<code>${user}</code>) that wasn't used for months was suddenly reactivated to secretly grant itself permanent admin access.`;
    easyImpactExplanation = "Creates a secret backdoor for the attacker to maintain permanent control over the cloud infrastructure even if passwords are changed.";
    easyDefenseExplanation = "Automatically delete or disable dormant accounts after 30 days of inactivity and strip unneeded administrative privileges.";
  } else if (scenario.toLowerCase().includes("exfiltration") || scenario.toLowerCase().includes("s3") || scenario.toLowerCase().includes("storage")) {
    easyAttackExplanation = `An automated script hijacked account <code>${user}</code> and rapidly downloaded thousands of confidential customer files and database backups.`;
    easyImpactExplanation = "Leads to severe data breach, exposure of private customer data, and compliance violations.";
    easyDefenseExplanation = "Set strict rate limits on cloud data downloads, block unauthorized file transfers, and alert security teams when egress spikes.";
  } else if (scenario.toLowerCase().includes("erasure") || scenario.toLowerCase().includes("trail") || scenario.toLowerCase().includes("log")) {
    easyAttackExplanation = `The attacker used account <code>${user}</code> to turn off security logging systems (CloudTrail) so security tools couldn't record their actions.`;
    easyImpactExplanation = "Blinds the security team, making it difficult to detect what files were stolen or altered.";
    easyDefenseExplanation = "Lock audit log storage buckets with unmodifiable Object Lock policies so logs cannot be deleted even by administrators.";
  } else {
    easyAttackExplanation = `Suspicious login activity was detected for user <code>${user}</code> from unexpected IP address ${ip}.`;
    easyImpactExplanation = "Potential unauthorized access to company resources and internal systems.";
    easyDefenseExplanation = "Revoke active login tokens, reset account passwords, and require identity re-verification.";
  }

  // Comprehensive ATT&CK Chained Attack Path
  const attackPathSteps = [
    { step: 1, tactic: "Initial Access", tid: "T1078.004", name: "Valid Accounts: Cloud Accounts", desc: `Attacker authenticated as user ${user} via origin IP ${ip} using valid session tokens.` },
    { step: 2, tactic: "Credential Access", tid: "T1621", name: "MFA Request Generation", desc: "Push notification spamming executed until user approved login or session was hijacked." },
    { step: 3, tactic: "Privilege Escalation", tid: "T1098.001", name: "Account Manipulation", desc: "Inline backdoor IAM admin policies or roles attached to gain full cloud tenancy access." },
    { step: 4, tactic: "Defense Evasion", tid: "T1562.001", name: "Disable Cloud Security Logs", desc: "CloudTrail logging disabled (StopLogging) or diagnostic log stream policies removed." },
    { step: 5, tactic: "Exfiltration", tid: "T1567.002", name: "Exfiltration to Cloud Storage", desc: "Automated high-rate egress downloading sensitive customer databases and backup blobs." }
  ];

  // MITRE D3FEND Defense Mechanisms Mapped to Scenario
  const d3fendDefenseMap = [
    {
      code: "D3-MFA",
      category: "Credential Hardening",
      name: "Hardware FIDO2 Multi-Factor Authentication",
      desc: "Enforce FIDO2 WebAuthn security keys and block vulnerable push notification / SMS fallback.",
      nist: "IA-2(1), IA-8",
      action: "Mandate hardware key sign-in for all admin roles."
    },
    {
      code: "D3-ILM",
      category: "Network Defense",
      name: "Inbound Traffic Filtering & Geo-IP Fencing",
      desc: `Restrict access to verified corporate CIDR blocks and block high-risk IP range ${ip}.`,
      nist: "AC-17, SC-7",
      action: "Apply Conditional Access location policy."
    },
    {
      code: "D3-IAM",
      category: "Identity Governance",
      name: "Privileged Access Management & Least Privilege",
      desc: "Conduct daily dormant privilege reviews and automatically strip unused inline admin permissions.",
      nist: "AC-2(2), AC-6",
      action: "Detach unassigned IAM policies immediately."
    },
    {
      code: "D3-ALM",
      category: "Audit Security",
      name: "Audit Log Immutability & S3 Object Lock",
      desc: "Configure CloudTrail S3 audit buckets with Write-Once-Read-Many (WORM) Object Lock and MFA Delete.",
      nist: "AU-9, AU-11",
      action: "Enable CloudTrail S3 Object Lock in compliance mode."
    },
    {
      code: "D3-CAE",
      category: "Access Evaluation",
      name: "Continuous Access Evaluation (CAE)",
      desc: "Enable real-time token revocation to immediately terminate active session bearer tokens upon risk alert.",
      nist: "AC-12, SC-23",
      action: "Invoke Revoke-MgUserSignInSession / aws iam revoke-security-credentials."
    }
  ];

  // Render Attack Path Stepper HTML
  let pathHtml = attackPathSteps.map(s => `
    <div style="background:var(--bg-surface); border:1px solid var(--border-color); border-radius:8px; padding:0.85rem; margin-bottom:0.6rem; display:flex; gap:0.75rem; align-items:center">
      <div style="background:linear-gradient(135deg, #00f0ff 0%, #3b82f6 100%); color:#000; font-weight:800; width:28px; height:28px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:0.8rem">
        ${s.step}
      </div>
      <div style="flex-grow:1">
        <div style="display:flex; justify-content:space-between">
          <strong style="color:var(--text-primary); font-size:0.85rem">${s.tactic}</strong>
          <code style="color:#38bdf8; font-size:0.8rem">${s.tid}: ${s.name}</code>
        </div>
        <div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.2rem">${s.desc}</div>
      </div>
    </div>
  `).join("");

  // Render Defense Mechanisms Table HTML
  let defenseRows = d3fendDefenseMap.map(d => `
    <tr>
      <td><strong style="color:var(--border-accent); font-family:var(--font-mono)">${d.code}</strong></td>
      <td><span class="badge badge-info">${d.category}</span></td>
      <td style="color:var(--text-primary); font-weight:600">${d.name}</td>
      <td style="font-size:0.8rem; color:var(--text-secondary)">${d.desc}</td>
      <td><code>${d.nist}</code></td>
    </tr>
  `).join("");

  return `
    <!-- AI Easy English Summary Box -->
    <div class="ai-box" style="margin-top:0; border-color:var(--border-accent); background:linear-gradient(135deg, rgba(0, 240, 255, 0.08) 0%, rgba(59, 130, 246, 0.08) 100%)">
      <div class="ai-header" style="justify-content:space-between; font-size:0.95rem">
        <span>🤖 EASY ENGLISH AI SUMMARY: ATTACK & DEFENSE OVERVIEW</span>
        <span class="badge badge-info">${provider} Telemetry</span>
      </div>
      <div class="ai-text" style="font-size:0.88rem; line-height:1.6; margin-top:0.75rem">
        <div style="margin-bottom:0.6rem">
          <strong style="color:var(--severity-critical)">⚔️ What the Attacker Did (Simple Terms):</strong><br>
          ${easyAttackExplanation}
        </div>
        <div style="margin-bottom:0.6rem">
          <strong style="color:var(--severity-high)">💥 Why It Matters (Business Impact):</strong><br>
          ${easyImpactExplanation}
        </div>
        <div>
          <strong style="color:var(--severity-info)">🛡️ How to Fix & Defend (Easy Actions):</strong><br>
          ${easyDefenseExplanation}
        </div>
      </div>
    </div>

    <div style="margin-top:1.25rem">
      <h3 style="color:var(--text-cyber); font-size:0.9rem; margin-bottom:0.75rem">⛓️ Technical MITRE ATT&CK Execution Path</h3>
      ${pathHtml}
    </div>

    <div style="margin-top:1.5rem">
      <h3 style="color:var(--severity-info); font-size:0.9rem; margin-bottom:0.75rem">🛡️ Mapped MITRE D3FEND Defense Countermeasures</h3>
      <div class="table-container">
        <table class="soc-table">
          <thead>
            <tr>
              <th>D3FEND ID</th>
              <th>Category</th>
              <th>Defense Mechanism</th>
              <th>Security Control Description</th>
              <th>NIST Control</th>
            </tr>
          </thead>
          <tbody>
            ${defenseRows}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// Trigger AI Log Summarization Animation & Generation
function triggerAiSummarization() {
  if (!currentInspectedEventId) return;
  const evt = anomalyEvents.find(e => e.event_id === currentInspectedEventId);
  if (!evt) return;

  const userEvents = anomalyEvents.filter(e => e.actor.user_name === evt.actor.user_name);
  const loadingBox = document.getElementById("modal-ai-loading");
  const contentBox = document.getElementById("modal-ai-summary-content");

  loadingBox.style.display = "block";
  contentBox.style.display = "none";

  setTimeout(() => {
    loadingBox.style.display = "none";
    contentBox.style.display = "block";
    contentBox.innerHTML = buildEnglishAiSummary(evt, userEvents);
  }, 400);
}

// Synthesize User Telemetry Logs into Plain English AI Summary
function buildEnglishAiSummary(evt, userEvents) {
  const userName = evt.actor.user_name;
  const provider = evt.cloud_provider;
  const scenario = evt.anomaly_details.scenario;
  const severity = evt.anomaly_details.severity;
  const riskScore = evt.anomaly_details.risk_score;
  const blastScore = evt.anomaly_details.blast_radius_score;
  const ip = evt.src_endpoint.ip;
  const country = evt.src_endpoint.country;
  const baseline = evt.anomaly_details.baseline_90d_avg_daily_events;
  const sessionCount = evt.anomaly_details.session_30m_event_count;
  const deltaRatio = evt.anomaly_details.baseline_delta_ratio;
  const mitreId = evt.anomaly_details.mitre_attack.technique_id;
  const mitreName = evt.anomaly_details.mitre_attack.technique_name;
  const mitreTactic = evt.anomaly_details.mitre_attack.tactic;
  const action = evt.anomaly_details.remediation_playbook.action;
  const command = evt.anomaly_details.remediation_playbook.cli_command;

  // Plain English Narrative Generation
  let englishNarrative = "";
  if (scenario.toLowerCase().includes("travel")) {
    englishNarrative = `The AI engine detected an <strong>Impossible Travel Velocity Anomaly</strong> for user account <code>${userName}</code> on <strong>${provider}</strong>. The user successfully authenticated from <code>${ip}</code> (${country}) just minutes after an active session in another geographic region, implying compromised credentials or session hijacking.`;
  } else if (scenario.toLowerCase().includes("mfa") || scenario.toLowerCase().includes("fatigue")) {
    englishNarrative = `User <code>${userName}</code> experienced an <strong>MFA Push Request Spamming Attack</strong> on <strong>${provider}</strong>. After multiple rejected authentication attempts, a push notification was approved from an untrusted origin IP (<code>${ip}</code>, ${country}), allowing the attacker to bypass multi-factor authentication.`;
  } else if (scenario.toLowerCase().includes("dormant") || scenario.toLowerCase().includes("admin") || scenario.toLowerCase().includes("backdoor")) {
    englishNarrative = `The security engine identified a <strong>Dormant IAM Privilege Drift Anomaly</strong> involving account <code>${userName}</code> on <strong>${provider}</strong>. This identity had been inactive for an extended period before suddenly executing high-privilege IAM configuration changes and generating secondary access credentials.`;
  } else if (scenario.toLowerCase().includes("exfiltration") || scenario.toLowerCase().includes("s3") || scenario.toLowerCase().includes("storage")) {
    englishNarrative = `High-risk <strong>Mass Cloud Data Exfiltration</strong> was detected for account <code>${userName}</code> on <strong>${provider}</strong>. The session initiated an abnormal spike in object read requests from <code>${ip}</code> (${country}), transferring sensitive data objects at an unauthorized rate.`;
  } else if (scenario.toLowerCase().includes("erasure") || scenario.toLowerCase().includes("trail") || scenario.toLowerCase().includes("log")) {
    englishNarrative = `Critical <strong>Defense Evasion & Audit Trail Tampering</strong> was executed by account <code>${userName}</code> on <strong>${provider}</strong>. Key security logging services (such as CloudTrail or Diagnostic Settings) were disabled from origin IP <code>${ip}</code> (${country}) to blind security monitoring tools.`;
  } else {
    englishNarrative = `Anomalous access activity detected for user <code>${userName}</code> on <strong>${provider}</strong>. Telemetry logs from <code>${ip}</code> (${country}) exhibit significant behavioral variance compared to historical baseline activity.`;
  }

  const severityBadgeClass = `badge-${severity.toLowerCase()}`;

  return `
    <div class="ai-box" style="margin-top:0">
      <div class="ai-header" style="font-size:0.95rem; justify-content:space-between">
        <span>🤖 AI INCIDENT INVESTIGATION SUMMARY (PLAIN ENGLISH)</span>
        <span class="badge ${severityBadgeClass}">${severity} (Risk: ${riskScore}/100)</span>
      </div>
      <div class="ai-text" style="font-size:0.9rem; line-height:1.6; margin-top:0.75rem">
        <p style="margin-bottom:0.85rem">${englishNarrative}</p>
        <p style="color:var(--text-secondary)">
          <strong>Total User Logs Analyzed:</strong> ${userEvents.length} event(s) across recent 30-minute windowing windows.
        </p>
      </div>
    </div>

    <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-top:1rem">
      <div style="background:var(--bg-surface); padding:1rem; border-radius:8px; border:1px solid var(--border-color)">
        <h4 style="color:var(--text-cyber); font-size:0.85rem; margin-bottom:0.5rem">🎯 Baseline Variance Analysis</h4>
        <ul style="list-style:none; padding:0; font-size:0.8rem; color:var(--text-secondary); line-height:1.8">
          <li>• <strong>90-Day Daily Baseline:</strong> ${baseline} avg daily events</li>
          <li>• <strong>30-Min Session Rate:</strong> <span style="color:var(--severity-critical); font-weight:700">${sessionCount} events</span></li>
          <li>• <strong>Session Spike Ratio:</strong> <strong style="color:var(--border-accent)">${deltaRatio}x</strong> above normal threshold</li>
          <li>• <strong>Blast Radius Score:</strong> ${blastScore} / 100</li>
        </ul>
      </div>

      <div style="background:var(--bg-surface); padding:1rem; border-radius:8px; border:1px solid var(--border-color)">
        <h4 style="color:var(--text-cyber); font-size:0.85rem; margin-bottom:0.5rem">🛡️ MITRE ATT&CK Matrix Mapping</h4>
        <ul style="list-style:none; padding:0; font-size:0.8rem; color:var(--text-secondary); line-height:1.8">
          <li>• <strong>Tactic:</strong> ${mitreTactic}</li>
          <li>• <strong>Technique ID:</strong> <code style="color:#38bdf8">${mitreId}</code></li>
          <li>• <strong>Technique Name:</strong> ${mitreName}</li>
          <li>• <strong>Origin IP (Country):</strong> <code>${ip}</code> (${country})</li>
        </ul>
      </div>
    </div>

    <div style="margin-top:1rem">
      <h4 style="color:var(--severity-high); font-size:0.85rem; margin-bottom:0.4rem">💡 Recommended SOC Action: ${action}</h4>
      <div class="code-block">${command}</div>
    </div>
  `;
}

// Copy AI Summary text to clipboard
function copyAiSummary() {
  const summaryBox = document.getElementById("modal-ai-summary-content");
  if (!summaryBox) return;
  const text = summaryBox.innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert("AI Incident Summary copied to clipboard!");
  });
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove("active");
}

// Copy CLI Playbook command to clipboard
function copyCommand() {
  const cmd = document.getElementById("modal-command").textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    alert("Remediation command copied to clipboard!");
  });
}

// 1-Click SIEM Report File Generator & Downloader (Blob)
function downloadSiemReport(platform, format) {
  let content = "";
  let mimeType = format === "json" ? "application/json" : "text/csv";
  let filename = `sample_${platform}.${format}`;

  if (format === "json") {
    content = JSON.stringify(anomalyEvents, null, 2);
  } else {
    // Generate CSV
    const headers = ["event_id", "timestamp", "cloud_provider", "actor_user", "src_ip", "src_country", "severity", "risk_score", "genai_explanation"];
    const rows = anomalyEvents.map(e => [
      e.event_id,
      e.timestamp,
      e.cloud_provider,
      e.actor.user_name,
      e.src_endpoint.ip,
      e.src_endpoint.country,
      e.anomaly_details.severity,
      e.anomaly_details.risk_score,
      `"${e.anomaly_details.genai_explanation.replace(/"/g, '""')}"`
    ].join(","));
    content = [headers.join(","), ...rows].join("\n");
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Live Adversarial Attack Simulator
function runAdversarialSimulation(scenarioType) {
  let newEvent = null;
  const now = new Date().toISOString();

  if (scenarioType === "mfa_fatigue") {
    newEvent = {
      event_id: `SIM-${Math.floor(Math.random() * 9000 + 1000)}`,
      timestamp: now,
      category_name: "Identity & Access Management",
      class_name: "MFA Push Fatigue Attack",
      cloud_provider: "Azure / Entra ID",
      actor: {
        user_name: "cfo.executive@cloudorg.internal",
        user_arn: "entra://cloudorg.onmicrosoft.com/users/cfo.executive",
        assigned_roles: ["Financial Admin"]
      },
      src_endpoint: {
        ip: "198.51.100.119",
        country: "North Korea",
        city: "Pyongyang",
        isp: "Proxy-VLAN-9"
      },
      anomaly_details: {
        scenario: "Simulated MFA Push Fatigue",
        severity: "CRITICAL",
        risk_score: 99.1,
        blast_radius_score: 96.0,
        baseline_90d_avg_daily_events: 15,
        session_30m_event_count: 620,
        baseline_delta_ratio: 41.33,
        mitre_attack: {
          technique_id: "T1621",
          technique_name: "Multi-Factor Authentication Request Generation",
          tactic: "Credential Access"
        },
        genai_explanation: "SIMULATION ALERT: Executive account received 45 continuous MFA prompts in 2 minutes before approval from Pyongyang IP. Wire transfer API key exported.",
        remediation_playbook: {
          action: "Emergency Revoke Executive Tokens",
          cli_command: "Revoke-MgUserSignInSession -UserId 'cfo.executive@cloudorg.internal'"
        }
      }
    };
  } else if (scenarioType === "s3_exfil") {
    newEvent = {
      event_id: `SIM-${Math.floor(Math.random() * 9000 + 1000)}`,
      timestamp: now,
      category_name: "Data Storage",
      class_name: "S3 Ransomware & Bucket Exfil",
      cloud_provider: "AWS",
      actor: {
        user_name: "unauthorized_role_assumed",
        user_arn: "arn:aws:sts::123456789012:assumed-role/S3BackupAdmin/session-x",
        assigned_roles: ["S3FullAccess"]
      },
      src_endpoint: {
        ip: "203.0.113.77",
        country: "Romania",
        city: "Bucharest",
        isp: "Hosting-Server-EU"
      },
      anomaly_details: {
        scenario: "Simulated Mass S3 Bucket Exfiltration",
        severity: "CRITICAL",
        risk_score: 97.5,
        blast_radius_score: 94.8,
        baseline_90d_avg_daily_events: 50,
        session_30m_event_count: 2400,
        baseline_delta_ratio: 48.00,
        mitre_attack: {
          technique_id: "T1567.002",
          technique_name: "Exfiltration to Cloud Storage",
          tactic: "Exfiltration"
        },
        genai_explanation: "SIMULATION ALERT: S3GetObject call rate surged to 2,400 ops/sec. Customer PII dataset exfiltrated to external bucket.",
        remediation_playbook: {
          action: "Block S3 Egress & Detach Policy",
          cli_command: "aws iam detach-role-policy --role-name S3BackupAdmin --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess"
        }
      }
    };
  } else if (scenarioType === "log_erasure") {
    newEvent = {
      event_id: `SIM-${Math.floor(Math.random() * 9000 + 1000)}`,
      timestamp: now,
      category_name: "Defense Evasion",
      class_name: "CloudTrail & Audit Wipe",
      cloud_provider: "AWS",
      actor: {
        user_name: "rogue_dev",
        user_arn: "arn:aws:iam::123456789012:user/rogue_dev",
        assigned_roles: ["DevAdmin"]
      },
      src_endpoint: {
        ip: "198.51.100.244",
        country: "Netherlands",
        city: "Amsterdam",
        isp: "Tor-Exit-Node"
      },
      anomaly_details: {
        scenario: "Simulated Audit Log Erasure",
        severity: "CRITICAL",
        risk_score: 99.8,
        blast_radius_score: 99.0,
        baseline_90d_avg_daily_events: 10,
        session_30m_event_count: 340,
        baseline_delta_ratio: 34.00,
        mitre_attack: {
          technique_id: "T1562.001",
          technique_name: "Impair Defenses: Disable Cloud Logs",
          tactic: "Defense Evasion"
        },
        genai_explanation: "SIMULATION ALERT: CloudTrail trails deleted and S3 Object Lock bypassed via Tor exit node.",
        remediation_playbook: {
          action: "Re-enable Trails & Lock IAM User",
          cli_command: "aws iam delete-login-profile --user-name rogue_dev && aws cloudtrail create-trail --name emergency-trail --s3-bucket-name sec-logs"
        }
      }
    };
  }

  if (newEvent) {
    anomalyEvents.unshift(newEvent);
    renderMetrics();
    renderTriageTable(anomalyEvents);
    renderCharts();

    // Stream simulation output notification
    const logBox = document.getElementById("sim-log-output");
    if (logBox) {
      logBox.innerHTML = `<div class="ai-box">
        <div class="ai-header">⚡ SIMULATION INJECTED SUCCESSFUL</div>
        <div class="ai-text"><strong>Scenario:</strong> ${newEvent.anomaly_details.scenario}<br>
        <strong>Target:</strong> ${newEvent.actor.user_name} | <strong>Risk Score:</strong> ${newEvent.anomaly_details.risk_score}<br>
        <strong>AI Narrative:</strong> ${newEvent.anomaly_details.genai_explanation}</div>
      </div>` + logBox.innerHTML;
    }
  }
}

// Drag & Drop Setup
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("siem-dropzone");
  if (dropzone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, preventDefaults, false);
    });
    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, () => dropzone.classList.add('active'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, () => dropzone.classList.remove('active'), false);
    });

    dropzone.addEventListener('drop', handleFileDrop, false);
  }
});

function handleFileDrop(e) {
  const dt = e.dataTransfer;
  const files = dt.files;
  if (files && files.length > 0) {
    processUploadedFile(files[0]);
  }
}

function handleFileUpload(event) {
  const files = event.target.files;
  if (files && files.length > 0) {
    processUploadedFile(files[0]);
  }
}

// Process Uploaded File (.json or .csv)
function processUploadedFile(file) {
  const statusBox = document.getElementById("upload-status");
  statusBox.innerHTML = `<div style="color:var(--border-accent); font-weight:600">⏳ Parsing ${file.name}...</div>`;

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const text = e.target.result;
      let parsedEvents = [];

      if (file.name.endsWith(".json")) {
        const rawJson = JSON.parse(text);
        parsedEvents = Array.isArray(rawJson) ? rawJson : [rawJson];
      } else if (file.name.endsWith(".csv")) {
        parsedEvents = parseCSV(text);
      } else {
        throw new Error("Unsupported file extension. Please upload a .json or .csv file.");
      }

      // Normalize events into OCSF schema structure
      const normalizedEvents = parsedEvents.map(raw => normalizeSiemRecord(raw));
      
      // Merge into active telemetry store
      anomalyEvents = [...normalizedEvents, ...anomalyEvents];
      
      // Update UI metrics & tables
      renderMetrics();
      renderTriageTable(anomalyEvents);
      renderCharts();

      statusBox.innerHTML = `<div class="ai-box" style="border-color:#10b981">
        <div class="ai-header" style="color:#10b981">✅ SIEM LOG INGESTION SUCCESSFUL</div>
        <div class="ai-text">Ingested <strong>${normalizedEvents.length}</strong> normalized records from <code>${file.name}</code> into live telemetry store.</div>
      </div>`;

    } catch (err) {
      statusBox.innerHTML = `<div class="ai-box" style="border-color:#ef4444">
        <div class="ai-header" style="color:#ef4444">❌ INGESTION ERROR</div>
        <div class="ai-text">${err.message}</div>
      </div>`;
    }
  };
  reader.readAsText(file);
}

// Simple CSV Parser
function parseCSV(text) {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  
  const headers = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, ''));
  const records = [];

  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    // Regex matches CSV cells taking quotes into account
    const values = lines[i].match(/(".*?"|[^",\s]+)(?=\s*,|\s*$)/g) || lines[i].split(",");
    const record = {};
    headers.forEach((h, idx) => {
      let val = values[idx] ? values[idx].trim().replace(/^"|"$/g, '') : "";
      record[h] = val;
    });
    records.push(record);
  }
  return records;
}

// Universal SIEM Record Normalizer
function normalizeSiemRecord(raw) {
  let record = raw;

  // If not OCSF format, normalize to standard schema
  if (!raw.event_id || !raw.actor || !raw.anomaly_details) {
    const now = new Date().toISOString();
    const user = raw.UserPrincipalName || raw.user || raw.actor_user || raw.user_email || raw.user_name || "imported.user@cloudorg.internal";
    const ip = raw.IPAddress || raw.src || raw.src_ip || raw.source_ip || "198.51.100.100";
    const country = raw.Country || raw.src_country || raw.source_country || "United States";
    const provider = raw.SourceSystem || raw.cloud_provider || (raw.TenantId ? "Azure / Entra ID" : "AWS");
    const risk = parseFloat(raw.InvestigationPriority || raw.risk_score || raw.elastic_ml_anomaly_score || 85.0);
    const scenario = raw.RiskDetail || raw.rba_threat_category || raw.wazuh_description || "Uploaded SIEM Anomaly Log";
    const summary = raw.SentinelCopilotSummary || raw.splunk_rba_narrative || raw.genai_explanation || raw.ai_attack_narrative || "Ingested log event from uploaded SIEM file.";
    const cli = raw.KQLRemediationQuery || raw.remediation_cli || `aws iam revoke-security-credentials --user-name ${user}`;

    record = {
      event_id: `INGEST-${Math.floor(Math.random() * 90000 + 10000)}`,
      timestamp: raw.TimeGenerated || raw._time || raw["@timestamp"] || now,
      category_name: "Identity & Access Management",
      class_name: "Imported SIEM Telemetry",
      cloud_provider: provider,
      actor: {
        user_name: user,
        user_arn: user,
        assigned_roles: ["ImportedRole"]
      },
      src_endpoint: {
        ip: ip,
        country: country,
        city: "Unknown",
        isp: "ISP-Cloud"
      },
      anomaly_details: {
        scenario: scenario,
        severity: risk >= 90 ? "CRITICAL" : (risk >= 75 ? "HIGH" : "MEDIUM"),
        risk_score: risk,
        blast_radius_score: Math.min(99, risk + 3),
        baseline_90d_avg_daily_events: parseInt(raw.BaselineDailyMean || raw.baseline_events || 25),
        session_30m_event_count: parseInt(raw.Session30mEvents || raw.actual_events || 150),
        baseline_delta_ratio: 6.0,
        mitre_attack: {
          technique_id: raw.rba_mitre_id || "T1078",
          technique_name: "Valid Accounts",
          tactic: "Initial Access"
        },
        genai_explanation: summary,
        remediation_playbook: {
          action: "Investigate Ingested Telemetry",
          cli_command: cli
        }
      }
    };
  }

  // Rulebook Evaluation for False Positive Auto-Classification
  const genaiText = (record.anomaly_details.genai_explanation || "").toLowerCase();
  const scenarioText = (record.anomaly_details.scenario || "").toLowerCase();
  const riskScore = record.anomaly_details.risk_score || 0;

  const isFpMatch = genaiText.includes("non-malicious") ||
                    genaiText.includes("operational baseline") ||
                    genaiText.includes("false positive") ||
                    genaiText.includes("verified safe") ||
                    scenarioText.includes("atypical service account") ||
                    record.anomaly_details.severity === "LOW" && riskScore < 30.0;

  if (isFpMatch) {
    record.anomaly_details.original_severity = record.anomaly_details.severity;
    record.anomaly_details.severity = "FALSE POSITIVE";
    userFeedbackStore[record.event_id] = false; // Flagged as False Positive feedback
  } else if (userFeedbackStore[record.event_id] === undefined) {
    userFeedbackStore[record.event_id] = true; // Confirmed True Positive default
  }

  // Ensure ingestion_timestamp is always recorded
  if (!record.ingestion_timestamp) {
    record.ingestion_timestamp = raw.ingestion_timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19);
  }

  return record;
}

