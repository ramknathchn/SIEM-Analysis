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
  }
];

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
});

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
  nodeList.innerHTML = html;

  // Render Summary
  summaryBox.innerHTML = `
    <strong>Target Identity:</strong> <code>${entityId}</code><br>
    <strong>Total Connected 1,000+ Systems:</strong> <span style="color:var(--border-accent); font-weight:700">${current.reachable_count} entities reachable in 5 hops</span><br>
    <strong>Calculated Blast Radius Score:</strong> <span style="color:var(--severity-critical); font-size:1.4rem; font-weight:800">${current.blast_score}</span><br>
    <p style="font-size:0.8rem; color:var(--text-muted); margin-top:0.5rem">
      Traversed via SQLite 5-Hop Recursive CTE algorithm in <code>caad_topology.db</code>. Score is weighted by criticality, data sensitivity, and hop distance attenuation.
    </p>
  `;

  // Render Visual Node Graph Canvas
  drawNodeGraphCanvas(entityId, current);
}

// Interactive HTML5 Canvas Node Graph Engine for Blast Radius
let activeGraphNodes = [];

function drawNodeGraphCanvas(entryEntityId, currentData) {
  const canvas = document.getElementById("blast-node-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width || 800;
  canvas.height = rect.height || 380;

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
    ctx.fillStyle = n.color.replace(")", ", 0.25)").replace("rgb", "rgba").replace("#", "rgba(") ? `${n.color}33` : "rgba(0,240,255,0.2)";
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
}

// Tab Switching Handler
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
      
      tab.classList.add("active");
      const targetPane = document.getElementById(tab.dataset.tab);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// Calculate and Render Top Banner Metrics
function renderMetrics() {
  const criticalCount = anomalyEvents.filter(e => e.anomaly_details.severity === "CRITICAL").length;
  const highCount = anomalyEvents.filter(e => e.anomaly_details.severity === "HIGH").length;
  const totalAnalyzed = anomalyEvents.reduce((acc, curr) => acc + curr.anomaly_details.session_30m_event_count, 0);
  const avgRisk = (anomalyEvents.reduce((acc, curr) => acc + curr.anomaly_details.risk_score, 0) / anomalyEvents.length).toFixed(1);

  document.getElementById("metric-critical").textContent = criticalCount;
  document.getElementById("metric-high").textContent = highCount;
  document.getElementById("metric-analyzed").textContent = totalAnalyzed.toLocaleString();
  document.getElementById("metric-risk").textContent = `${avgRisk} / 100`;
}

// Render Triage Table with Filter and Search Support
function renderTriageTable(events) {
  const tbody = document.getElementById("triage-tbody");
  if (!tbody) return;
  
  tbody.innerHTML = "";
  
  events.forEach(evt => {
    const tr = document.createElement("tr");
    const severityClass = `badge-${evt.anomaly_details.severity.toLowerCase()}`;
    
    tr.innerHTML = `
      <td><span class="badge ${severityClass}">${evt.anomaly_details.severity}</span></td>
      <td class="table-user">${evt.actor.user_name}</td>
      <td><span style="color:var(--text-cyber)">${evt.cloud_provider}</span></td>
      <td>${evt.anomaly_details.scenario}</td>
      <td><code>${evt.src_endpoint.ip}</code> (${evt.src_endpoint.country})</td>
      <td style="font-weight:700; color:${evt.anomaly_details.risk_score > 90 ? '#ef4444' : '#f97316'}">${evt.anomaly_details.risk_score}</td>
      <td>
        <button class="btn btn-primary" onclick="openRemediationModal('${evt.event_id}')">Playbook</button>
        <button class="btn" onclick="openDetailModal('${evt.event_id}')">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Filter Events based on search bar & dropdowns
function filterEvents() {
  const query = document.getElementById("search-input").value.toLowerCase();
  const severityFilter = document.getElementById("severity-select").value;
  const providerFilter = document.getElementById("provider-select").value;

  const filtered = anomalyEvents.filter(evt => {
    const matchesQuery = evt.actor.user_name.toLowerCase().includes(query) ||
                         evt.anomaly_details.scenario.toLowerCase().includes(query) ||
                         evt.src_endpoint.ip.includes(query) ||
                         evt.src_endpoint.country.toLowerCase().includes(query);
    const matchesSeverity = severityFilter === "ALL" || evt.anomaly_details.severity === severityFilter;
    const matchesProvider = providerFilter === "ALL" || evt.cloud_provider.includes(providerFilter);

    return matchesQuery && matchesSeverity && matchesProvider;
  });

  renderTriageTable(filtered);
}

// Render Interactive Chart.js Visualizations
function renderCharts() {
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

  // Switch to Summary Tab & Run AI Summarizer
  switchModalTab('summary');
  triggerAiSummarization();

  document.getElementById("modal-detail").classList.add("active");
}

// Switch between AI Summary and Raw JSON tabs inside Modal
function switchModalTab(tabName) {
  const summaryBtn = document.getElementById("modal-tab-summary-btn");
  const jsonBtn = document.getElementById("modal-tab-json-btn");
  const summaryView = document.getElementById("modal-view-summary");
  const jsonView = document.getElementById("modal-view-json");

  if (tabName === 'summary') {
    summaryBtn.className = "btn btn-primary";
    jsonBtn.className = "btn";
    summaryView.style.display = "block";
    jsonView.style.display = "none";
  } else {
    summaryBtn.className = "btn";
    jsonBtn.className = "btn btn-primary";
    summaryView.style.display = "none";
    jsonView.style.display = "block";
  }
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
  // If already OCSF format
  if (raw.event_id && raw.actor && raw.anomaly_details) {
    return raw;
  }

  // Generic extraction fallback
  const now = new Date().toISOString();
  const user = raw.UserPrincipalName || raw.user || raw.actor_user || raw.user_email || raw.user_name || "imported.user@cloudorg.internal";
  const ip = raw.IPAddress || raw.src || raw.src_ip || raw.source_ip || "198.51.100.100";
  const country = raw.Country || raw.src_country || raw.source_country || "United States";
  const provider = raw.SourceSystem || raw.cloud_provider || (raw.TenantId ? "Azure / Entra ID" : "AWS");
  const risk = parseFloat(raw.InvestigationPriority || raw.risk_score || raw.elastic_ml_anomaly_score || 85.0);
  const scenario = raw.RiskDetail || raw.rba_threat_category || raw.wazuh_description || "Uploaded SIEM Anomaly Log";
  const summary = raw.SentinelCopilotSummary || raw.splunk_rba_narrative || raw.genai_explanation || raw.ai_attack_narrative || "Ingested log event from uploaded SIEM file.";
  const cli = raw.KQLRemediationQuery || raw.remediation_cli || `aws iam revoke-security-credentials --user-name ${user}`;

  return {
    event_id: `INGEST-${Math.floor(Math.random() * 9000 + 1000)}`,
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

