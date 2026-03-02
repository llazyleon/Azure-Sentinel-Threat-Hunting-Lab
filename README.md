# 🔍 Azure Sentinel Threat Hunting Lab

> **Detecting Azure AD Credential Abuse via Microsoft Sentinel & KQL**  
> *Mapped to MITRE ATT&CK T1098.001 — Account Manipulation: Additional Cloud Credentials*

---

## 📌 Overview

This lab simulates a real-world threat hunting investigation inside **Microsoft Sentinel**, targeting a common cloud attack technique: **unauthorized service principal certificate and secret manipulation** in Azure Active Directory.

Attackers use this technique after initial compromise to add rogue credentials (certificates or client secrets) to existing app registrations — granting persistent, hard-to-detect access to cloud resources even after passwords are reset.

This lab demonstrates how a security analyst can proactively hunt for this behaviour using custom KQL queries before it escalates into a full breach.

---

## 🎯 Objectives

- Hunt for suspicious Azure AD operations using **Microsoft Sentinel Advanced Hunting**
- Write and execute custom **KQL queries** against Azure Audit Logs
- Parse complex nested JSON structures from cloud telemetry
- Correlate **IP addresses, user identities, and user agents** to surface anomalies
- Map findings to the **MITRE ATT&CK Framework**

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|------|---------|
| Microsoft Sentinel | SIEM / Advanced Hunting platform |
| KQL (Kusto Query Language) | Log querying and analysis |
| Azure Active Directory | Source of audit log telemetry |
| Log Analytics Workspace | Backend data store (sentinel-prime) |
| Azure Portal | Lab environment |

---

## 🗂️ Repository Structure

```
azure-sentinel-threat-hunting-lab/
├── README.md
├── queries/
│   └── service-principal-abuse.kql       # Full KQL query used in the investigation
└── screenshots/
    ├── 01-kql-query.png                   # Query in Sentinel Advanced Hunting editor
    ├── 02-results-table.png               # Results table with 5 returned items
    ├── 03-expanded-result.png             # Expanded row showing parsed fields
    └── 04-ip-correlation.png             # Filtered view by suspicious IP
```

---

## 🔎 The KQL Query

```kql
AuditLogs_CL
| where OperationName has_any ("Add service principal", "Certificates and secrets management")
| where Result_s =~ "success"
| mv-expand target = todynamic(TargetResources_s)
| where tostring(tostring(parse_json(tostring(parse_json(InitiatedBy_s).user)).userPrincipalName))
| extend targetDisplayName = tostring(parse_json(TargetResources_s)[0].displayName)
| extend targetId = tostring(parse_json(TargetResources_s)[0].id)
| extend targetType = tostring(parse_json(TargetResources_s)[0].type)
| extend eventtemp = todynamic(TargetResources_s)
| extend keyEvents = eventtemp[0].modifiedProperties
```

### What This Query Does

| Step | Description |
|------|-------------|
| `has_any(...)` | Filters for high-risk operations — adding service principals or managing credentials |
| `Result_s =~ "success"` | Only surfaces successful operations (failed attempts filtered out) |
| `mv-expand` + `todynamic()` | Unpacks nested JSON arrays in the TargetResources field |
| `parse_json()` + `tostring()` | Extracts structured fields: display name, ID, type |
| `keyEvents` | Captures the `modifiedProperties` — what exactly was changed |

---

## 📊 Findings

The query returned **5 results** on **Feb 25, 2026**, all within the same minute (12:25:4x), pointing to a coordinated or scripted operation.

| Timestamp | Operation | User | Source IP | User Agent |
|-----------|-----------|------|-----------|------------|
| Feb 25, 2026 12:25:4 | Update application – Certif… | victim@buildseccxpninja.o | 45.153.160.2 | Mozilla/5.0 |
| Feb 25, 2026 12:25:4 | Update application – Certif… | VadimJ@buildseccxpninja. | 192.168.5.8 | Mozilla/5.0 |
| Feb 25, 2026 12:25:4 | Update application – Certif… | VadimJ@buildseccxpninja. | 185.20.35.69 | python/3.8.9 |

### 🚩 Key Indicators of Compromise

- **Multiple source IPs** for the same user (`VadimJ`) in the same minute — suggests either session hijacking or scripted access from multiple locations
- **45.153.160.2** — External IP associated with `victim@` account — unusual for an internal user
- **185.20.35.69 with python/3.8.9 user agent** — Programmatic access, not a browser. Strong indicator of automated credential addition via script
- All operations targeting **certificate updates** on app registrations — consistent with T1098.001

---

## 🗺️ MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Technique** | T1098 — Account Manipulation |
| **Sub-technique** | T1098.001 — Additional Cloud Credentials |
| **Platform** | Azure AD / Microsoft 365 |
| **Description** | Adversaries add credentials to service principals/app registrations to maintain access independent of user password changes |

---

## 🔮 Future Application & Detection Engineering

This lab's query logic can be operationalized in a production environment:

- **Sentinel Analytics Rule** — Convert this hunt query into a scheduled analytics rule that fires an alert when matching events appear
- **Logic Apps Playbook** — Automatically revoke suspicious certificates, notify the SOC team, or disable the affected app registration on alert trigger
- **Watchlist Integration** — Maintain a watchlist of known-good IPs and flag deviations automatically
- **Workbook Dashboard** — Visualize credential change frequency per app registration over time to surface anomalies

This forms the foundation of a **cloud identity threat detection pipeline** aligned with Zero Trust principles.

---

## 📚 References & Further Reading

- [MITRE ATT&CK T1098.001](https://attack.mitre.org/techniques/T1098/001/)
- [Microsoft Sentinel Advanced Hunting Docs](https://learn.microsoft.com/en-us/azure/sentinel/hunting)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Azure AD Audit Log Schema](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)

---

## 👤 Author

**Ssali Leon Reich**  
Computer Science Engineering BSc — University of Dunaújváros, Hungary  
[LinkedIn](https://www.linkedin.com/in/leon-reich-8367a8291/) · [Email](mailto:reichleon221@gmail.com)

---

*This lab was conducted in a controlled Azure environment for educational and professional development purposes.*
