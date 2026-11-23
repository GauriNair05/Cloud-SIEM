# Automated Cloud Incident Response & SIEM Pipeline on GCP

Serverless, event-driven detection pipeline that watches Google Cloud IAM audit logs for privilege-escalation activity, classifies each event by severity, maps it to MITRE ATT&CK, and stores structured records in BigQuery for SQL threat hunting.

**Stack:** GCP Cloud Logging, Pub/Sub, Cloud Functions (Gen 2), BigQuery, Python 3.11, SQL

## Why this project

In cloud environments, compromised IAM credentials let an attacker run valid administrative actions, such as granting elevated permissions or creating service account keys, without triggering traditional operating-system alarms. The signal lives in the audit logs. This pipeline turns those logs into searchable, severity-tagged security events within seconds of the action.

## Architecture

```
Cloud Logging (admin activity audit logs)
        |  Log Router sink (filter: SetIamPolicy, CreateServiceAccountKey)
        v
   Pub/Sub topic
        |  triggers
        v
Cloud Function (Gen 2, Python 3.11)
   decode -> extract -> classify -> map to MITRE ATT&CK
        |  streaming insert
        v
BigQuery table: security_events
```

1. **Ingestion:** Cloud Logging captures administrative write events (`protoPayload`).
2. **Filtered routing:** A Log Router sink selects only the IAM modifications `SetIamPolicy` and `CreateServiceAccountKey` and publishes them to Pub/Sub.
3. **Processing:** A Python Cloud Function (Gen 2) receives each base64-encoded CloudEvent, decodes the audit payload, and extracts the principal, the action, and the caller IP.
4. **Detection and mapping:** The function inspects the policy change, for example a grant of `roles/owner`, assigns a severity, and attaches the matching MITRE ATT&CK technique ID.
5. **Storage:** The function writes the structured record to BigQuery, where analysts query it with SQL.

## Detection rules

| Audit event | Detected pattern | Severity | MITRE ATT&CK technique | ID |
| :--- | :--- | :--- | :--- | :--- |
| `SetIamPolicy` | Over-privileged role assignment (`roles/owner` or `roles/editor`) | **CRITICAL** | Account Manipulation | **T1098** |
| `SetIamPolicy` | Standard IAM permission update | **HIGH** | Account Manipulation | **T1098** |
| `CreateServiceAccountKey` | Long-term service account key generation | **HIGH** | Valid Accounts: Cloud Accounts | **T1078.004** |

Detection is rule-based. The function flags every owner or editor grant as CRITICAL; it does not judge whether a given grant was authorized.

## Event record

Each event is stored as one row in the BigQuery table `security_events`. The schema is defined in `schema.json`.

| Field | Type | Mode | Description |
| :--- | :--- | :--- | :--- |
| `timestamp` | TIMESTAMP | REQUIRED | When the security event occurred |
| `principal_email` | STRING | NULLABLE | User or service account that performed the action |
| `method_name` | STRING | REQUIRED | GCP API method invoked, for example `SetIamPolicy` |
| `resource_name` | STRING | NULLABLE | Target GCP resource affected by the change |
| `caller_ip` | STRING | NULLABLE | Originating IP address of the caller |
| `severity` | STRING | REQUIRED | Assigned severity: `INFORMATIONAL`, `HIGH` or `CRITICAL` |
| `mitre_technique` | STRING | NULLABLE | Mapped MITRE ATT&CK technique, for example `T1098 - Account Manipulation` |

## Proof of execution

### 1. Detection function

The function parses an incoming `SetIamPolicy` event, detects a `roles/owner` assignment, flags it as `CRITICAL`, and writes it to BigQuery.

![Cloud Function execution log](./assets/screenshot1.png)

### 2. BigQuery event log

Structured events in BigQuery, ready for threat hunting.

![BigQuery query output](./assets/screenshot2.png)

```sql
SELECT timestamp, principal_email, method_name, severity, mitre_technique
FROM `YOUR_PROJECT_ID.siem_logs.security_events`
ORDER BY timestamp DESC
LIMIT 5;
```

## Repository layout

| Path | Contents |
| :--- | :--- |
| `cloud_function_sec/` | Cloud Function source code |
| `schema.json` | BigQuery table schema for `security_events` (7 fields) |
| `assets/` | Screenshots used in this README |

## Limitations and next steps

- The pipeline detects and records. It does not respond: nothing here revokes a key, removes a binding, or alerts a person.
- Only two event types are covered. Other privilege-escalation paths, such as role creation or service account impersonation, are not detected.
- Severity comes from fixed rules, with no baseline of what is normal for a given principal.

Next steps: add automated containment for CRITICAL events (for example, removing the offending role binding), send alerts through a notification channel, and extend the rules to more audit event types.
