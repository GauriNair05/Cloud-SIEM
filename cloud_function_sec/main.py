import base64
import json
import functions_framework
from google.cloud import bigquery
from datetime import datetime


bq_client = bigquery.Client()
DATASET_ID = "siem_logs"
TABLE_ID = "security_events"

@functions_framework.cloud_event
def process_security_event(cloud_event):
    """Triggered by a Cloud Pub/Sub message containing GCP audit log telemetry."""
    

    pubsub_message = base64.b64decode(cloud_event.data["message"]["data"]).decode('utf-8')
    log_entry = json.loads(pubsub_message)

    proto_payload = log_entry.get("protoPayload", {})
    method_name = proto_payload.get("methodName", "UNKNOWN")
    principal_email = proto_payload.get("authenticationInfo", {}).get("principalEmail", "UNKNOWN")
    caller_ip = proto_payload.get("requestMetadata", {}).get("callerIp", "UNKNOWN")
    resource_name = proto_payload.get("resourceName", "UNKNOWN")
    timestamp = log_entry.get("timestamp", datetime.utcnow().isoformat())

    print(f"[SECURITY ALERT] Method: {method_name} | User: {principal_email} | IP: {caller_ip}")


    mitre_technique = "T1078 - Valid Accounts"
    severity = "INFORMATIONAL"


    if "SetIamPolicy" in method_name:
        severity = "HIGH"
        mitre_technique = "T1098 - Account Manipulation"
        

        bindings = proto_payload.get("serviceData", {}).get("policyDelta", {}).get("bindingDeltas", [])
        for binding in bindings:
            assigned_role = binding.get("role", "")
            action = binding.get("action", "")
            
            if assigned_role in ["roles/owner", "roles/editor"] and action == "ADD":
                severity = "CRITICAL"
                print(f"[CRITICAL THREAT] Privileged role {assigned_role} granted to {binding.get('member')}")

    elif "CreateServiceAccountKey" in method_name:
        severity = "HIGH"
        mitre_technique = "T1078.004 - Valid Accounts: Cloud Accounts"


    row_to_insert = [{
        "timestamp": timestamp,
        "principal_email": principal_email,
        "method_name": method_name,
        "resource_name": resource_name,
        "caller_ip": caller_ip,
        "severity": severity,
        "mitre_technique": mitre_technique
    }]


    table_ref = f"{bq_client.project}.{DATASET_ID}.{TABLE_ID}"
    errors = bq_client.insert_rows_json(table_ref, row_to_insert)
    
    if not errors:
        print("[SIEM SUCCESS] Log written to BigQuery.")
    else:
        print(f"[SIEM ERROR] Streaming insertion failed: {errors}")
