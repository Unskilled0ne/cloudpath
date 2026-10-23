import os
import requests
from typing import Dict, Any, List

DEFAULT_SOAR_URL = os.environ.get("SOAR_INVESTIGATE_URL", "http://127.0.0.1:8082/api/v1/alerts/investigate")

class CloudPathSOARBridge:
    def __init__(self, soar_url: str = DEFAULT_SOAR_URL):
        self.soar_url = soar_url

    def dispatch_critical_escalations(self, escalation_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        dispatched = []
        for path in escalation_paths:
            if path.get("severity") != "CRITICAL":
                continue

            alert_payload = {
                "source": "cloudpath_iam_auditor",
                "event_type": f"IAM Privilege Escalation Path: {path.get('name')}",
                "severity": "CRITICAL",
                "source_ip": "127.0.0.1",
                "user_identity": path.get("source_identity"),
                "raw_log": f"CloudPath detected privilege escalation: {path.get('description')} Chain: {' -> '.join(path.get('attack_chain', []))}",
                "metadata": {
                    "rule_id": path.get("rule_id"),
                    "target_identity": path.get("target_identity"),
                    "hop_count": path.get("hop_count"),
                    "mitre_attack": path.get("mitre_attack_id"),
                    "remediation": path.get("remediation")
                }
            }

            try:
                resp = requests.post(self.soar_url, json=alert_payload, timeout=2.0)
                if resp.status_code in (200, 201):
                    dispatched.append({
                        "rule_id": path.get("rule_id"),
                        "status": "DISPATCHED_TO_AEGIS_SOAR",
                        "response": resp.json()
                    })
                else:
                    dispatched.append({
                        "rule_id": path.get("rule_id"),
                        "status": f"BUFFERED_LOCAL_HTTP_{resp.status_code}"
                    })
            except Exception as e:
                dispatched.append({
                    "rule_id": path.get("rule_id"),
                    "status": f"BUFFERED_LOCAL_OFFLINE: {e}"
                })

        return dispatched
