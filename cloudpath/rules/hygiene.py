import re
from typing import List
from pydantic import BaseModel
from cloudpath.parser import IAMAuthorizationDetails

class HygieneFinding(BaseModel):
    rule_id: str
    name: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    identity: str
    description: str
    remediation: str

class HygieneRuleEngine:
    def __init__(self, auth: IAMAuthorizationDetails):
        self.auth = auth

    def evaluate_all(self) -> List[HygieneFinding]:
        findings = []
        findings.extend(self.check_mfa_status())
        findings.extend(self.check_stale_keys())
        findings.extend(self.check_cross_account_trust())
        findings.extend(self.check_wildcard_permissions())
        return findings

    def check_mfa_status(self) -> List[HygieneFinding]:
        findings = []
        for arn, u in self.auth.users.items():
            if not u.has_mfa and (u.admin_privileges or len(u.access_keys) > 0):
                findings.append(HygieneFinding(
                    rule_id="CP-HYG-01",
                    name="MFA Not Configured on Privileged User",
                    severity="HIGH" if u.admin_privileges else "MEDIUM",
                    identity=arn,
                    description=f"User {u.name} has active credentials/admin rights but lacks Multi-Factor Authentication (MFA).",
                    remediation="Enforce mandatory virtual MFA device registration via IAM policy condition."
                ))
        return findings

    def check_stale_keys(self) -> List[HygieneFinding]:
        findings = []
        for arn, u in self.auth.users.items():
            if u.stale_keys:
                findings.append(HygieneFinding(
                    rule_id="CP-HYG-02",
                    name="Stale Access Keys Exceeding Retention Limit",
                    severity="MEDIUM",
                    identity=arn,
                    description=f"User {u.name} maintains {len(u.stale_keys)} active IAM access key(s) created over 90 days ago: {', '.join(u.stale_keys)}",
                    remediation="Rotate active access keys every 90 days and deactivate unused credentials."
                ))
        return findings

    def check_cross_account_trust(self) -> List[HygieneFinding]:
        findings = []
        for arn, r in self.auth.roles.items():
            trust_doc = r.trust_policy or {}
            stmts = trust_doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", {})
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_p = principal["AWS"]
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            acct_match = re.search(r"arn:aws:iam::(\d{12}):", p)
                            if acct_match:
                                target_acct = acct_match.group(1)
                                if target_acct not in arn:
                                    findings.append(HygieneFinding(
                                        rule_id="CP-HYG-03",
                                        name="Cross-Account AssumeRole Trust Relationship",
                                        severity="HIGH" if r.admin_privileges else "MEDIUM",
                                        identity=arn,
                                        description=f"Role {r.name} trusts external AWS account {target_acct} via AssumeRole.",
                                        remediation="Verify third-party trust relationships and mandate external ID conditions (sts:ExternalId)."
                                    ))
        return findings

    def check_wildcard_permissions(self) -> List[HygieneFinding]:
        findings = []
        for arn, u in self.auth.users.items():
            if "*" in u.permissions or "*:*" in u.permissions:
                findings.append(HygieneFinding(
                    rule_id="CP-HYG-04",
                    name="Full Wildcard Permissions Statement",
                    severity="HIGH",
                    identity=arn,
                    description=f"User {u.name} possesses full wildcard Action: '*' statement.",
                    remediation="Apply least privilege by replacing Action: '*' with specific API operations."
                ))
        return findings
