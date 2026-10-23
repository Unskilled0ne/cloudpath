from typing import List, Dict, Any, Set
from pydantic import BaseModel
from cloudpath.parser import IAMAuthorizationDetails, match_permission
from cloudpath.graph import IAMAttackGraph

class EscalationFinding(BaseModel):
    rule_id: str
    name: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    source_identity: str
    target_identity: str
    mitre_attack_id: str
    description: str
    hop_count: int
    attack_chain: List[str]
    remediation: str

class EscalationRuleEngine:
    def __init__(self, auth: IAMAuthorizationDetails, attack_graph: IAMAttackGraph):
        self.auth = auth
        self.attack_graph = attack_graph

    def evaluate_all(self) -> List[EscalationFinding]:
        findings = []
        findings.extend(self.detect_passrole_compute())
        findings.extend(self.detect_create_access_key())
        findings.extend(self.detect_attach_policy_privesc())
        findings.extend(self.detect_assumerole_chains())
        findings.extend(self.detect_wildcard_trust())
        findings.extend(self.detect_login_profile_hijack())
        findings.extend(self.detect_update_trust_policy())
        findings.extend(self.detect_policy_version_privesc())
        return sorted(findings, key=lambda f: (0 if f.severity == "CRITICAL" else 1, f.hop_count))

    def detect_passrole_compute(self) -> List[EscalationFinding]:
        findings = []
        compute_actions = [
            "lambda:createfunction", "ec2:runinstances", "ecs:runtask",
            "glue:createjob", "codebuild:startbuild"
        ]

        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            has_pass = match_permission(u.permissions, "iam:PassRole")
            has_compute = any(match_permission(u.permissions, a) for a in compute_actions)

            if has_pass and has_compute:
                for r_arn, r in self.auth.roles.items():
                    if r.admin_privileges:
                        findings.append(EscalationFinding(
                            rule_id="CP-ESC-01",
                            name="PassRole with Compute Execution",
                            severity="CRITICAL",
                            source_identity=u_arn,
                            target_identity=r_arn,
                            mitre_attack_id="T1548 / T1078.004",
                            description=f"Identity {u.name} can pass high-privilege role {r.name} to compute services to execute code with admin permissions.",
                            hop_count=1,
                            attack_chain=[f"{u.name} [iam:PassRole + Compute] -> {r.name}"],
                            remediation="Scope iam:PassRole Resource to least-privilege non-administrative roles."
                        ))
        return findings

    def detect_create_access_key(self) -> List[EscalationFinding]:
        findings = []
        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            if match_permission(u.permissions, "iam:CreateAccessKey"):
                for target_arn, target_u in self.auth.users.items():
                    if u_arn != target_arn and target_u.admin_privileges:
                        findings.append(EscalationFinding(
                            rule_id="CP-ESC-02",
                            name="CreateAccessKey on Privileged User",
                            severity="CRITICAL",
                            source_identity=u_arn,
                            target_identity=target_arn,
                            mitre_attack_id="T1098",
                            description=f"Identity {u.name} has permission to generate active API access keys for administrative user {target_u.name}.",
                            hop_count=1,
                            attack_chain=[f"{u.name} [iam:CreateAccessKey] -> {target_u.name}"],
                            remediation="Revoke iam:CreateAccessKey or restrict Resource to own ARN (${aws:username})."
                        ))
        return findings

    def detect_attach_policy_privesc(self) -> List[EscalationFinding]:
        findings = []
        grant_actions = ["iam:attachuserpolicy", "iam:attachrolepolicy", "iam:putuserpolicy", "iam:putrolepolicy"]

        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            for act in grant_actions:
                if match_permission(u.permissions, act):
                    findings.append(EscalationFinding(
                        rule_id="CP-ESC-03",
                        name="Direct Policy Self-Attachment",
                        severity="CRITICAL",
                        source_identity=u_arn,
                        target_identity=u_arn,
                        mitre_attack_id="T1098.001",
                        description=f"Identity {u.name} can attach administrator policies or inject inline allow-all statements to grant self full privileges.",
                        hop_count=0,
                        attack_chain=[f"{u.name} [{act}] -> AdministratorAccess"],
                        remediation="Apply IAM Permission Boundaries to restrict policy attachment capabilities."
                    ))
                    break
        return findings

    def detect_assumerole_chains(self) -> List[EscalationFinding]:
        findings = []
        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            paths = self.attack_graph.find_paths_to_admin(u_arn)
            for path in paths:
                chain_str = " -> ".join([f"{step[0].split('/')[-1]} [{step[1]}]" for step in path]) + f" -> {path[-1][2].split('/')[-1]}"
                findings.append(EscalationFinding(
                    rule_id="CP-ESC-04",
                    name="Multi-Hop AssumeRole Chain to Admin",
                    severity="HIGH" if len(path) > 1 else "CRITICAL",
                    source_identity=u_arn,
                    target_identity=path[-1][2],
                    mitre_attack_id="T1548 / T1078.004",
                    description=f"Identity {u.name} can escalate to administrative role {path[-1][2].split('/')[-1]} across {len(path)} hops.",
                    hop_count=len(path),
                    attack_chain=[chain_str],
                    remediation="Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions."
                ))
        return findings

    def detect_wildcard_trust(self) -> List[EscalationFinding]:
        findings = []
        for r_arn, r in self.auth.roles.items():
            trust_doc = r.trust_policy or {}
            stmts = trust_doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", {})
                    is_wildcard = principal == "*" or principal == {"AWS": "*"}
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_p = principal["AWS"]
                        if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                            is_wildcard = True

                    if is_wildcard:
                        findings.append(EscalationFinding(
                            rule_id="CP-ESC-05",
                            name="Wildcard Principal Trust Policy",
                            severity="CRITICAL" if r.admin_privileges else "HIGH",
                            source_identity="* (Any Identity)",
                            target_identity=r_arn,
                            mitre_attack_id="T1199",
                            description=f"Role {r.name} has a wildcard trust policy (Principal: *), allowing arbitrary external identities to assume it.",
                            hop_count=0,
                            attack_chain=[f"External Attacker -> sts:AssumeRole -> {r.name}"],
                            remediation="Specify explicit account IDs or role ARNs in AssumeRolePolicyDocument."
                        ))
        return findings

    def detect_login_profile_hijack(self) -> List[EscalationFinding]:
        findings = []
        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            can_profile = match_permission(u.permissions, "iam:CreateLoginProfile") or match_permission(u.permissions, "iam:UpdateLoginProfile")
            if can_profile:
                for target_arn, target_u in self.auth.users.items():
                    if u_arn != target_arn and target_u.admin_privileges:
                        findings.append(EscalationFinding(
                            rule_id="CP-ESC-06",
                            name="Console Login Password Reset / Hijack",
                            severity="CRITICAL",
                            source_identity=u_arn,
                            target_identity=target_arn,
                            mitre_attack_id="T1098",
                            description=f"Identity {u.name} can reset the AWS Management Console password for administrator {target_u.name}.",
                            hop_count=1,
                            attack_chain=[f"{u.name} [iam:CreateLoginProfile] -> {target_u.name} Console Login"],
                            remediation="Prevent non-administrators from managing login profiles across other identities."
                        ))
        return findings

    def detect_update_trust_policy(self) -> List[EscalationFinding]:
        findings = []
        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            if match_permission(u.permissions, "iam:UpdateAssumeRolePolicy"):
                for r_arn, r in self.auth.roles.items():
                    if r.admin_privileges:
                        findings.append(EscalationFinding(
                            rule_id="CP-ESC-07",
                            name="UpdateAssumeRolePolicy Trust Modification",
                            severity="CRITICAL",
                            source_identity=u_arn,
                            target_identity=r_arn,
                            mitre_attack_id="T1098",
                            description=f"Identity {u.name} can alter the trust policy of role {r.name} to trust self, enabling full admin assumption.",
                            hop_count=1,
                            attack_chain=[f"{u.name} [iam:UpdateAssumeRolePolicy] -> {r.name}"],
                            remediation="Restrict iam:UpdateAssumeRolePolicy to privileged identity administrators."
                        ))
        return findings

    def detect_policy_version_privesc(self) -> List[EscalationFinding]:
        findings = []
        for u_arn, u in self.auth.users.items():
            if u.admin_privileges:
                continue
            can_create_ver = match_permission(u.permissions, "iam:CreatePolicyVersion")
            can_set_default = match_permission(u.permissions, "iam:SetDefaultPolicyVersion")
            if can_create_ver or can_set_default:
                findings.append(EscalationFinding(
                    rule_id="CP-ESC-08",
                    name="IAM Policy Version Rollback / Creation",
                    severity="CRITICAL",
                    source_identity=u_arn,
                    target_identity=u_arn,
                    mitre_attack_id="T1098",
                    description=f"Identity {u.name} can create new versions of managed policies or roll back to historical versions containing admin rights.",
                    hop_count=0,
                    attack_chain=[f"{u.name} [iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion] -> AdministratorAccess"],
                    remediation="Enforce policy version pruning and restrict policy versioning permissions."
                ))
        return findings
