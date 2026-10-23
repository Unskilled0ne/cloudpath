# CloudPath: IAM Attack-Path & Privilege Escalation Audit Report

**Generated:** 2026-10-23 17:42:12 UTC  
**IAM Security Posture Score:** 0/100  
**Analyzed Identities:** 5 Users, 4 Roles, 0 Groups  
**Total Attack Paths Discovered:** 33 (Critical: 12)  

---

## 1. Executive Summary
CloudPath analyzed the AWS IAM account authorization details using directed graph pathfinding. The audit identified **33 privilege escalation vectors** allowing non-administrative identities to acquire full administrative permissions, along with **3 hygiene findings**.

---

## 2. Ranked Privilege Escalation Paths

### Path #1: Direct Policy Self-Attachment (`CP-ESC-03`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **MITRE ATT&CK Cloud Mapping:** `T1098.001`
- **Hop Count:** `0`
- **Description:** Identity ci-deployer can attach administrator policies or inject inline allow-all statements to grant self full privileges.
- **Attack Chain:**
```
ci-deployer [iam:attachuserpolicy] -> AdministratorAccess
```
- **Remediation Action:**
> Apply IAM Permission Boundaries to restrict policy attachment capabilities.

### Path #2: Wildcard Principal Trust Policy (`CP-ESC-05`)
- **Severity:** `CRITICAL`
- **Source Identity:** `* (Any Identity)`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1199`
- **Hop Count:** `0`
- **Description:** Role vendor-data-sync has a wildcard trust policy (Principal: *), allowing arbitrary external identities to assume it.
- **Attack Chain:**
```
External Attacker -> sts:AssumeRole -> vendor-data-sync
```
- **Remediation Action:**
> Specify explicit account IDs or role ARNs in AssumeRolePolicyDocument.

### Path #3: PassRole with Compute Execution (`CP-ESC-01`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can pass high-privilege role admin-compute-role to compute services to execute code with admin permissions.
- **Attack Chain:**
```
dev-lambda-runner [iam:PassRole + Compute] -> admin-compute-role
```
- **Remediation Action:**
> Scope iam:PassRole Resource to least-privilege non-administrative roles.

### Path #4: PassRole with Compute Execution (`CP-ESC-01`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can pass high-privilege role admin-breakglass-role to compute services to execute code with admin permissions.
- **Attack Chain:**
```
dev-lambda-runner [iam:PassRole + Compute] -> admin-breakglass-role
```
- **Remediation Action:**
> Scope iam:PassRole Resource to least-privilege non-administrative roles.

### Path #5: PassRole with Compute Execution (`CP-ESC-01`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can pass high-privilege role vendor-data-sync to compute services to execute code with admin permissions.
- **Attack Chain:**
```
dev-lambda-runner [iam:PassRole + Compute] -> vendor-data-sync
```
- **Remediation Action:**
> Scope iam:PassRole Resource to least-privilege non-administrative roles.

### Path #6: CreateAccessKey on Privileged User (`CP-ESC-02`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1098`
- **Hop Count:** `1`
- **Description:** Identity intern-security has permission to generate active API access keys for administrative user admin-executive.
- **Attack Chain:**
```
intern-security [iam:CreateAccessKey] -> admin-executive
```
- **Remediation Action:**
> Revoke iam:CreateAccessKey or restrict Resource to own ARN (${aws:username}).

### Path #7: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can escalate to administrative role admin-compute-role across 1 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #8: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can escalate to administrative role admin-breakglass-role across 1 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #9: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity dev-lambda-runner can escalate to administrative role vendor-data-sync across 1 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #10: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity intern-security can escalate to administrative role admin-executive across 1 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #11: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity ci-deployer can escalate to administrative role admin-executive across 1 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #12: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `CRITICAL`
- **Source Identity:** `arn:aws:iam::123456789012:user/audit-contractor`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `1`
- **Description:** Identity audit-contractor can escalate to administrative role vendor-data-sync across 1 hops.
- **Attack Chain:**
```
audit-contractor [CAN_ASSUME] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #13: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity dev-lambda-runner can escalate to administrative role admin-executive across 2 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> admin-compute-role [CAN_MANAGE_LOGIN] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #14: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity dev-lambda-runner can escalate to administrative role admin-executive across 2 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> admin-breakglass-role [CAN_MANAGE_LOGIN] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #15: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/dev-lambda-runner`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity dev-lambda-runner can escalate to administrative role admin-executive across 2 hops.
- **Attack Chain:**
```
dev-lambda-runner [CAN_PASS_ROLE] -> vendor-data-sync [CAN_MANAGE_LOGIN] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #16: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role admin-compute-role across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> dev-lambda-runner [CAN_PASS_ROLE] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #17: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role admin-compute-role across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> admin-executive [CAN_UPDATE_TRUST] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #18: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> dev-lambda-runner [CAN_PASS_ROLE] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #19: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> admin-executive [CAN_UPDATE_TRUST] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #20: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> dev-lambda-runner [CAN_PASS_ROLE] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #21: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> audit-contractor [CAN_ASSUME] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #22: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/intern-security`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity intern-security can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
intern-security [CAN_CREATE_KEY] -> admin-executive [CAN_UPDATE_TRUST] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #23: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role admin-compute-role across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> dev-lambda-runner [CAN_PASS_ROLE] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #24: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role admin-compute-role across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> admin-executive [CAN_UPDATE_TRUST] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #25: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> dev-lambda-runner [CAN_PASS_ROLE] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #26: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> admin-executive [CAN_UPDATE_TRUST] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #27: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> dev-lambda-runner [CAN_PASS_ROLE] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #28: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> audit-contractor [CAN_ASSUME] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #29: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Target Identity:** `arn:aws:iam::123456789012:role/vendor-data-sync`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity ci-deployer can escalate to administrative role vendor-data-sync across 2 hops.
- **Attack Chain:**
```
ci-deployer [CAN_PUT_POLICY] -> admin-executive [CAN_UPDATE_TRUST] -> vendor-data-sync
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #30: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/audit-contractor`
- **Target Identity:** `arn:aws:iam::123456789012:user/admin-executive`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity audit-contractor can escalate to administrative role admin-executive across 2 hops.
- **Attack Chain:**
```
audit-contractor [CAN_ASSUME] -> vendor-data-sync [CAN_MANAGE_LOGIN] -> admin-executive
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #31: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/audit-contractor`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-compute-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity audit-contractor can escalate to administrative role admin-compute-role across 2 hops.
- **Attack Chain:**
```
audit-contractor [CAN_ASSUME] -> vendor-data-sync [CAN_UPDATE_TRUST] -> admin-compute-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #32: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/audit-contractor`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity audit-contractor can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
audit-contractor [CAN_ASSUME] -> staging-support-role [CAN_ASSUME] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

### Path #33: Multi-Hop AssumeRole Chain to Admin (`CP-ESC-04`)
- **Severity:** `HIGH`
- **Source Identity:** `arn:aws:iam::123456789012:user/audit-contractor`
- **Target Identity:** `arn:aws:iam::123456789012:role/admin-breakglass-role`
- **MITRE ATT&CK Cloud Mapping:** `T1548 / T1078.004`
- **Hop Count:** `2`
- **Description:** Identity audit-contractor can escalate to administrative role admin-breakglass-role across 2 hops.
- **Attack Chain:**
```
audit-contractor [CAN_ASSUME] -> vendor-data-sync [CAN_UPDATE_TRUST] -> admin-breakglass-role
```
- **Remediation Action:**
> Audit sts:AssumeRole trust relationships and remove transitive lateral movement permissions.

---

## 3. Identity Hygiene Findings

| Rule ID | Finding | Severity | Identity | Remediation |
|---|---|---|---|---|
| `CP-HYG-01` | MFA Not Configured on Privileged User | `MEDIUM` | `dev-lambda-runner` | Enforce mandatory virtual MFA device registration via IAM policy condition. |
| `CP-HYG-02` | Stale Access Keys Exceeding Retention Limit | `MEDIUM` | `dev-lambda-runner` | Rotate active access keys every 90 days and deactivate unused credentials. |
| `CP-HYG-04` | Full Wildcard Permissions Statement | `HIGH` | `admin-executive` | Apply least privilege by replacing Action: '*' with specific API operations. |
