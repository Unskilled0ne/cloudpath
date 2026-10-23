import fnmatch
from typing import Dict, Any, List, Set, Optional, Literal
from pydantic import BaseModel, Field

class IAMIdentity(BaseModel):
    arn: str
    name: str
    identity_type: Literal["User", "Role", "Group"]
    permissions: Set[str] = Field(default_factory=set)
    admin_privileges: bool = False
    trust_policy: Optional[Dict[str, Any]] = None
    attached_policies: List[str] = Field(default_factory=list)
    has_mfa: bool = False
    access_keys: List[Dict[str, Any]] = Field(default_factory=list)
    stale_keys: List[str] = Field(default_factory=list)

class IAMAuthorizationDetails:
    def __init__(self, raw_data: Dict[str, Any]):
        self.raw = raw_data
        self.users: Dict[str, IAMIdentity] = {}
        self.roles: Dict[str, IAMIdentity] = {}
        self.groups: Dict[str, IAMIdentity] = {}
        self.managed_policies: Dict[str, List[Dict[str, Any]]] = {}
        self._parse()

    def _parse(self):
        for pol in self.raw.get("Policies", []):
            arn = pol.get("Arn", "")
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion", False):
                    statements = ver.get("Document", {}).get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    self.managed_policies[arn] = statements
                    break

        for g in self.raw.get("GroupDetailList", []):
            arn = g.get("Arn", "")
            name = g.get("GroupName", "")
            perms = self._extract_statements_permissions(
                g.get("GroupPolicyList", []),
                g.get("AttachedManagedPolicies", [])
            )
            self.groups[name] = IAMIdentity(
                arn=arn,
                name=name,
                identity_type="Group",
                permissions=perms,
                admin_privileges=self._has_admin(perms)
            )

        for u in self.raw.get("UserDetailList", []):
            arn = u.get("Arn", "")
            name = u.get("UserName", "")
            perms = self._extract_statements_permissions(
                u.get("UserPolicyList", []),
                u.get("AttachedManagedPolicies", [])
            )
            for g_name in u.get("GroupList", []):
                if g_name in self.groups:
                    perms.update(self.groups[g_name].permissions)

            has_mfa = len(u.get("MFADevices", [])) > 0 or u.get("MFAActive", False)
            access_keys = u.get("AccessKeyMetadata", [])
            stale_keys = []
            for k in access_keys:
                if k.get("Status") == "Active":
                    create_date = k.get("CreateDate", "")
                    if "2020" in str(create_date) or "2021" in str(create_date) or "2022" in str(create_date) or "2023" in str(create_date):
                        stale_keys.append(k.get("AccessKeyId", ""))

            self.users[arn] = IAMIdentity(
                arn=arn,
                name=name,
                identity_type="User",
                permissions=perms,
                admin_privileges=self._has_admin(perms),
                has_mfa=has_mfa,
                access_keys=access_keys,
                stale_keys=stale_keys,
                attached_policies=[p.get("PolicyArn", "") for p in u.get("AttachedManagedPolicies", [])]
            )

        for r in self.raw.get("RoleDetailList", []):
            arn = r.get("Arn", "")
            name = r.get("RoleName", "")
            perms = self._extract_statements_permissions(
                r.get("RolePolicyList", []),
                r.get("AttachedManagedPolicies", [])
            )
            trust_policy = r.get("AssumeRolePolicyDocument", {})

            self.roles[arn] = IAMIdentity(
                arn=arn,
                name=name,
                identity_type="Role",
                permissions=perms,
                admin_privileges=self._has_admin(perms),
                trust_policy=trust_policy,
                attached_policies=[p.get("PolicyArn", "") for p in r.get("AttachedManagedPolicies", [])]
            )

    def _extract_statements_permissions(
        self,
        inline_policies: List[Dict[str, Any]],
        attached_managed: List[Dict[str, Any]]
    ) -> Set[str]:
        permissions: Set[str] = set()

        for inline in inline_policies:
            doc = inline.get("PolicyDocument", {})
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            self._accumulate_actions(stmts, permissions)

        for managed in attached_managed:
            arn = managed.get("PolicyArn", "")
            stmts = self.managed_policies.get(arn, [])
            self._accumulate_actions(stmts, permissions)

        return permissions

    def _accumulate_actions(self, statements: List[Dict[str, Any]], target_set: Set[str]):
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for act in actions:
                target_set.add(act.lower())

    def _has_admin(self, permissions: Set[str]) -> bool:
        if "*" in permissions or "*:*" in permissions:
            return True
        admin_actions = {
            "iam:*",
            "administratoraccess"
        }
        return any(act in permissions for act in admin_actions)

def match_permission(permissions: Set[str], action: str) -> bool:
    action_lower = action.lower()
    if "*" in permissions or "*:*" in permissions:
        return True
    for p in permissions:
        if fnmatch.fnmatch(action_lower, p):
            return True
    return False
