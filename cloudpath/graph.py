from typing import Dict, Any, List, Tuple
import networkx as nx
from cloudpath.parser import IAMAuthorizationDetails, match_permission

class IAMAttackGraph:
    def __init__(self, auth_details: IAMAuthorizationDetails):
        self.auth = auth_details
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        for arn, u in self.auth.users.items():
            self.graph.add_node(
                arn,
                name=u.name,
                type="User",
                is_admin=u.admin_privileges,
                has_mfa=u.has_mfa,
                stale_keys=u.stale_keys,
                permissions=u.permissions
            )

        for arn, r in self.auth.roles.items():
            self.graph.add_node(
                arn,
                name=r.name,
                type="Role",
                is_admin=r.admin_privileges,
                permissions=r.permissions,
                trust_policy=r.trust_policy
            )

        for src_arn, src_user in self.auth.users.items():
            self._evaluate_identity_edges(src_arn, src_user.permissions)

        for src_arn, src_role in self.auth.roles.items():
            self._evaluate_identity_edges(src_arn, src_role.permissions)

    def _evaluate_identity_edges(self, src_arn: str, perms: set):
        can_assume = match_permission(perms, "sts:AssumeRole")
        can_pass = match_permission(perms, "iam:PassRole")
        can_attach_user = match_permission(perms, "iam:AttachUserPolicy")
        can_attach_role = match_permission(perms, "iam:AttachRolePolicy")
        can_create_key = match_permission(perms, "iam:CreateAccessKey")
        can_put_role_policy = match_permission(perms, "iam:PutRolePolicy")
        can_put_user_policy = match_permission(perms, "iam:PutUserPolicy")
        can_update_trust = match_permission(perms, "iam:UpdateAssumeRolePolicy")
        can_login_profile = match_permission(perms, "iam:CreateLoginProfile") or match_permission(perms, "iam:UpdateLoginProfile")

        for target_arn, target_role in self.auth.roles.items():
            if src_arn == target_arn:
                continue

            if can_assume and self._trusts_principal(target_role.trust_policy, src_arn):
                self.graph.add_edge(src_arn, target_arn, relation="CAN_ASSUME", weight=1)

            if can_pass:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_PASS_ROLE", weight=2)

            if can_attach_role:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_ATTACH_POLICY", weight=1)

            if can_put_role_policy:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_PUT_POLICY", weight=1)

            if can_update_trust:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_UPDATE_TRUST", weight=1)

        for target_arn, target_user in self.auth.users.items():
            if src_arn == target_arn:
                continue

            if can_attach_user:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_ATTACH_POLICY", weight=1)

            if can_put_user_policy:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_PUT_POLICY", weight=1)

            if can_create_key:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_CREATE_KEY", weight=1)

            if can_login_profile:
                self.graph.add_edge(src_arn, target_arn, relation="CAN_MANAGE_LOGIN", weight=1)

    def _trusts_principal(self, trust_doc: dict, principal_arn: str) -> bool:
        if not trust_doc:
            return False
        stmts = trust_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*" or principal == {"AWS": "*"}:
                return True
            if isinstance(principal, dict):
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                if "*" in aws_principals or principal_arn in aws_principals:
                    return True
        return False

    def find_paths_to_admin(self, source_arn: str) -> List[List[Tuple[str, str, str]]]:
        paths = []
        if source_arn not in self.graph:
            return []

        admin_nodes = [
            n for n, data in self.graph.nodes(data=True)
            if data.get("is_admin") and n != source_arn
        ]

        for admin_arn in admin_nodes:
            if nx.has_path(self.graph, source_arn, admin_arn):
                for p in nx.all_shortest_paths(self.graph, source_arn, admin_arn):
                    edge_chain = []
                    for i in range(len(p) - 1):
                        u, v = p[i], p[i+1]
                        rel = self.graph.get_edge_data(u, v, {}).get("relation", "TRANSIT")
                        edge_chain.append((u, rel, v))
                    paths.append(edge_chain)

        return paths
