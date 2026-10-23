import json
from typing import Dict, Any, List
from cloudpath.parser import IAMAuthorizationDetails
from cloudpath.graph import IAMAttackGraph
from cloudpath.rules.escalation import EscalationRuleEngine, EscalationFinding
from cloudpath.rules.hygiene import HygieneRuleEngine, HygieneFinding

class CloudPathAnalyzer:
    def __init__(self, raw_iam_data: Dict[str, Any]):
        self.raw_data = raw_iam_data
        self.auth = IAMAuthorizationDetails(self.raw_data)
        self.attack_graph = IAMAttackGraph(self.auth)
        self.escalation_engine = EscalationRuleEngine(self.auth, self.attack_graph)
        self.hygiene_engine = HygieneRuleEngine(self.auth)

    @classmethod
    def from_file(cls, filepath: str) -> "CloudPathAnalyzer":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def analyze(self) -> Dict[str, Any]:
        escalation_paths = self.escalation_engine.evaluate_all()
        hygiene_findings = self.hygiene_engine.evaluate_all()

        crit_count = sum(1 for f in escalation_paths if f.severity == "CRITICAL")
        high_count = sum(1 for f in escalation_paths if f.severity == "HIGH") + sum(1 for f in hygiene_findings if f.severity == "HIGH")
        med_count = sum(1 for f in hygiene_findings if f.severity == "MEDIUM")

        deduction = (crit_count * 20) + (high_count * 8) + (med_count * 3)
        posture_score = max(0, 100 - deduction)

        return {
            "summary": {
                "posture_score": posture_score,
                "total_users": len(self.auth.users),
                "total_roles": len(self.auth.roles),
                "total_groups": len(self.auth.groups),
                "total_escalation_paths": len(escalation_paths),
                "critical_escalations": crit_count,
                "hygiene_issues": len(hygiene_findings)
            },
            "escalation_paths": [f.model_dump() for f in escalation_paths],
            "hygiene_findings": [f.model_dump() for f in hygiene_findings],
            "graph_metrics": {
                "total_nodes": self.attack_graph.graph.number_of_nodes(),
                "total_edges": self.attack_graph.graph.number_of_edges()
            }
        }
