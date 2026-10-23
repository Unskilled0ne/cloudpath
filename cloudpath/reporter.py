import json
import os
from datetime import datetime, timezone
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class CloudPathReporter:
    def __init__(self, analysis_result: Dict[str, Any]):
        self.data = analysis_result
        self.summary = self.data["summary"]
        self.escalations = self.data["escalation_paths"]
        self.hygiene = self.data["hygiene_findings"]

    def print_cli_summary(self):
        console.print()
        score = self.summary["posture_score"]
        score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
        
        console.print(Panel.fit(
            f"[bold cyan]CloudPath: IAM Attack-Path & Privilege Escalation Auditor[/bold cyan]\n"
            f"[dim]Graph-Theoretic Privilege Escalation Detection for Cloud Identities[/dim]\n\n"
            f"IAM Posture Score: [{score_color}]{score}/100[/{score_color}] | "
            f"Critical Escalation Paths: [bold red]{self.summary['critical_escalations']}[/bold red] | "
            f"Hygiene Issues: [yellow]{self.summary['hygiene_issues']}[/yellow]",
            border_style="cyan"
        ))

        esc_table = Table(title="Ranked Privilege Escalation Attack Paths", border_style="dim")
        esc_table.add_column("Rule ID", style="bold cyan")
        esc_table.add_column("Attack Vector", style="bold white")
        esc_table.add_column("Severity", justify="center")
        esc_table.add_column("Source Identity", style="dim")
        esc_table.add_column("Target Identity", style="bold red")
        esc_table.add_column("Hops", justify="center")
        esc_table.add_column("MITRE ATT&CK", style="yellow")

        for f in self.escalations:
            sev_badge = f"[bold red]{f['severity']}[/bold red]" if f["severity"] == "CRITICAL" else f"[yellow]{f['severity']}[/yellow]"
            src_short = f["source_identity"].split("/")[-1]
            tgt_short = f["target_identity"].split("/")[-1]
            esc_table.add_row(
                f["rule_id"],
                f["name"],
                sev_badge,
                src_short,
                tgt_short,
                str(f["hop_count"]),
                f["mitre_attack_id"]
            )

        console.print(esc_table)
        console.print()

        if self.hygiene:
            hyg_table = Table(title="IAM Hygiene & Identity Posture Findings", border_style="dim")
            hyg_table.add_column("Rule ID", style="bold cyan")
            hyg_table.add_column("Hygiene Issue", style="bold white")
            hyg_table.add_column("Severity", justify="center")
            hyg_table.add_column("Affected Identity", style="dim")
            hyg_table.add_column("Recommended Remediation", style="green")

            for h in self.hygiene:
                sev_badge = f"[bold red]{h['severity']}[/bold red]" if h["severity"] == "HIGH" else f"[yellow]{h['severity']}[/yellow]"
                ident_short = h["identity"].split("/")[-1]
                hyg_table.add_row(
                    h["rule_id"],
                    h["name"],
                    sev_badge,
                    ident_short,
                    h["remediation"][:50] + ("..." if len(h["remediation"]) > 50 else "")
                )
            console.print(hyg_table)
            console.print()

    def generate_markdown_report(self, output_dir: str = "reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "attack_paths.md")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        md = f"""# CloudPath: IAM Attack-Path & Privilege Escalation Audit Report

**Generated:** {now}  
**IAM Security Posture Score:** {self.summary['posture_score']}/100  
**Analyzed Identities:** {self.summary['total_users']} Users, {self.summary['total_roles']} Roles, {self.summary['total_groups']} Groups  
**Total Attack Paths Discovered:** {self.summary['total_escalation_paths']} (Critical: {self.summary['critical_escalations']})  

---

## 1. Executive Summary
CloudPath analyzed the AWS IAM account authorization details using directed graph pathfinding. The audit identified **{len(self.escalations)} privilege escalation vectors** allowing non-administrative identities to acquire full administrative permissions, along with **{len(self.hygiene)} hygiene findings**.

---

## 2. Ranked Privilege Escalation Paths

"""
        for i, esc in enumerate(self.escalations, 1):
            md += f"""### Path #{i}: {esc['name']} (`{esc['rule_id']}`)
- **Severity:** `{esc['severity']}`
- **Source Identity:** `{esc['source_identity']}`
- **Target Identity:** `{esc['target_identity']}`
- **MITRE ATT&CK Cloud Mapping:** `{esc['mitre_attack_id']}`
- **Hop Count:** `{esc['hop_count']}`
- **Description:** {esc['description']}
- **Attack Chain:**
```
{" -> ".join(esc['attack_chain'])}
```
- **Remediation Action:**
> {esc['remediation']}

"""

        md += """---

## 3. Identity Hygiene Findings

| Rule ID | Finding | Severity | Identity | Remediation |
|---|---|---|---|---|
"""
        for h in self.hygiene:
            md += f"| `{h['rule_id']}` | {h['name']} | `{h['severity']}` | `{h['identity'].split('/')[-1]}` | {h['remediation']} |\n"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md)

        return report_path
