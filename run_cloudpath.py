#!/usr/bin/env python3
import argparse
import os
import sys

from cloudpath.analyzer import CloudPathAnalyzer
from cloudpath.reporter import CloudPathReporter
from cloudpath.soar_bridge import CloudPathSOARBridge

def main():
    parser = argparse.ArgumentParser(description="CloudPath: IAM Attack-Path & Privilege Escalation Auditor")
    parser.add_argument(
        "--input",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "fixtures", "cloudgoat_iam_privesc.json"),
        help="Path to aws iam get-account-authorization-details JSON output"
    )
    parser.add_argument("--report", action="store_true", help="Generate Markdown audit report in reports/ directory")
    parser.add_argument("--soar", action="store_true", help="Forward critical escalation paths to Aegis-SOAR webhook")
    parser.add_argument("--serve", action="store_true", help="Launch CloudPath API server")
    parser.add_argument("--port", type=int, default=8083, help="Port for API server (default: 8083)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: input file {args.input} does not exist.")
        sys.exit(1)

    analyzer = CloudPathAnalyzer.from_file(args.input)
    results = analyzer.analyze()

    reporter = CloudPathReporter(results)
    reporter.print_cli_summary()

    if args.report:
        report_path = reporter.generate_markdown_report()
        print(f"[*] Audit report written to: {report_path}")

    if args.soar:
        bridge = CloudPathSOARBridge()
        dispatched = bridge.dispatch_critical_escalations(results["escalation_paths"])
        print(f"[*] Forwarded {len(dispatched)} critical escalation findings to Aegis-SOAR.")
        for d in dispatched:
            print(f"    - {d['rule_id']}: {d['status']}")

    if args.serve:
        import uvicorn
        from fastapi import FastAPI
        api_app = FastAPI(title="CloudPath IAM Attack-Path Auditor API", version="1.0.0")
        
        @api_app.get("/api/analysis")
        def get_analysis():
            return results

        @api_app.get("/api/paths")
        def get_paths():
            return results["escalation_paths"]

        @api_app.get("/api/hygiene")
        def get_hygiene():
            return results["hygiene_findings"]

        print(f"[*] Starting CloudPath API on http://0.0.0.0:{args.port}...")
        uvicorn.run(api_app, host="0.0.0.0", port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
