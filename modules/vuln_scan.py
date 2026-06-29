"""
vuln_scan.py — Run Nuclei templates against live hosts.

Reads live_hosts.txt, runs nuclei with -json output.  The results are
stored as a newline-delimited JSON file, each line a single finding.
Nuclei will handle template auto-download by default, but a custom
template path can be specified in config.yaml.
"""

import os
import json
from modules.utils import Logger, tool_exists, run_command

def run(cfg):
    Logger.stage("Vulnerability Scanning (Nuclei)")

    output_dir = cfg["output_dir"]
    live_file = os.path.join(output_dir, "live_hosts.txt")
    if not os.path.isfile(live_file):
        Logger.warning(f"{live_file} missing — skipping vulnerability scan.")
        return None

    tool = cfg["tools"]["nuclei"]
    if not tool_exists(tool):
        Logger.warning("nuclei not found — skipping vulnerability scan.")
        return None

    # nuclei can read a file of hosts with the -l flag
    cmd = [tool, "-l", live_file, "-json", "-silent"]
    # Optionally include custom templates
    templates = cfg["nuclei"].get("templates", "")
    if templates:
        cmd.extend(["-t", templates])

    Logger.info("Running nuclei (this may take a while)...")
    result = run_command(cmd, timeout=cfg["timeouts"]["nuclei"])
    if result is None:
        Logger.warning("Nuclei scan failed.")
        return None

    # Collect valid JSON lines
    findings = []
    for line in result.stdout.splitlines():
        try:
            finding = json.loads(line)
            findings.append(finding)
        except json.JSONDecodeError:
            continue

    Logger.success(f"Nuclei scan complete – {len(findings)} findings.")

    out_path = os.path.join(output_dir, "nuclei_results.json")
    # Save as a JSON array (or line-delimited, easier for cve_mapper)
    with open(out_path, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")
    Logger.success(f"Nuclei results -> {out_path}")
    return out_path