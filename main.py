#!/usr/bin/env python3
"""
main.py — ReconForge CLI entry point.

Parses command-line arguments, loads configuration from config.yaml,
and runs the reconnaissance pipeline stage by stage.  If a stage
fails (tool missing, timeout, empty results) it logs a warning and
continues to the next stage rather than crashing.
"""

import argparse
import sys
import os
import yaml
from pathlib import Path

from modules.utils import Logger

def load_config(path="config.yaml"):
    """Load configuration YAML with sensible defaults if file is missing."""
    defaults = {
        "tools": {
            "subfinder": "subfinder",
            "assetfinder": "assetfinder",
            "httpx": "httpx",
            "nmap": "nmap",
            "ffuf": "ffuf",
            "nuclei": "nuclei",
        },
        "timeouts": {
            "subfinder": 300,
            "assetfinder": 300,
            "httpx": 300,
            "nmap": 600,
            "ffuf": 300,
            "nuclei": 900,
        },
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "nmap": {"top_ports": 100},
        "nuclei": {"templates": ""},
        "nvd": {"api_key": ""},
        "output_dir": "output",
    }
    try:
        with open(path, "r") as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        Logger.warning(f"{path} not found, using built-in defaults.")
        cfg = {}
    # Deep-merge defaults with loaded config
    for section, values in defaults.items():
        if section not in cfg:
            cfg[section] = values
        elif isinstance(values, dict):
            for k, v in values.items():
                if k not in cfg[section]:
                    cfg[section][k] = v
        else:
            cfg[section] = cfg.get(section, values)
    return cfg

def main():
    parser = argparse.ArgumentParser(
        description="Vulnsweep — Automated Reconnaissance & Vulnerability Assessment"
    )
    parser.add_argument("--target", "-t", required=True, help="Target domain (e.g. example.com)")
    # Module selection flags
    parser.add_argument("--all", action="store_true", help="Run all stages (default if no individual flags)")
    parser.add_argument("--subdomains-only", action="store_true")
    parser.add_argument("--live-only", action="store_true")
    parser.add_argument("--ports-only", action="store_true")
    parser.add_argument("--dirs-only", action="store_true")
    parser.add_argument("--vulns-only", action="store_true")
    parser.add_argument("--cve-only", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--skip-dirs", action="store_true", help="Skip directory enumeration")
    args = parser.parse_args()

    # Determine which stages to run
    run_all = args.all or not any([
        args.subdomains_only, args.live_only, args.ports_only,
        args.dirs_only, args.vulns_only, args.cve_only, args.report_only
    ])
    cfg = load_config()

    # Helper to conditionally run a stage
    def run_stage(flag, skip_flag, module_name, func):
        if skip_flag:
            Logger.warning(f"Skipping {module_name}")
            return None
        if flag or run_all:
            return func()
        return None

    import modules.subdomain_enum as subdomain_enum
    import modules.live_hosts as live_hosts
    import modules.port_scan as port_scan
    import modules.dir_enum as dir_enum
    import modules.vuln_scan as vuln_scan
    import modules.cve_mapper as cve_mapper
    import modules.report_gen as report_gen

    # Stage 1: Subdomain enumeration
    subdomain_file = run_stage(
        args.subdomains_only, False, "Subdomain Enumeration",
        lambda: subdomain_enum.run(args.target, cfg)
    )
    if subdomain_file is None and (args.subdomains_only or run_all):
        Logger.warning("Subdomain file not generated; some later stages depend on it.")

    # Stage 2: Live host detection (needs subdomains.txt)
    live_hosts_file = run_stage(
        args.live_only, False, "Live Host Detection",
        lambda: live_hosts.run(cfg)   # reads subdomains.txt from output dir
    )

    # Stage 3: Port scanning (needs live_hosts.txt)
    port_scan_file = run_stage(
        args.ports_only, False, "Port Scanning",
        lambda: port_scan.run(cfg)    # reads live_hosts.txt
    )

    # Stage 4: Directory enumeration (needs live_hosts.txt, can be skipped)
    if not args.skip_dirs:
        run_stage(
            args.dirs_only, False, "Directory Enumeration",
            lambda: dir_enum.run(cfg)  # reads live_hosts.txt
        )

    # Stage 5: Vulnerability scanning (needs live_hosts.txt)
    vuln_results = run_stage(
        args.vulns_only, False, "Vulnerability Scanning",
        lambda: vuln_scan.run(cfg)      # reads live_hosts.txt
    )

    # Stage 6: CVE mapping (needs nuclei_results.json)
    run_stage(
        args.cve_only, False, "CVE Mapping",
        lambda: cve_mapper.run(cfg)     # reads nuclei_results.json
    )

    # Stage 7: Report generation (needs all output files)
    if args.report_only or run_all:
        report_gen.run(cfg)

    Logger.success("Pipeline complete.")

if __name__ == "__main__":
    main()