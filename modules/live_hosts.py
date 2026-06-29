"""
live_hosts.py — Probe discovered subdomains to find live web hosts.

Reads output/subdomains.txt, runs httpx with --silent, --status-code,
and --title flags.  The output is a simple text file containing each
live URL, its HTTP status code, and the page title (if any).

If subdomains.txt is missing or empty, we warn and exit early.
"""

import os
from modules.utils import Logger, tool_exists, run_command

def run(cfg):
    """Entry point called from main.py."""
    Logger.stage("Live Host Detection")

    output_dir = cfg["output_dir"]
    sub_file = os.path.join(output_dir, "subdomains.txt")
    if not os.path.isfile(sub_file):
        Logger.warning(f"{sub_file} not found — skipping live host check.")
        return None

    with open(sub_file, "r") as f:
        subdomains = [line.strip() for line in f if line.strip()]
    if not subdomains:
        Logger.warning("No subdomains to test.")
        return None

    tool = cfg["tools"]["httpx"]
    if not tool_exists(tool):
        Logger.warning("httpx not found in PATH — skipping live host detection.")
        return None

    # httpx reads hosts from stdin.  -silent -status-code -title gives one
    # line per host with the format: <url> [<status>] [<title>]
    cmd = [tool, "-silent", "-status-code", "-title"]
    Logger.info(f"Probing {len(subdomains)} subdomains with httpx...")

    # Feed subdomains via stdin_data
    stdin_data = "\n".join(subdomains)
    result = run_command(cmd, timeout=cfg["timeouts"]["httpx"], stdin_data=stdin_data)
    if result is None:
        return None

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    Logger.success(f"httpx found {len(lines)} live hosts.")

    live_file = os.path.join(output_dir, "live_hosts.txt")
    with open(live_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    Logger.success(f"Live hosts saved -> {live_file}")
    return live_file