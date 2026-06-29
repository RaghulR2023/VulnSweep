"""
subdomain_enum.py — passive subdomain enumeration.

Strategy:
  1. Run `subfinder -d <domain> -silent` (fast passive sources).
  2. Run `assetfinder --subs-only <domain>` (different source set).
  3. Merge both result sets, deduplicate, sort.
  4. Save the unique subdomains to output/subdomains.txt.

Each tool runs independently. If one is missing or fails, we log a
warning and still use whatever the other produced, so the stage never
hard-crashes the pipeline.
"""

import os

from modules.utils import Logger, tool_exists, run_command


def _run_subfinder(domain, cfg):
    """Run subfinder and return a set of discovered subdomains."""
    tool = cfg["tools"]["subfinder"]
    if not tool_exists(tool):
        Logger.warning("subfinder not found in PATH — skipping it.")
        return set()

    # -silent makes subfinder print only hostnames (one per line),
    # which is exactly what we want to parse.
    cmd = [tool, "-d", domain, "-silent"]
    Logger.info(f"Running: {' '.join(cmd)}")
    result = run_command(cmd, timeout=cfg["timeouts"]["subfinder"])
    if result is None:
        return set()

    # Split stdout into clean, non-empty lines.
    found = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    Logger.success(f"subfinder found {len(found)} subdomains.")
    return found


def _run_assetfinder(domain, cfg):
    """Run assetfinder and return a set of discovered subdomains."""
    tool = cfg["tools"]["assetfinder"]
    if not tool_exists(tool):
        Logger.warning("assetfinder not found in PATH — skipping it.")
        return set()

    # --subs-only restricts output to subdomains of the target only,
    # filtering out unrelated domains assetfinder might otherwise return.
    cmd = [tool, "--subs-only", domain]
    Logger.info(f"Running: {' '.join(cmd)}")
    result = run_command(cmd, timeout=cfg["timeouts"]["assetfinder"])
    if result is None:
        return set()

    found = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    Logger.success(f"assetfinder found {len(found)} subdomains.")
    return found


def run(domain, cfg):
    """Entry point called by main.py.

    Returns the path to the saved subdomains file (or None if nothing
    was found / both tools failed).
    """
    Logger.stage(f"Subdomain Enumeration — {domain}")

    # Union of results from both tools deduplicates automatically.
    subs = _run_subfinder(domain, cfg) | _run_assetfinder(domain, cfg)

    # Always include the apex domain itself — it's a valid host to scan.
    subs.add(domain)

    if not subs:
        Logger.warning("No subdomains discovered.")
        return None

    output_dir = cfg["output_dir"]
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "subdomains.txt")

    # Sorted output is deterministic and easier to diff between runs.
    with open(out_path, "w", encoding="utf-8") as f:
        for sub in sorted(subs):
            f.write(sub + "\n")

    Logger.success(f"Saved {len(subs)} unique subdomains -> {out_path}")
    return out_path
