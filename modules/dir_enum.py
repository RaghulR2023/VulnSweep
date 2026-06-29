"""
dir_enum.py — Directory and file brute-forcing on live web hosts.

Uses ffuf with a wordlist (either user-supplied or a small built-in
fallback).  Each target is scanned via HTTP/HTTPS, and results are
stored as a JSON file.

If the external wordlist is missing, we create a temporary file with
a small built-in list so the module still works.
"""

import os
import json
import tempfile
from modules.utils import Logger, tool_exists, run_command

# A minimal built-in wordlist (common paths) to use as a fallback.
FALLBACK_WORDLIST = [
    "admin", "login", "dashboard", "wp-admin", "backup",
    "robots.txt", "sitemap.xml", ".git", ".env", "config",
    "api", "test", "dev", "uploads", "images", "css",
    "js", "static", "includes", "logs", "tmp", "server-status",
]

def run(cfg):
    Logger.stage("Directory Enumeration")

    output_dir = cfg["output_dir"]
    live_file = os.path.join(output_dir, "live_hosts.txt")
    if not os.path.isfile(live_file):
        Logger.warning(f"{live_file} missing — skipping directory enumeration.")
        return None

    tool = cfg["tools"]["ffuf"]
    if not tool_exists(tool):
        Logger.warning("ffuf not found in PATH — skipping directory enumeration.")
        return None

    wordlist_path = cfg.get("wordlist", "")
    if not os.path.isfile(wordlist_path):
        Logger.warning(f"Wordlist '{wordlist_path}' not found. Using built-in fallback.")
        # Create a temporary wordlist file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            for word in FALLBACK_WORDLIST:
                tmp.write(word + "\n")
            wordlist_path = tmp.name
        Logger.info(f"Temporary wordlist created: {wordlist_path}")

    # Read live hosts (URLs from live_hosts.txt)
    with open(live_file, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    all_results = {}

    for line in lines:
        # line format: https://example.com [200] [Title]
        url = line.split()[0] if line else ""
        if not url.startswith("http"):
            # assume https:// if scheme missing
            url = f"https://{url}"
        Logger.info(f"Brute-forcing directories on {url}")
        # ffuf command: -u URL/FUZZ -w wordlist -json -silent
        # We redirect stderr to /dev/null to avoid progress bars.
        cmd = [
            tool, "-u", f"{url}/FUZZ", "-w", wordlist_path,
            "-json", "-silent",
        ]
        result = run_command(cmd, timeout=cfg["timeouts"]["ffuf"])
        if result is None:
            Logger.warning(f"ffuf failed for {url}")
            continue

        # Each line is a JSON object with keys: url, status, etc.
        entries = []
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                continue

        if entries:
            Logger.success(f"{url}: {len(entries)} directories/files found")
        all_results[url] = entries

    # Clean up temporary wordlist if we created one
    if wordlist_path != cfg.get("wordlist", ""):
        os.unlink(wordlist_path)

    out_path = os.path.join(output_dir, "dir_enum.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    Logger.success(f"Directory enum results -> {out_path}")
    return out_path