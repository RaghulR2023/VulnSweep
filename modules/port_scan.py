"""
port_scan.py — Perform service/version detection on live hosts using Nmap.

For every live host found in output/live_hosts.txt we extract the
hostname (or IP) and run an Nmap scan of the top N TCP ports.
Results are saved as structured JSON in output/port_scan.json.

Uses -sT (TCP connect) to avoid needing root privileges.
"""

import os
import re
import json
from modules.utils import Logger, tool_exists, run_command

def parse_nmap_xml(xml_string):
    """Parse Nmap XML output into a list of host/port/service dicts.

    Example element:
    <host><address addr="1.2.3.4"/><ports><port portid="80">
    <state state="open"/><service name="http" product="nginx" version="1.18"/>
    </port></ports></host>
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        Logger.error("xml.etree not available – cannot parse Nmap XML.")
        return []
    root = ET.fromstring(xml_string)
    results = []
    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "unknown")
        host_data = {"host": ip, "ports": []}
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem.findall("port"):
            portid = port.get("portid")
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            service_elem = port.find("service")
            if service_elem is None:
                continue
            service_name = service_elem.get("name", "unknown")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            host_data["ports"].append({
                "port": int(portid),
                "service": service_name,
                "product": product,
                "version": version,
            })
        results.append(host_data)
    return results

def run(cfg):
    Logger.stage("Port Scanning")

    output_dir = cfg["output_dir"]
    live_file = os.path.join(output_dir, "live_hosts.txt")
    if not os.path.isfile(live_file):
        Logger.warning(f"{live_file} missing — skipping port scan.")
        return None

    tool = cfg["tools"]["nmap"]
    if not tool_exists(tool):
        Logger.warning("nmap not found — skipping port scan.")
        return None

    # Read live hosts – extract host part from lines like "https://example.com [200] [Title]"
    hosts = set()
    with open(live_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Simple extraction: take first token, remove scheme if present
            parts = line.split()
            if parts:
                url = parts[0]
                # remove http(s)://
                url = url.split("://")[-1].split("/")[0]
                hosts.add(url)

    if not hosts:
        Logger.warning("No hosts to scan.")
        return None

    top_ports = cfg["nmap"].get("top_ports", 100)
    all_results = []

    for host in hosts:
        Logger.info(f"Scanning {host} (top {top_ports} ports)...")
        # Nmap command: -sT connect scan, -sV version detection, -T4 speed,
        # --top-ports, -oX - for XML to stdout
        cmd = [
            tool, "-sT", "-sV", "-T4", "--top-ports", str(top_ports),
            "-oX", "-", host
        ]
        result = run_command(cmd, timeout=cfg["timeouts"]["nmap"])
        if result is None:
            Logger.warning(f"Nmap scan failed for {host}")
            continue
        # Parse XML output
        parsed = parse_nmap_xml(result.stdout)
        all_results.extend(parsed)

    if not all_results:
        Logger.warning("No open ports found on any host.")
    else:
        Logger.success(f"Port scan complete – {len(all_results)} host(s) scanned.")

    out_path = os.path.join(output_dir, "port_scan.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    Logger.success(f"Port scan results -> {out_path}")
    return out_path