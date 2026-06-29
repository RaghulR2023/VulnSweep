# Vulnsweep

Automated Reconnaissance & Vulnerability Assessment Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Vulnsweep is a modular Python CLI tool that chains together industry‑standard open‑source security tools to perform comprehensive reconnaissance and initial vulnerability assessment. It is designed for **authorised penetration testing, bug bounty programmes, and CTF challenges**.

The pipeline gracefully handles missing tools, network timeouts, and empty results – it never crashes mid‑scan. All findings are consolidated into a single, easy‑to‑read Markdown report.

---

## Features

- **Subdomain Enumeration** – Combines `subfinder` and `assetfinder`, deduplicates, and saves the results.
- **Live Host Detection** – Probes discovered subdomains with `httpx` to find live web servers and their status codes/titles.
- **Port Scanning** – Runs `nmap -sV -T4 --top-ports 100` on every live host (no root required) and structures the output as JSON.
- **Directory Brute‑forcing** – Uses `ffuf` with a common wordlist (or a built‑in fallback) to discover hidden files and directories.
- **Vulnerability Scanning** – Executes `nuclei` templates against all live hosts and extracts CVE IDs.
- **CVE Mapping** – Queries the NVD 2.0 API for CVSS scores and severity; caches results to avoid rate limiting.
- **Unified Markdown Report** – Compiles every stage into `output/report.md` with tables for subdomains, live hosts, open ports, discovered directories, vulnerabilities, and CVE details.
- **Coloured Console Output** – Clear stage‑by‑stage logging so you always know what’s happening.
- **Resilient Execution** – Missing tools, timeouts, or empty results are logged as warnings; the pipeline continues to the next stage.

---

## Prerequisites

### External tools (must be installed and in your `PATH`)

| Tool | Purpose |
|------|---------|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomains from various sources |
| [httpx](https://github.com/projectdiscovery/httpx) | Probe for live HTTP/HTTPS servers |
| [Nmap](https://nmap.org) | Port scanning and service detection |
| [ffuf](https://github.com/ffuf/ffuf) | Web content brute‑forcing |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template‑based vulnerability scanning |

> **Windows users**: download the `.exe` files from each project’s releases page and place them in a folder that is in your system `PATH` (e.g. `C:\Tools`).

### Python dependencies

Install automatically from `requirements.txt`:
