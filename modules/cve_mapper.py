"""
cve_mapper.py — Extract CVE IDs from Nuclei findings, query NVD API.

Reads nuclei_results.json, finds any CVE references, then uses the
NVD 2.0 REST API to retrieve CVSS scores and severity.  A simple
JSON cache (cve_cache.json) prevents duplicate requests.  The API
rate limit (~5 requests per 30 seconds without key) is respected
via automatic delays.
"""

import os
import json
import re
import time
import requests
from modules.utils import Logger

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_cache(cache_path):
    if os.path.isfile(cache_path):
        with open(cache_path, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache_path, cache):
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)

def get_cve_info(cve_id, cache, api_key=""):
    """Fetch CVSS data for a single CVE, using cache if available."""
    if cve_id in cache:
        Logger.info(f"  {cve_id} (cached)")
        return cache[cve_id]

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    Logger.info(f"  Querying NVD for {cve_id}...")
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_item = vulns[0].get("cve", {})
                metrics = cve_item.get("metrics", {})
                # Try CVSS v3.1 first, fallback to v2.0
                cvss_data = None
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get("cvssData", {})
                        break
                if cvss_data:
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    vector = cvss_data.get("vectorString", "")
                    result = {
                        "score": score,
                        "severity": severity,
                        "vector": vector,
                    }
                else:
                    result = {"score": None, "severity": "UNKNOWN", "vector": ""}
                cache[cve_id] = result
                return result
        elif resp.status_code == 404:
            Logger.warning(f"  {cve_id} not found in NVD.")
            cache[cve_id] = {"score": None, "severity": "N/A", "vector": ""}
            return cache[cve_id]
        else:
            Logger.error(f"  NVD API error for {cve_id}: {resp.status_code}")
    except requests.exceptions.RequestException as e:
        Logger.error(f"  Request failed for {cve_id}: {e}")
    return None

def run(cfg):
    Logger.stage("CVE Mapping")

    output_dir = cfg["output_dir"]
    nuclei_file = os.path.join(output_dir, "nuclei_results.json")
    if not os.path.isfile(nuclei_file):
        Logger.warning(f"{nuclei_file} missing — skipping CVE mapping.")
        return None

    # Read findings (line-delimited JSON)
    findings = []
    with open(nuclei_file, "r") as f:
        for line in f:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Extract CVE IDs (patterns like CVE-YYYY-NNNN)
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    cve_ids = set()
    for finding in findings:
        # Look in common fields: info.name, info.description, classification, etc.
        text_fields = []
        info = finding.get("info", {})
        text_fields.append(info.get("name", ""))
        text_fields.append(info.get("description", ""))
        # also check tags or other nested strings
        for field in text_fields:
            cve_ids.update(cve_pattern.findall(field))
        # Also check in the raw "curl-command" or "matcher-name" if present
        for key in finding:
            val = finding[key]
            if isinstance(val, str):
                cve_ids.update(cve_pattern.findall(val))

    if not cve_ids:
        Logger.warning("No CVE IDs found in Nuclei results.")
        out = []
    else:
        Logger.info(f"Found {len(cve_ids)} unique CVE ID(s).")
        cache_path = os.path.join(output_dir, "cve_cache.json")
        cache = load_cache(cache_path)
        api_key = cfg.get("nvd", {}).get("api_key", "")

        results = {}
        delay = 6  # seconds between requests without API key (5 per 30s)
        for idx, cve in enumerate(sorted(cve_ids)):
            info = get_cve_info(cve, cache, api_key)
            if info:
                results[cve] = info
            else:
                results[cve] = {"score": None, "severity": "ERROR", "vector": ""}
            # Rate limiting delay
            if not api_key and idx < len(cve_ids)-1:
                time.sleep(delay)
        # Save updated cache
        save_cache(cache_path, cache)
        # Build output list of dicts
        out = []
        for cve, data in results.items():
            out.append({"cve": cve, **data})
    out_path = os.path.join(output_dir, "cve_mapping.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    Logger.success(f"CVE mapping results -> {out_path}")
    return out_path