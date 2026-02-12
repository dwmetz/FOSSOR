#!/usr/bin/env python3
"""FOSSOR - Federated Open-Source Sample Search & Object Retriever"""

import os
import re
import sys
import csv
import time
import requests
from datetime import datetime, timezone
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(text: str) -> str:  return _c("32", text)
def red(text: str) -> str:    return _c("31", text)
def yellow(text: str) -> str: return _c("33", text)
def cyan(text: str) -> str:   return _c("36", text)
def bold(text: str) -> str:   return _c("1", text)
def dim(text: str) -> str:    return _c("2", text)

# ---------------------------------------------------------------------------
# Hash type detection
# ---------------------------------------------------------------------------

HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def detect_hash_type(h: str) -> Optional[str]:
    """Return hash type string if valid hex of known length, else None."""
    if _HEX_RE.match(h) and len(h) in HASH_LENGTHS:
        return HASH_LENGTHS[len(h)]
    return None

# ---------------------------------------------------------------------------
# API key loader
# ---------------------------------------------------------------------------

def load_api_key(key_file: str) -> Optional[str]:
    """Load API key from a file in the script's directory. Returns None if missing."""
    key_path = os.path.join(SCRIPT_DIR, key_file)
    try:
        with open(key_path, "r") as f:
            key = f.read().strip()
            return key if key else None
    except FileNotFoundError:
        return None

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

_last_request_time: dict[str, float] = {}

def rate_limit_wait(source_key: str, delay_seconds: float):
    """Sleep if needed to respect rate limit for a source."""
    if delay_seconds <= 0:
        return
    last = _last_request_time.get(source_key, 0)
    elapsed = time.time() - last
    if elapsed < delay_seconds:
        wait = delay_seconds - elapsed
        print(dim(f"    [rate limit: waiting {wait:.0f}s]"), flush=True)
        time.sleep(wait)
    _last_request_time[source_key] = time.time()

# ---------------------------------------------------------------------------
# Source: MalwareBazaar
# ---------------------------------------------------------------------------

MB_API = "https://mb-api.abuse.ch/api/v1/"

def download_malwarebazaar(sha256: str, api_key: str, dest_dir: str) -> Optional[str]:
    """Download a sample from MalwareBazaar. Returns path to saved zip or None."""
    response = requests.post(MB_API, data={
        "query": "get_file",
        "sha256_hash": sha256,
    }, headers={"Auth-Key": api_key})
    if response.status_code == 200 and response.headers.get("Content-Type", "").startswith("application/"):
        os.makedirs(dest_dir, exist_ok=True)
        filename = f"{sha256}.zip"
        filepath = os.path.join(dest_dir, filename)
        with open(filepath, "wb") as f:
            f.write(response.content)
        return filepath
    return None

def query_malwarebazaar(hash_val: str, api_key: str) -> Optional[dict]:
    response = requests.post(MB_API, data={
        "query": "get_info",
        "hash": hash_val,
    }, headers={"Auth-Key": api_key})
    response.raise_for_status()
    result = response.json()
    if result.get("error"):
        raise RuntimeError(f"API error: {result['error']}")
    if result.get("query_status") == "hash_not_found":
        return None
    if result.get("query_status") == "ok" and result.get("data"):
        hit = result["data"][0]
        return {
            "hash": hash_val,
            "source": "MalwareBazaar",
            "status": "FOUND",
            "signature": hit.get("signature", ""),
            "file_type": hit.get("file_type", ""),
            "file_name": hit.get("file_name", ""),
            "first_seen": hit.get("first_seen", ""),
            "tags": ", ".join(hit.get("tags", [])) if hit.get("tags") else "",
            "detection_ratio": "",
            "reporter": hit.get("reporter", ""),
        }
    return None

# ---------------------------------------------------------------------------
# Source: VirusTotal
# ---------------------------------------------------------------------------

VT_API = "https://www.virustotal.com/api/v3/files/"

def query_virustotal(hash_val: str, api_key: str) -> Optional[dict]:
    response = requests.get(VT_API + hash_val, headers={"x-apikey": api_key})
    if response.status_code == 404:
        return None
    response.raise_for_status()
    data = response.json().get("data", {})
    attrs = data.get("attributes", {})

    # Detection ratio
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    detection_ratio = f"{malicious + suspicious}/{total}" if total else ""

    # Threat label
    threat_class = attrs.get("popular_threat_classification", {})
    label = threat_class.get("suggested_threat_label", "")

    # First submission date
    first_sub = attrs.get("first_submission_date")
    first_seen = ""
    if first_sub:
        first_seen = datetime.fromtimestamp(first_sub, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "hash": hash_val,
        "source": "VirusTotal",
        "status": "FOUND",
        "signature": label or attrs.get("meaningful_name", ""),
        "file_type": attrs.get("type_description", ""),
        "file_name": attrs.get("meaningful_name", ""),
        "first_seen": first_seen,
        "tags": ", ".join(attrs.get("tags", [])) if attrs.get("tags") else "",
        "detection_ratio": detection_ratio,
        "reporter": "",
    }

# ---------------------------------------------------------------------------
# Source: AlienVault OTX
# ---------------------------------------------------------------------------

OTX_API = "https://otx.alienvault.com/api/v1/indicators/file/"

def query_otx(hash_val: str, api_key: str) -> Optional[dict]:
    response = requests.get(OTX_API + hash_val + "/general",
                            headers={"X-OTX-API-KEY": api_key})
    if response.status_code == 404:
        return None
    response.raise_for_status()
    result = response.json()

    pulse_info = result.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    if pulse_count == 0:
        return None

    # Collect pulse names and tags
    pulses = pulse_info.get("pulses", [])
    pulse_names = [p.get("name", "") for p in pulses[:3]]
    all_tags = []
    for p in pulses:
        all_tags.extend(p.get("tags", []))
    unique_tags = ", ".join(dict.fromkeys(all_tags)) if all_tags else ""

    file_type = result.get("type_title", "")

    return {
        "hash": hash_val,
        "source": "OTX",
        "status": "FOUND",
        "signature": pulse_names[0] if pulse_names else "",
        "file_type": file_type,
        "file_name": "",
        "first_seen": "",
        "tags": unique_tags,
        "detection_ratio": f"{pulse_count} pulses",
        "reporter": "",
    }

# ---------------------------------------------------------------------------
# Source registry — add new sources here
# ---------------------------------------------------------------------------

SOURCES = {
    "mb": {
        "name": "MalwareBazaar",
        "key_file": "mb-api.txt",
        "rate_limit": 0,
        "query_fn": query_malwarebazaar,
        "download_fn": download_malwarebazaar,
    },
    "vt": {
        "name": "VirusTotal",
        "key_file": "vt-api.txt",
        "rate_limit": 15,
        "query_fn": query_virustotal,
    },
    "otx": {
        "name": "OTX",
        "key_file": "otx-api.txt",
        "rate_limit": 0,
        "query_fn": query_otx,
    },
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

BANNER = r"""
 ███████╗ ██████╗ ███████╗███████╗ ██████╗ ██████╗ 
 ██╔════╝██╔═══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗
 █████╗  ██║   ██║███████╗███████╗██║   ██║██████╔╝
 ██╔══╝  ██║   ██║╚════██║╚════██║██║   ██║██╔══██╗
 ██║     ╚██████╔╝███████║███████║╚██████╔╝██║  ██║
 ╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                  
 Federated Open-Source Sample Search & Object Retriever
"""

def main():
    print(bold(BANNER))
    if len(sys.argv) < 2:
        source_flags = " ".join(f"[--no-{k}]" for k in SOURCES)
        print(f"Usage: {sys.argv[0]} <hash_or_file> [--csv output.csv] [--download] {source_flags}")
        print("  hash_or_file: a single hash (MD5/SHA1/SHA256) or a text file with one hash per line")
        print("  --download:   download available samples to ./samples/ (password: infected)")
        sys.exit(1)

    # Parse args
    csv_output = None
    if "--csv" in sys.argv:
        csv_output = sys.argv[sys.argv.index("--csv") + 1]

    do_download = "--download" in sys.argv

    disabled = set()
    for arg in sys.argv:
        if arg.startswith("--no-"):
            disabled.add(arg[5:])

    # Single hash mode vs file mode
    first_arg = sys.argv[1]
    if detect_hash_type(first_arg):
        hashes = [first_arg]
    else:
        with open(first_arg, "r", encoding="utf-8-sig") as f:
            hashes = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # Sanitize: strip any stray non-hex characters (BOM fragments, quotes, commas)
    hashes = [re.sub(r'[^0-9a-fA-F]', '', h) for h in hashes]
    hashes = [h for h in hashes if h]

    # Detect and display hash types
    hash_types_seen = set()
    valid_hashes = []
    for h in hashes:
        ht = detect_hash_type(h)
        if ht:
            hash_types_seen.add(ht)
            valid_hashes.append(h)
        else:
            print(yellow(f"[!] Skipping invalid hash: {h[:20]}..."))
    hashes = valid_hashes

    if not hashes:
        print(red("[!] No valid hashes found."))
        sys.exit(1)

    hash_type_str = ", ".join(sorted(hash_types_seen))

    # Initialize sources
    active_sources = {}
    for key, src in SOURCES.items():
        if key in disabled:
            print(dim(f"[*] {src['name']}: disabled (--no-{key})"))
            continue
        api_key = load_api_key(src["key_file"])
        if not api_key:
            print(dim(f"[*] {src['name']}: skipped (no {src['key_file']} found)"))
            continue
        active_sources[key] = {**src, "api_key": api_key}
        print(f"[*] {src['name']}: " + green("key loaded"))

    if not active_sources:
        print(red("[!] No sources available. Provide API key files or remove --no-X flags."))
        sys.exit(1)

    source_names = ", ".join(s["name"] for s in active_sources.values())
    print(f"\n[*] Querying {bold(str(len(hashes)))} hashes ({hash_type_str}) across: {bold(source_names)}\n")

    # Query loop
    results = []
    # Track hits per source and per hash for the matrix
    source_hits: dict[str, int] = {k: 0 for k in active_sources}
    hashes_with_hits: set[str] = set()
    matrix: dict[str, dict[str, str]] = {}  # hash -> {source_key -> "HIT"/"---"/"ERR"}

    try:
        for i, hash_val in enumerate(hashes, 1):
            ht = detect_hash_type(hash_val)
            print(bold(f"[{i}/{len(hashes)}]") + f" {hash_val[:20]}... " + dim(f"({ht})"))
            matrix[hash_val] = {}
            for key, src in active_sources.items():
                label = f"  {src['name']+':' :<18}"
                try:
                    rate_limit_wait(key, src["rate_limit"])
                    hit = src["query_fn"](hash_val, src["api_key"])
                    if hit:
                        source_hits[key] += 1
                        hashes_with_hits.add(hash_val)
                        results.append(hit)
                        matrix[hash_val][key] = "HIT"
                        extra = f" | {hit['detection_ratio']}" if hit["detection_ratio"] else ""
                        print(f"{label}" + green(f"HIT") + f" - {hit['signature'] or 'N/A'} | {hit['file_type'] or 'N/A'}{extra}")
                    else:
                        results.append({
                            "hash": hash_val, "source": src["name"], "status": "NOT FOUND",
                            "signature": "", "file_type": "", "file_name": "",
                            "first_seen": "", "tags": "", "detection_ratio": "", "reporter": "",
                        })
                        matrix[hash_val][key] = "---"
                        print(f"{label}" + red("NOT FOUND"))
                except Exception as e:
                    results.append({
                        "hash": hash_val, "source": src["name"], "status": f"ERROR: {e}",
                        "signature": "", "file_type": "", "file_name": "",
                        "first_seen": "", "tags": "", "detection_ratio": "", "reporter": "",
                    })
                    matrix[hash_val][key] = "ERR"
                    print(f"{label}" + yellow(f"ERROR - {e}"))
    except KeyboardInterrupt:
        print(yellow(f"\n[!] Interrupted. Partial results below."))

    # Summary
    print(f"\n{bold('='*60)}")
    print(bold(f"Summary: {len(hashes)} hashes queried across {len(active_sources)} sources\n"))
    for key, src in active_sources.items():
        count = source_hits[key]
        color = green if count > 0 else dim
        print(f"  {src['name']+':' :<18}{color(f'{count}/{len(hashes)} found')}")
    total_hit = len(hashes_with_hits)
    total_color = green if total_hit > 0 else red
    print(f"\n  Unique hashes with at least one hit: {total_color(f'{total_hit}/{len(hashes)}')}")

    # Summary matrix
    if len(hashes) > 1 and len(active_sources) > 1:
        print(f"\n{bold('Results Matrix:')}")
        # Header
        src_labels = {k: s["name"][:6] for k, s in active_sources.items()}
        header = f"  {'Hash':<18}"
        for k in active_sources:
            header += f" {src_labels[k]:>6}"
        print(bold(header))
        print(f"  {'-'*18}" + "".join(f" {'-'*6}" for _ in active_sources))
        # Rows
        for hash_val in hashes:
            row = f"  {hash_val[:18]}"
            for key in active_sources:
                cell = matrix.get(hash_val, {}).get(key, "???")
                if cell == "HIT":
                    row += f" {green('  HIT'):>6}"
                elif cell == "ERR":
                    row += f" {yellow('  ERR'):>6}"
                else:
                    row += f" {dim('    -'):>6}"
            print(row)

    print(bold('='*60))

    # Download phase
    if do_download:
        downloadable = []
        for r in results:
            if r["status"] != "FOUND":
                continue
            # Find the source key for this result
            for key, src in active_sources.items():
                if src["name"] == r["source"] and "download_fn" in src:
                    downloadable.append((r["hash"], key, src))
                    break

        # Deduplicate by hash (same hash may hit on multiple sources, only download once per source that supports it)
        seen = set()
        unique_downloads = []
        for hash_val, key, src in downloadable:
            if (hash_val, key) not in seen:
                seen.add((hash_val, key))
                unique_downloads.append((hash_val, key, src))

        if unique_downloads:
            samples_dir = os.path.join(SCRIPT_DIR, "samples")
            print(f"\n{bold('[+] Downloading')} {len(unique_downloads)} sample(s) to {samples_dir}/")
            print(dim(f"    Password for all zips: infected\n"))
            for hash_val, key, src in unique_downloads:
                print(f"  {hash_val[:20]}... ", end="", flush=True)
                try:
                    path = src["download_fn"](hash_val, src["api_key"], samples_dir)
                    if path:
                        print(green(f"saved ({os.path.basename(path)})"))
                    else:
                        print(yellow("not available for download"))
                except Exception as e:
                    print(yellow(f"failed ({e})"))
        else:
            print(dim("\n[*] --download: no sources support sample downloads for the hits found"))

    # CSV export
    if csv_output and results:
        fields = ["hash", "hash_type", "source", "status", "signature", "file_type",
                  "file_name", "first_seen", "tags", "detection_ratio", "reporter"]
        with open(csv_output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                r["hash_type"] = detect_hash_type(r["hash"]) or ""
                writer.writerow(r)
        print(green(f"\n[+] Results exported to {csv_output}"))

if __name__ == "__main__":
    main()
