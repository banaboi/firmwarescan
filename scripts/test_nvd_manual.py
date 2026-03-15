"""
Manual NVD API test script.

Usage:
    python scripts/test_nvd_manual.py
    python scripts/test_nvd_manual.py --cpe "cpe:2.3:a:lwip:lwip:2.1.2:*:*:*:*:*:*:*"
    python scripts/test_nvd_manual.py --no-cache
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import Dependency
from nvd import _cache_get, _NVDClient, lookup

DEFAULT_CPE = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"

KNOWN_VULNERABLE = [
    # RTOS / networking
    ("freertos", "10.4.3", "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"),
    ("lwip",     "2.1.2",  "cpe:2.3:a:lwip:lwip:2.1.2:*:*:*:*:*:*:*"),
    # TLS / crypto
    ("openssl",  "1.0.1",  "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"),
    ("mbedtls",  "2.16.0", "cpe:2.3:a:arm:mbed_tls:2.16.0:*:*:*:*:*:*:*"),
    ("wolfssl",  "4.0.0",  "cpe:2.3:a:wolfssl:wolfssl:4.0.0:*:*:*:*:*:*:*"),
    # Compression / parsing
    ("zlib",     "1.2.11", "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"),
    ("expat",    "2.4.1",  "cpe:2.3:a:libexpat:libexpat:2.4.1:*:*:*:*:*:*:*"),
    ("libpng",   "1.6.35", "cpe:2.3:a:libpng:libpng:1.6.35:*:*:*:*:*:*:*"),
    # Utilities
    ("curl",     "7.64.0", "cpe:2.3:a:haxx:curl:7.64.0:*:*:*:*:*:*:*"),
    ("busybox",  "1.31.0", "cpe:2.3:a:busybox:busybox:1.31.0:*:*:*:*:*:*:*"),
    ("sqlite",   "3.31.0", "cpe:2.3:a:sqlite:sqlite:3.31.0:*:*:*:*:*:*:*"),
    # Bootloader
    ("u-boot",   "2020.01","cpe:2.3:a:denx:u-boot:2020.01:*:*:*:*:*:*:*"),
]


def print_findings(findings, label: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    if not findings:
        print("  No findings.")
        return
    for f in findings:
        score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
        print(f"  [{f.severity:<8}] {f.cve_id}  CVSS {score}")
        print(f"           {f.description[:80]}...")
        print(f"           {f.nvd_url}")
    print(f"\n  Total: {len(findings)} CVE(s)")


def test_single(cpe: str, no_cache: bool):
    dep = Dependency(name="manual", version="0.0", confidence="high", source_file="manual", cpe=cpe)

    if no_cache:
        print(f"\nSkipping cache — fetching directly from NVD...")
        raw = _NVDClient().fetch(cpe)
        print(f"Raw response ({len(raw)} items):")
        for item in raw:
            print(f"  {item}")
        return

    cached = _cache_get(cpe)
    source = "CACHE" if cached is not None else "NVD API"
    findings = lookup(dep)
    print_findings(findings, f"{cpe}  [{source}]")


def test_known_vulnerable():
    print("\nTesting known-vulnerable components...")
    for name, version, cpe in KNOWN_VULNERABLE:
        dep = Dependency(name=name, version=version, confidence="high", source_file="manual", cpe=cpe)
        cached = _cache_get(cpe)
        source = "CACHE" if cached is not None else "NVD API"
        findings = lookup(dep)
        print_findings(findings, f"{name} {version}  [{source}]")


def main():
    parser = argparse.ArgumentParser(description="Manually test the NVD API client")
    parser.add_argument("--cpe", default=None, help="CPE string to query")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and fetch raw response")
    parser.add_argument("--all", action="store_true", help="Run against all known-vulnerable test cases")
    args = parser.parse_args()

    if args.all:
        test_known_vulnerable()
    else:
        test_single(args.cpe or DEFAULT_CPE, args.no_cache)


if __name__ == "__main__":
    main()
