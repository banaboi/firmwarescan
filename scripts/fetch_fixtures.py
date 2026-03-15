#!/usr/bin/env python3
"""
Fetches real upstream source files into tests/fixtures/ for each extractor type.
Fixtures are pinned to specific library releases so tests are deterministic and
broken patterns are caught during development rather than in production.

Usage:
    python scripts/fetch_fixtures.py
    python scripts/fetch_fixtures.py --extractor header
    python scripts/fetch_fixtures.py --component freertos
    python scripts/fetch_fixtures.py --force
    python scripts/fetch_fixtures.py --verify

Set GITHUB_TOKEN env var for higher API rate limits (5000/hr vs 60/hr anonymous).

Binary extractor fixtures cannot be automated — compiled binaries must be added
manually. See tests/fixtures/binary/README.md for instructions.

After fetching, --verify tests each header fixture against the version_patterns
in component_db.json and reports which patterns match or fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import NamedTuple

import requests

FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures"
COMPONENT_DB = Path(__file__).parent.parent / "db" / "component_db.json"
GITHUB_RAW = "https://raw.githubusercontent.com"

RATE_LIMIT_PAUSE = 1.0  # seconds between requests when unauthenticated


class Fixture(NamedTuple):
    component: str
    repo: str               # owner/repo on GitHub
    tag: str                # pinned release tag
    path: str               # file path within the repo
    filename: str           # saved filename under tests/fixtures/{extractor}/{component}/
    expected_version: str | None = None  # asserted by --verify; None skips version check


# ---------------------------------------------------------------------------
# Manifest — one entry per file to fetch, grouped by extractor type.
#
# Naming convention for filenames: {tag}_{original_filename}
# This makes it immediately obvious which release a fixture came from.
#
# Header fixtures: the actual version header files that get vendored into
# firmware projects. These directly exercise version_patterns in the DB.
#
# CMake/Makefile fixtures: files from the libraries themselves (project()
# declarations contain version) plus firmware projects that import them.
#
# README fixtures: library README files at a pinned release — used by the
# fallback heuristic ReadmeExtractor.
#
# Gitmodules fixtures: .gitmodules from real embedded projects that vendor
# these libraries as git submodules.
#
# Binary fixtures: cannot be automated — see tests/fixtures/binary/README.md
# ---------------------------------------------------------------------------
MANIFEST: dict[str, list[Fixture]] = {
    "header": [
        Fixture(
            "freertos", "FreeRTOS/FreeRTOS-Kernel", "V10.6.2",
            "include/task.h", "V10.6.2_task.h",
            expected_version="10.6.2",
        ),
        Fixture(
            # Version defines moved from version.h to build_info.h in mbedtls 3.x.
            "mbedtls", "Mbed-TLS/mbedtls", "v3.6.2",
            "include/mbedtls/build_info.h", "v3.6.2_build_info.h",
            expected_version="3.6.2",
        ),
        Fixture(
            "lwip", "lwip-tcpip/lwip", "STABLE-2_2_0_RELEASE",
            "src/include/lwip/init.h", "STABLE-2_2_0_init.h",
            expected_version="2.2.0",
        ),
        Fixture(
            # Zephyr stores its version in a plain text VERSION file, not a header.
            "zephyr", "zephyrproject-rtos/zephyr", "v3.6.0",
            "VERSION", "v3.6.0_VERSION",
            expected_version="3.6.0",
        ),
        Fixture(
            # OpenSSL 1.1.x — version is both a packed hex and a text string.
            "openssl", "openssl/openssl", "OpenSSL_1_1_1w",
            "include/openssl/opensslv.h", "1.1.1w_opensslv.h",
            expected_version="1.1.1w",
        ),
        Fixture(
            "wolfssl", "wolfSSL/wolfssl", "v5.7.2-stable",
            "wolfssl/version.h", "v5.7.2_version.h",
            expected_version="5.7.2",
        ),
        Fixture(
            # littlefs encodes version as a packed hex constant (0x00020009 = 2.9).
            # The extractor must decode: major = value >> 16, minor = value & 0xffff.
            "littlefs", "littlefs-project/littlefs", "v2.9.3",
            "lfs.h", "v2.9.3_lfs.h",
            expected_version="0x00020009",
        ),
        # libcoap: coap.h is a generated template (.h.in) — no static version header
        # exists in the source tree. Version is in CMakeLists.txt. See cmake fixtures.
        # uboot: version is declared in Makefile — see makefile fixtures.
        # fatfs: no official GitHub repository — add manually from elm-chan.org.
        # See tests/fixtures/header/fatfs/README.md for instructions.
    ],
    "cmake": [
        # Library CMakeLists.txt files that declare their own version via project().
        Fixture(
            "freertos", "FreeRTOS/FreeRTOS-Kernel", "V10.6.2",
            "CMakeLists.txt", "V10.6.2_CMakeLists.txt",
        ),
        Fixture(
            "mbedtls", "Mbed-TLS/mbedtls", "v3.6.2",
            "CMakeLists.txt", "v3.6.2_CMakeLists.txt",
        ),
        Fixture(
            "wolfssl", "wolfSSL/wolfssl", "v5.7.2-stable",
            "CMakeLists.txt", "v5.7.2_CMakeLists.txt",
        ),
        Fixture(
            "libcoap", "obgm/libcoap", "v4.3.4",
            "CMakeLists.txt", "v4.3.4_CMakeLists.txt",
        ),
        # Firmware project CMakeLists.txt that pulls in these libraries
        # via FetchContent — exercises the extractor against realistic input.
        Fixture(
            "esp-idf_lwip", "espressif/esp-idf", "v5.2.1",
            "components/lwip/CMakeLists.txt",
            "esp-idf_v5.2.1_lwip_CMakeLists.txt",
        ),
    ],
    "makefile": [
        Fixture(
            # U-Boot Makefile: VERSION = 2024 / PATCHLEVEL = 01
            "uboot", "u-boot/u-boot", "v2024.01",
            "Makefile", "v2024.01_Makefile",
        ),
        Fixture(
            "esp-idf_lwip", "espressif/esp-idf", "v5.2.1",
            "components/lwip/Makefile",
            "esp-idf_v5.2.1_lwip_Makefile",
        ),
    ],
    "readme": [
        Fixture(
            "freertos", "FreeRTOS/FreeRTOS-Kernel", "V10.6.2",
            "README.md", "V10.6.2_README.md",
        ),
        Fixture(
            "mbedtls", "Mbed-TLS/mbedtls", "v3.6.2",
            "README.md", "v3.6.2_README.md",
        ),
        Fixture(
            "wolfssl", "wolfSSL/wolfssl", "v5.7.2-stable",
            "README.md", "v5.7.2_README.md",
        ),
        Fixture(
            "littlefs", "littlefs-project/littlefs", "v2.9.3",
            "README.md", "v2.9.3_README.md",
        ),
        Fixture(
            "libcoap", "libcoap-org/libcoap", "v4.3.4",
            "README.md", "v4.3.4_README.md",
        ),
        Fixture(
            "zephyr", "zephyrproject-rtos/zephyr", "v3.6.0",
            "README.rst", "v3.6.0_README.rst",
        ),
    ],
    "gitmodules": [
        # Real embedded firmware projects that vendor these libraries
        # as git submodules — exercises GitmodulesExtractor against real input.
        Fixture(
            "nrf-sdk", "nrfconnect/sdk-nrf", "v2.6.0",
            ".gitmodules", "nrf-sdk_v2.6.0_.gitmodules",
        ),
        Fixture(
            "esp-idf", "espressif/esp-idf", "v5.2.1",
            ".gitmodules", "esp-idf_v5.2.1_.gitmodules",
        ),
        Fixture(
            "zephyr", "zephyrproject-rtos/zephyr", "v3.6.0",
            ".gitmodules", "zephyr_v3.6.0_.gitmodules",
        ),
    ],
}


def _session() -> requests.Session:
    s = requests.Session()
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    s.headers["Accept"] = "application/vnd.github.v3.raw"
    return s


def _fetch_raw(session: requests.Session, fixture: Fixture, pause: float) -> str | None:
    url = f"{GITHUB_RAW}/{fixture.repo}/{fixture.tag}/{fixture.path}"
    time.sleep(pause)
    try:
        r = session.get(url, timeout=15)
    except requests.RequestException as e:
        print(f"    ERROR  network error: {e}")
        return None

    if r.status_code == 200:
        return r.text
    if r.status_code == 404:
        print(f"    MISS   404 — path may have changed: {url}")
        return None
    if r.status_code == 429:
        retry_after = int(r.headers.get("Retry-After", 60))
        print(f"    WAIT   rate limited — sleeping {retry_after}s")
        time.sleep(retry_after)
        return _fetch_raw(session, fixture, 0)

    print(f"    ERROR  HTTP {r.status_code}: {url}")
    return None


def _save(extractor: str, fixture: Fixture, content: str) -> Path:
    dest = FIXTURES_DIR / extractor / fixture.component / fixture.filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def fetch(
    extractor_filter: str | None,
    component_filter: str | None,
    force: bool,
) -> dict[str, int]:
    session = _session()
    authenticated = "Authorization" in session.headers
    pause = 0.2 if authenticated else RATE_LIMIT_PAUSE

    counts = {"fetched": 0, "skipped": 0, "failed": 0}

    for extractor, fixtures in MANIFEST.items():
        if extractor_filter and extractor != extractor_filter:
            continue

        print(f"\n[{extractor}]")

        for fixture in fixtures:
            if component_filter and fixture.component != component_filter:
                continue

            dest = FIXTURES_DIR / extractor / fixture.component / fixture.filename
            label = f"{fixture.component}/{fixture.filename}"

            if dest.exists() and not force:
                print(f"  SKIP   {label}")
                counts["skipped"] += 1
                continue

            print(f"  FETCH  {label}  ({fixture.repo}@{fixture.tag})", end="", flush=True)
            content = _fetch_raw(session, fixture, pause)

            if content is None:
                counts["failed"] += 1
                continue

            path = _save(extractor, fixture, content)
            size = len(content.encode())
            print(f"\r  OK     {label}  ({size:,} bytes)")
            counts["fetched"] += 1

    return counts


def verify_header_patterns() -> None:
    """
    Cross-references every fetched header fixture against the version_patterns
    in component_db.json and reports matches and failures.

    Runs re.search with re.DOTALL so multi-line patterns work correctly —
    this also validates that the patterns as written will behave when the
    extractor uses DOTALL mode.

    When a Fixture in the MANIFEST has an expected_version, the extracted
    version must equal it exactly. Multi-group patterns (MAJOR/MINOR/PATCH)
    have their groups joined with '.' before comparison.
    """
    db = json.loads(COMPONENT_DB.read_text())
    alias_map: dict[str, dict] = {}
    for c in db["components"]:
        alias_map[c["name"].lower()] = c
        for alias in c.get("aliases", []):
            alias_map[alias.lower()] = c

    # Build lookup from (component, filename) -> Fixture for expected_version checks.
    fixture_meta: dict[tuple[str, str], Fixture] = {
        (f.component, f.filename): f
        for f in MANIFEST["header"]
    }

    header_dir = FIXTURES_DIR / "header"
    if not header_dir.exists():
        print("No header fixtures found — run without --verify first.")
        return

    print("\n=== Pattern verification (header fixtures) ===\n")

    any_failure = False
    for component_dir in sorted(header_dir.iterdir()):
        db_entry = alias_map.get(component_dir.name.lower())
        if db_entry is None:
            print(f"  SKIP {component_dir.name}: no DB entry")
            continue

        patterns = db_entry.get("version_patterns", [])
        if not patterns:
            print(f"  SKIP {component_dir.name}: no version_patterns defined")
            continue

        for fixture_file in sorted(component_dir.iterdir()):
            content = fixture_file.read_text(encoding="utf-8", errors="replace")
            meta = fixture_meta.get((component_dir.name, fixture_file.name))
            expected = meta.expected_version if meta else None

            matched_version: str | None = None
            matched_pattern: str | None = None

            for pattern in patterns:
                m = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                if m:
                    matched_version = ".".join(g for g in m.groups() if g is not None)
                    matched_pattern = pattern
                    break

            label = f"{component_dir.name}/{fixture_file.name}"

            if matched_version is None:
                any_failure = True
                print(f"  FAIL {label}")
                print(f"         no pattern matched ({len(patterns)} tried)")
                for p in patterns:
                    print(f"         - {p!r}")
                continue

            if expected and matched_version != expected:
                any_failure = True
                print(f"  FAIL {label}")
                print(f"         pattern : {matched_pattern!r}")
                print(f"         expected: {expected!r}")
                print(f"         got     : {matched_version!r}")
                continue

            suffix = f"  (expected={expected!r})" if expected else "  (no expected_version set)"
            print(f"  OK   {label}")
            print(f"         pattern : {matched_pattern!r}")
            print(f"         version : {matched_version!r}{suffix}")

    if any_failure:
        print("\nSome patterns failed. Update version_patterns in db/component_db.json.")
        sys.exit(1)
    else:
        print("\nAll patterns matched.")


def _write_binary_readme() -> None:
    dest = FIXTURES_DIR / "binary" / "README.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    dest.write_text(
        "# Binary Extractor Fixtures\n\n"
        "Binary fixtures cannot be fetched automatically.\n\n"
        "To add a fixture:\n\n"
        "1. Obtain a compiled `.elf`, `.a`, or `.so` built from a known library version.\n"
        "2. Place it here as `{component}/{tag}_{filename}` "
        "(e.g. `freertos/V10.6.2_libfreertos.a`).\n"
        "3. Add the expected version string to the corresponding test assertion.\n\n"
        "The binary extractor runs `strings(1)` against the file and applies "
        "version_patterns heuristics. Confidence is always `low`.\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extractor", choices=list(MANIFEST), help="Fetch only this extractor's fixtures")
    parser.add_argument("--component", help="Fetch only this component (e.g. freertos, mbedtls)")
    parser.add_argument("--force", action="store_true", help="Re-fetch even if fixture already exists")
    parser.add_argument("--verify", action="store_true", help="Verify header fixtures against DB version_patterns (implies fetch)")
    args = parser.parse_args()

    authenticated = bool(os.environ.get("GITHUB_TOKEN"))
    if not authenticated:
        print("Tip: set GITHUB_TOKEN to raise the rate limit from 60 to 5000 requests/hr.\n")

    _write_binary_readme()

    counts = fetch(args.extractor, args.component, args.force)

    print(f"\nDone — fetched: {counts['fetched']}, skipped: {counts['skipped']}, failed: {counts['failed']}")

    if counts["failed"]:
        print(f"\n{counts['failed']} fixture(s) failed to fetch.")
        print("Paths may have changed in upstream repos — update the MANIFEST in this script.")

    if args.verify:
        verify_header_patterns()


if __name__ == "__main__":
    main()
