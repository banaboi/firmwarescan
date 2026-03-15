# FirmwareScan

A CLI tool for firmware dependency vulnerability scanning. Designed for embedded C/C++ projects where traditional SCA tools (Grype, Trivy, Dependabot) are ineffective because libraries are vendored directly into source trees with no package manager metadata.

FirmwareScan heuristically extracts library versions from source files, build scripts, and binaries, maps them to [NVD CPE](https://nvd.nist.gov/products/cpe) identifiers, queries the NVD CVE API, and produces a PDF vulnerability report. It also aligns with [IEC 62443-4-1](https://www.isa.org/products/ansi-isa-62443-4-1-2018-security-for-industrial-aut) secure development lifecycle requirements (SR 4-1, SR 4-2).

---

## The Problem

Embedded firmware projects typically vendor C/C++ libraries like FreeRTOS, lwIP, and Mbed TLS directly into the repository. There is no `package.json`, `Cargo.toml`, or `requirements.txt` — just source files. Standard SCA tools have no way to discover these dependencies, leaving firmware projects with no automated path to CVE detection.

---

## Features

- **Heuristic extraction** — parses CMakeLists.txt, header files, Makefiles, and compiled binaries to find library versions
- **Curated component database** — maps 10 common embedded libraries to NVD CPE identifiers with verified CPE strings
- **NVD CVE API v2** — queries the National Vulnerability Database with a 24-hour SQLite cache to avoid rate limiting
- **PDF reports** — generates structured vulnerability reports with severity summaries, findings tables, and dependency inventories
- **CVE suppression** — `.firmwarescan.yml` allowlist with mandatory `reason` fields and expiry dates, per IEC 62443-4-1
- **CI integration** — `--fail-on` flag exits non-zero when findings at or above a severity threshold are found

---

## Supported Components

| Library | CPE Vendor | NVD Verified |
|---|---|---|
| FreeRTOS | `amazon` | Yes |
| Mbed TLS | `arm` | Yes |
| lwIP | `lwip_project` | Yes |
| U-Boot | `denx` | Yes |
| Zephyr RTOS | `zephyrproject` | Yes |
| OpenSSL | `openssl` | Yes |
| wolfSSL | `wolfssl` | Yes |
| libcoap | `libcoap` | Yes |
| littlefs | — | No NVD CPE |
| FatFs | — | No NVD CPE |

---

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/your-org/firmwarescan
cd firmwarescan
pip install -e .
```

### Dependencies

| Package | Purpose |
|---|---|
| `requests>=2.28` | NVD API HTTP client |
| `pyyaml>=6.0` | Suppression config parsing |
| `fpdf2>=2.7` | PDF report generation |

---

## Usage

```
firmwarescan [PATH] [--fail-on SEVERITY] [--config CONFIG] [--output OUTPUT]
```

| Argument | Description |
|---|---|
| `PATH` | Path to the firmware project root (defaults to current directory) |
| `--fail-on` | Exit non-zero if any finding at or above this severity is found. One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--config` | Path to suppression config file (default: `.firmwarescan.yml` in `PATH`) |
| `--output` | Write output to a file |

### Example

```bash
# Scan a project, fail CI on HIGH or CRITICAL findings
firmwarescan ./my-firmware --fail-on HIGH

# Scan with a custom suppression config
firmwarescan ./my-firmware --config ./security/suppressions.yml
```

---

## CVE Suppression

Create a `.firmwarescan.yml` file in your project root to suppress false positives or accepted risks:

```yaml
suppress:
  - cve: CVE-2021-44228
    reason: "Not exploitable — our build does not use the affected log4j JNDI lookup path."
    expires: 2026-12-31

  - cve: CVE-2023-12345
    reason: "Vendor patch applied via backport in our fork at commit abc1234."
```

**Rules:**
- `reason` is mandatory — entries without a reason are silently skipped and a warning is printed to stderr
- `expires` is optional — past expiry dates keep the finding active and print a warning to stderr, prompting review
- Both rules enforce the IEC 62443-4-1 requirement for documented, time-bounded risk acceptance decisions

---

## How It Works

```
Firmware project root
        │
        ▼
  [Extractors]  ── CMakeLists.txt, headers, Makefiles, binaries
        │             Produce: Dependency(name, version, source_file)
        ▼
  [DB Lookup]   ── db/component_db.json
        │             Resolves: CPE string (e.g. cpe:2.3:o:amazon:freertos:10.4.3:...)
        ▼
  [NVD Client]  ── NVD CVE API v2, SQLite cache (~/.firmwarescan/cache.db, 24h TTL)
        │             Produces: Finding(cve_id, cvss_score, severity, description)
        ▼
  [Suppression] ── .firmwarescan.yml
        │             Filters: accepted/expired CVEs
        ▼
  [PDF Report]  ── fpdf2
                    Output: vulnerability_report.pdf
```

---

## Development

Install the package in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=term-missing

# Run a specific test file
pytest tests/test_nvd.py

# Run a specific test by name
pytest tests/test_nvd.py::test_cache_miss
```

### Writing Tests

Tests live in the `tests/` directory and are picked up automatically by pytest. Each test file corresponds to a module (e.g. `tests/test_nvd.py` tests `nvd.py`).

**NVD tests** use a `tmp_path` fixture to redirect the SQLite cache away from `~/.firmwarescan/` so tests never touch the real cache:

```python
@pytest.fixture(autouse=True)
def isolate_cache(tmp_path, monkeypatch):
    monkeypatch.setattr("nvd.CACHE_DIR", tmp_path)
    monkeypatch.setattr("nvd.CACHE_DB", tmp_path / "cache.db")
```

**NVD network calls** are monkeypatched so tests never hit the real API:

```python
def test_lookup_calls_fetch_on_cache_miss(tmp_path, monkeypatch):
    monkeypatch.setattr("nvd._NVDClient.fetch", lambda self, cpe: [...])
    findings = nvd.lookup(dep)
    assert len(findings) == 1
```

**Suppression tests** write a temporary `.firmwarescan.yml` via `tmp_path` and pass the path directly to `suppress.apply()`.

**DB loader tests** call `db.loader.lookup()` directly — no fixtures needed as the component DB is read-only.

### Adding a Component

Use the interactive script to add a new library to the component database. It validates the CPE string against NVD before writing:

```bash
python scripts/add_component.py
```

### Validating the Component Database

```bash
# Validate all components
python scripts/validate_db.py

# Validate a single component
python scripts/validate_db.py --component freertos
```

---

## Status

The core infrastructure is complete and tested: NVD client with caching, CVE suppression, PDF reporting, component database, and DB loader. The **extractors are currently stubs** — the version extraction pipeline from source files and binaries is the active development milestone.

| Module | Status |
|---|---|
| NVD client + cache | Complete |
| PDF report | Complete |
| CVE suppression | Complete |
| Component database (10 libs) | Complete |
| CMake extractor | In progress |
| Header extractor | Planned |
| Makefile extractor | Planned |
| Binary extractor | Planned |
| `--fail-on` CI integration | Planned |

---

## License

MIT
