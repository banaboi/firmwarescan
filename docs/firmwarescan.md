# FirmwareScan
## Firmware Dependency Vulnerability Scanner
### Product Requirements Document

| | |
|---|---|
| **Version** | 0.1 — Draft |
| **Author** | Luke |
| **Date** | March 2026 |
| **Status** | In Review |
| **Classification** | Personal / Portfolio Project |

---

## 1. Overview

### 1.1 Problem Statement

Modern embedded firmware depends on a growing number of third-party C and C++ libraries — FreeRTOS, lwIP, Mbed TLS, U-Boot, Zephyr subsystems, and many more. Unlike software ecosystems with centralised package managers, embedded projects typically vendor these dependencies directly into source trees, stripping package metadata in the process.

Existing open-source scanners such as Grype and Trivy excel at container and package-ecosystem scanning (apt, pip, npm, cargo) but provide poor coverage for embedded firmware contexts where:

- Dependencies are vendored C/C++ libraries with no lockfile or package manager metadata
- Version strings are buried in source files, CMakeLists, or compiled binaries
- Binary-only third-party components (static libraries, BSPs) have no package identity
- Custom forks of upstream projects do not map cleanly to NVD CPE identifiers
- Common embedded components (FreeRTOS, lwIP, Mbed TLS) have sparse or inconsistent NVD coverage

The consequence is that embedded engineering teams have no reliable, automated mechanism for identifying known vulnerabilities in their dependency chains — a significant gap given increasing regulatory pressure (IEC 62443, FDA cybersecurity guidance, UN R155) and the growing attack surface of connected embedded devices.

### 1.2 Proposed Solution

FirmwareScan is a command-line tool and optional CI integration that performs firmware-specific dependency vulnerability scanning. It targets the gap between generic SCA (Software Composition Analysis) tools and the realities of embedded C/C++ projects, providing:

- Heuristic version extraction from source files, build scripts, and binary strings
- A curated embedded component database mapping common libraries to NVD CPE identifiers
- NVD API v2 integration for CVE lookup with CVSS v3 scoring
- CMake and Makefile build system integration
- CI/CD pipeline output (JSON, SARIF) compatible with GitHub Actions and similar
- A prioritised human-readable report with remediation guidance

### 1.3 Goals

- Provide actionable vulnerability reports for embedded C/C++ firmware projects with no package manager metadata
- Achieve meaningful coverage of the most common embedded open-source components
- Integrate into existing CMake-based build pipelines with minimal friction
- Produce output consumable by both engineers and security reviewers
- Demonstrate practical application of IEC 62443 Series 4 secure development lifecycle requirements

### 1.4 Non-Goals

- Not a replacement for Grype/Trivy in container or Linux package contexts
- Not a binary analysis or reverse engineering tool — source-available projects only in v1
- Not a runtime security monitor or SAST tool
- Not a managed SaaS product — CLI and self-hosted only in v1

---

## 2. Target Users

### 2.1 Primary

- Embedded software engineers at companies building connected devices (IoT, medical, industrial, automotive)
- Security engineers performing product security assessments on firmware
- DevSecOps engineers integrating security gates into embedded CI/CD pipelines

### 2.2 Secondary

- Compliance engineers preparing IEC 62443 or FDA cybersecurity documentation
- Engineering managers and security leads reviewing vulnerability posture

---

## 3. Functional Requirements

### 3.1 Dependency Discovery

#### 3.1.1 Source-Based Extraction

The tool shall extract dependency names and version strings from the following source artefacts without requiring a package manager:

| Source Artefact | Details |
|---|---|
| `CMakeLists.txt` | FetchContent, ExternalProject, find_package declarations |
| `Makefile` | Variable assignments and download targets |
| `version.h` / `version.c` / `*_version.*` | Common embedded version header patterns |
| `README` and `CHANGELOG` files | Fallback heuristic extraction |
| `.gitmodules` | Remote URL and path extraction |

#### 3.1.2 Binary String Extraction

For components where source metadata is unavailable, the tool shall:

- Run `strings(1)` against compiled binaries and static libraries (`.a`, `.so`, `.elf`)
- Apply regex heuristics to identify version strings matching common embedded library patterns
- Flag these findings as low-confidence and require manual confirmation before inclusion in reports

#### 3.1.3 Embedded Component Database

The tool shall maintain a curated local database mapping common embedded library names and version patterns to their canonical NVD CPE identifiers. Initial coverage shall include at minimum:

- FreeRTOS / FreeRTOS-Kernel
- Mbed TLS (mbedtls)
- lwIP
- U-Boot
- Zephyr RTOS
- OpenSSL (embedded builds)
- wolfSSL / wolfCrypt
- littlefs
- FATFS
- libcoap

### 3.2 Vulnerability Lookup

- The tool shall query the NVD CVE API v2 using extracted CPE identifiers
- Results shall include CVE ID, CVSS v3 base score, severity rating, description, and affected version range
- The tool shall cache NVD API responses locally (SQLite) with a configurable TTL to avoid rate limiting
- The tool shall handle NVD API rate limits gracefully with exponential backoff and clear user messaging
- Offline mode shall be supported using a previously cached database

### 3.3 Reporting

#### 3.3.1 Human-Readable Report

The default output shall be a terminal report providing:

- **Summary:** total dependencies scanned, CVEs found, breakdown by severity (Critical / High / Medium / Low / Info)
- **Per-finding detail:** component name, detected version, CVE ID, CVSS score, brief description, NVD link
- **Confidence indicator** per finding (High / Medium / Low based on extraction method)
- **Suggested remediation:** patched version if available, or advisory link

#### 3.3.2 Machine-Readable Output

- JSON output mode for pipeline integration (`--format json`)
- SARIF output mode for GitHub Advanced Security integration (`--format sarif`)
- Exit code non-zero when findings at or above a configurable severity threshold are found (`--fail-on HIGH`)

### 3.4 Build System Integration

- A CMake module (`FindFirmwareScan.cmake`) shall be provided for optional integration as a build target
- A GitHub Actions workflow template shall be provided as a reference CI integration
- A pre-commit hook template shall be provided for local developer use

### 3.5 Configuration

- YAML configuration file (`.firmwarescan.yml`) for project-specific settings
- **Allowlist/suppressions:** ability to suppress known false positives or accepted risks with a mandatory reason string and expiry date
- **Custom component mappings:** user-defined CPE overrides for internal forks or unusual naming
- Severity threshold configuration for CI failure behaviour

---

## 4. Non-Functional Requirements

- Scan completion for a medium-sized firmware project (50–100 dependencies) in under 60 seconds including NVD API calls
- Zero external runtime dependencies beyond Python 3.9+ standard library and `requests`
- Cross-platform: Linux, macOS, Windows (WSL2)
- NVD API key support for higher rate limits (optional, documented)
- All NVD data cached locally — no telemetry, no outbound calls beyond NVD API

---

## 5. Feature Priorities

*(To be populated)*

---

## 6. Technical Design

### 6.1 Architecture

FirmwareScan is a single Python CLI application with the following internal modules:

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing (argparse), config loading, orchestration |
| `extractors/` | Pluggable extractor classes (CMakeExtractor, MakefileExtractor, BinaryExtractor, HeaderExtractor) |
| `db/component_db.json` | Curated embedded component CPE mapping database |
| `nvd.py` | NVD API v2 client with rate limiting, retry, and SQLite cache |
| `report.py` | Report rendering (terminal, JSON, SARIF) |
| `suppress.py` | Suppression/allowlist management |

### 6.2 Extractor Interface

Each extractor implements a common interface returning a list of `Dependency` objects (`name`, `version`, `confidence`, `source_file`, `line_number`). This makes adding new build system support straightforward without modifying core logic.

### 6.3 NVD API Cache

Responses are stored in a local SQLite database (`~/.firmwarescan/cache.db`) keyed by CPE string and timestamp. Default TTL is 24 hours. This keeps the tool usable in environments with restricted outbound access after an initial warm-up.

### 6.4 IEC 62443 Alignment

This tool directly supports compliance activities under **IEC 62443-4-1** (Secure Product Development Lifecycle), specifically:

- **SR 4-1:** Security requirements for the component — automated identification of known vulnerabilities in dependencies
- **SR 4-2:** Vulnerability testing — providing evidence of dependency vulnerability assessment for audit

The suppression mechanism with mandatory reason strings and expiry dates supports the documented risk acceptance process required under the standard.

---

## 7. MVP Scope

The MVP (v0.1) delivers a working scanner against a real firmware codebase with the following scope:

| Feature | Priority |
|---|---|
| CMake extractor | P0 |
| NVD API v2 client with SQLite cache | P0 |
| Terminal report | P0 |
| Embedded component database — top 10 libraries | P1 |
| JSON output mode | P1 |
| Basic suppression file support | P1 |

Post-MVP (v0.2+) adds binary extraction, GitHub Actions template, Makefile support, and SARIF output.

---

## 8. Success Metrics

- Successfully identifies at least one real CVE in a public embedded firmware project (e.g. an older FreeRTOS or lwIP version in an open source repo) — demonstrating genuine signal over noise
- Zero false positives on a known-clean dependency list in regression testing
- Scan completes in under 60 seconds for a 50-dependency project including NVD API round trips
- Published as a public GitHub repository with README, example output, and documented IEC 62443 alignment
- Integrated into Embedify as a demonstrable security tooling example

---

## 9. Open Questions

1. **CPE matching accuracy** — NVD CPE identifiers for embedded libraries are inconsistently maintained. May need to supplement NVD with GitHub Advisory Database (GHSA) for better embedded coverage. Investigate during P1 implementation.

2. **Binary extraction false positive rate** — heuristic version string matching from binaries may be noisy. Consider requiring explicit opt-in flag (`--include-binary`) rather than enabling by default.

3. **Handling forks** — projects that fork upstream libraries (common in embedded) won't have matching NVD entries. A warning and manual review prompt may be the best approach rather than attempting automated matching.

4. **SBOM output** — CycloneDX or SPDX SBOM generation would be a natural v0.3 feature given increasing regulatory interest. Out of MVP scope but worth designing the data model to accommodate.

---

## 10. Appendix — IEC 62443 Reference

The following IEC 62443 series and requirements are most relevant to this project:

*(To be populated)*
