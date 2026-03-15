# Binary Extractor Fixtures

Binary fixtures cannot be fetched automatically.

To add a fixture:

1. Obtain a compiled `.elf`, `.a`, or `.so` built from a known library version.
2. Place it here as `{component}/{tag}_{filename}` (e.g. `freertos/V10.6.2_libfreertos.a`).
3. Add the expected version string to the corresponding test assertion.

The binary extractor runs `strings(1)` against the file and applies version_patterns heuristics. Confidence is always `low`.
