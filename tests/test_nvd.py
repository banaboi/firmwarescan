import time
import pytest # type: ignore

from models import Dependency, Finding
from nvd import _cache_get, _cache_set, _CacheDB, _NVDClient, lookup


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr("nvd.CACHE_DIR", tmp_path)
    monkeypatch.setattr("nvd.CACHE_DB", tmp_path / "cache.db")


def make_dependency(cpe: str = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*") -> Dependency:
    return Dependency(
        name="freertos",
        version="10.4.3",
        confidence="high",
        source_file="CMakeLists.txt",
        cpe=cpe,
    )


SAMPLE_FINDINGS = [
    {
        "cve_id": "CVE-2021-31571",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "description": "Buffer overflow in FreeRTOS.",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-31571",
        "affected_versions": "",
        "patched_version": None,
    }
]


def test_cache_miss_returns_none():
    assert _cache_get("cpe:2.3:a:unknown:unknown:1.0:*:*:*:*:*:*:*") is None


def test_cache_set_then_get_returns_data():
    cpe = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"
    _cache_set(cpe, SAMPLE_FINDINGS)
    result = _cache_get(cpe)
    assert result == SAMPLE_FINDINGS


def test_cache_hit_is_keyed_per_cpe():
    cpe_a = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"
    cpe_b = "cpe:2.3:a:lwip:lwip:2.1.2:*:*:*:*:*:*:*"
    _cache_set(cpe_a, SAMPLE_FINDINGS)
    assert _cache_get(cpe_b) is None


def test_stale_cache_returns_none():
    cpe = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"
    past = int(time.time()) - (60 * 60 * 25)  # 25 hours ago
    with _CacheDB() as db:
        db.execute(
            "INSERT INTO cve_cache (cpe, data, fetched_at) VALUES (?, ?, ?)",
            (cpe, '[]', past),
        )
        db.commit()
    assert _cache_get(cpe) is None


def test_fresh_cache_within_ttl_is_returned():
    cpe = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"
    recent = int(time.time()) - (60 * 60 * 23)  # 23 hours ago
    with _CacheDB() as db:
        db.execute(
            "INSERT INTO cve_cache (cpe, data, fetched_at) VALUES (?, ?, ?)",
            (cpe, '[{"cve_id": "CVE-2021-31571", "cvss_score": 7.5, "severity": "HIGH", "description": "x", "nvd_url": "http://x"}]', recent),
        )
        db.commit()
    result = _cache_get(cpe)
    assert result is not None
    assert result[0]["cve_id"] == "CVE-2021-31571"


def test_cache_overwrite_refreshes_timestamp():
    cpe = "cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*"
    past = int(time.time()) - (60 * 60 * 25)
    with _CacheDB() as db:
        db.execute(
            "INSERT INTO cve_cache (cpe, data, fetched_at) VALUES (?, ?, ?)",
            (cpe, '[]', past),
        )
        db.commit()

    _cache_set(cpe, SAMPLE_FINDINGS)
    result = _cache_get(cpe)
    assert result == SAMPLE_FINDINGS


def test_lookup_returns_cached_findings_without_network():
    dep = make_dependency()
    _cache_set(dep.cpe, SAMPLE_FINDINGS)

    result = lookup(dep)

    assert len(result) == 1
    assert isinstance(result[0], Finding)
    assert result[0].cve_id == "CVE-2021-31571"
    assert result[0].dependency is dep


def test_lookup_no_cpe_returns_empty():
    dep = Dependency(name="fatfs", version="0.14", confidence="medium", source_file="CMakeLists.txt", cpe=None)
    assert lookup(dep) == []


def test_lookup_cache_miss_calls_fetch(monkeypatch):
    dep = make_dependency()
    monkeypatch.setattr(_NVDClient, "fetch", lambda self, cpe: SAMPLE_FINDINGS)
    result = lookup(dep)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2021-31571"
