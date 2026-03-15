from models import Dependency, Finding
from suppress import apply


def make_finding(cve_id: str) -> Finding:
    dep = Dependency(name="lwip", version="2.1.2", confidence="high", source_file="CMakeLists.txt")
    return Finding(
        dependency=dep,
        cve_id=cve_id,
        cvss_score=7.5,
        severity="HIGH",
        description="Test CVE",
        nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


def write_config(tmp_path, content: str):
    config = tmp_path / ".firmwarescan.yml"
    config.write_text(content)
    return str(config)


def test_active_suppression_removes_finding(tmp_path):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
    reason: "Not exploitable in our configuration"
""")
    assert apply(findings, config) == []


def test_unsuppressed_finding_is_kept(tmp_path):
    findings = [make_finding("CVE-2021-99999")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
    reason: "Not exploitable"
""")
    result = apply(findings, config)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2021-99999"


def test_expired_suppression_does_not_suppress(tmp_path):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
    reason: "Accepted risk"
    expires: 2020-01-01
""")
    result = apply(findings, config)
    assert len(result) == 1


def test_expired_suppression_prints_warning(tmp_path, capsys):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
    reason: "Accepted risk"
    expires: 2020-01-01
""")
    apply(findings, config)
    assert "expired" in capsys.readouterr().err


def test_future_expiry_still_suppresses(tmp_path):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
    reason: "Accepted risk"
    expires: 2099-01-01
""")
    assert apply(findings, config) == []


def test_suppression_without_reason_is_skipped(tmp_path, capsys):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-12345
""")
    result = apply(findings, config)
    assert len(result) == 1
    assert "no reason" in capsys.readouterr().err


def test_missing_config_file_returns_all_findings(tmp_path):
    findings = [make_finding("CVE-2021-12345")]
    result = apply(findings, str(tmp_path / "nonexistent.yml"))
    assert result == findings


def test_empty_suppress_block_returns_all_findings(tmp_path):
    findings = [make_finding("CVE-2021-12345")]
    config = write_config(tmp_path, "suppress:\n")
    assert apply(findings, config) == findings


def test_multiple_suppressions(tmp_path):
    findings = [make_finding("CVE-2021-AAA"), make_finding("CVE-2021-BBB"), make_finding("CVE-2021-CCC")]
    config = write_config(tmp_path, """
suppress:
  - cve_id: CVE-2021-AAA
    reason: "Not exploitable"
  - cve_id: CVE-2021-CCC
    reason: "Mitigated by firewall rules"
""")
    result = apply(findings, config)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2021-BBB"
