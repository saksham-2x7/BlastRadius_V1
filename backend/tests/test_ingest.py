"""Import validation and Trivy mapping. Pure functions, no database needed."""
import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("LIVE_FEEDS", "0")

import ingest  # noqa: E402

BASE = {
    "hosts": [{"id": "web", "exposed": True}, {"id": "app"}],
    "datastores": [{"id": "db", "crown": True}],
    "edges": [["web", "app"], ["app", "db"]],
}


def spec(**over):
    return ingest.ImportSpec.model_validate({**BASE, **over})


def test_valid_inventory_loads():
    assert len(spec().hosts) == 2


def test_needs_a_crown_jewel():
    with pytest.raises(ValidationError):
        spec(datastores=[{"id": "db", "crown": False}])


def test_edge_to_unknown_node_is_rejected():
    with pytest.raises(ValidationError):
        spec(edges=[["web", "ghost"]])


def test_finding_on_unknown_host_is_rejected():
    with pytest.raises(ValidationError):
        spec(findings=[{"host": "ghost", "cve": "CVE-2021-44228"}])


def test_bad_cve_id_is_rejected():
    with pytest.raises(ValidationError):
        spec(findings=[{"host": "web", "cve": "not-a-cve"}])


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        spec(unexpected=1)


def test_duplicate_ids_and_reserved_internet_are_rejected():
    with pytest.raises(ValidationError):
        spec(hosts=[{"id": "web"}, {"id": "web"}])
    with pytest.raises(ValidationError):
        spec(hosts=[{"id": "internet"}])


def test_trivy_report_maps_to_findings():
    report = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "Title": "Log4Shell",
         "CVSS": {"nvd": {"V3Score": 10.0}, "redhat": {"V3Score": 9.0}}},
        {"VulnerabilityID": "GHSA-xxxx-yyyy", "PkgName": "ignored"},
    ]}]}
    found = ingest._trivy_findings(ingest.TrivyIn(host="app", report=report))
    assert [(f.cve, f.cvss, f.product) for f in found] == [("CVE-2021-44228", 10.0, "log4j-core")]


def test_duplicate_self_and_implied_internet_edges_are_dropped():
    s = spec(edges=[["web", "app"], ["web", "app"], ["app", "app"], ["internet", "web"], ["app", "db"], ["internet", "app"]])
    assert ingest.normalize_edges(s) == [("web", "app"), ("app", "db"), ("internet", "app")]


def test_duplicate_findings_across_manual_and_trivy_are_merged(monkeypatch):
    captured = {}
    monkeypatch.setattr(ingest.importer, "load_workspace", lambda h, d, e, f: captured.update(edges=e, findings=f))
    report = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "CVSS": {"n": {"V3Score": 10}}}]}]}
    counts = ingest.build(spec(findings=[{"host": "app", "cve": "CVE-2021-44228", "cvss": 9.0}],
                               trivy=[{"host": "app", "report": report}], edges=[["web", "app"], ["web", "app"], ["app", "db"]]))
    assert counts["findings"] == 1 and counts["edges"] == 2
    assert captured["findings"][0]["cvss"] == 9.0  # the hand-written entry wins over the scanner's


def test_high_cvss_is_exploitable_until_live_feeds_say_otherwise(monkeypatch):
    captured = {}
    monkeypatch.setattr(ingest.importer, "load_workspace", lambda h, d, e, f: captured.update(findings=f))
    ingest.build(spec(findings=[{"host": "app", "cve": "CVE-2021-44228", "cvss": 7.0}, {"host": "web", "cve": "CVE-2020-8177", "cvss": 6.9}]))
    assert [f["exp"] for f in captured["findings"]] == [True, False]
