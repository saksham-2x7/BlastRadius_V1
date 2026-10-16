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
