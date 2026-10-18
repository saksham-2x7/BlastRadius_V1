"""NVD parsing, Grype mapping (pure), plus escalation, approvals and blast zone against a real FalkorDB (skipped without one)."""
import json
import uuid
from unittest import mock

import pytest

import enrich
import ingest
from blastradius_db import db

try:
    db.run("RETURN 1")
    UP = True
except Exception:
    UP = False


# ------------------------------------------------------------------ pure
def test_nvd_score_prefers_v31_then_falls_back(monkeypatch):
    def body(metrics):
        return json.dumps({"vulnerabilities": [{"cve": {"metrics": metrics}}]}).encode()
    monkeypatch.setattr(enrich, "_get", lambda *a, **k: body({"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}], "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}))
    assert enrich._nvd_score("CVE-2021-44228") == 9.8
    monkeypatch.setattr(enrich, "_get", lambda *a, **k: body({"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}))
    assert enrich._nvd_score("CVE-2014-0160") == 7.5
    monkeypatch.setattr(enrich, "_get", lambda *a, **k: body({}))
    assert enrich._nvd_score("CVE-2099-0001") is None


def test_grype_report_maps_to_findings():
    report = {"matches": [
        {"vulnerability": {"id": "CVE-2021-44228", "description": "Log4Shell", "cvss": [{"metrics": {"baseScore": 10.0}}, {"metrics": {"baseScore": 9.0}}]},
         "artifact": {"name": "log4j-core"}},
        {"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc"}, "artifact": {"name": "ignored"}},
    ]}
    found = ingest._grype_findings(ingest.GrypeIn(host="app", report=report))
    assert [(f.cve, f.cvss, f.product) for f in found] == [("CVE-2021-44228", 10.0, "log4j-core")]


def test_grype_host_must_exist():
    with pytest.raises(Exception):
        ingest.ImportSpec.model_validate({"hosts": [{"id": "web"}], "datastores": [{"id": "db", "crown": True}],
                                          "grype": [{"host": "ghost", "report": {}}]})


# ------------------------------------------------------------------ integration
pytestmark_db = pytest.mark.skipif(not UP, reason="needs a reachable FalkorDB")

if UP:
    import engine
    import main
    import threat_tools as t
    from blastradius_db import memory

    @pytest.fixture()
    def sample():
        token = db.use_graph(db.SAMPLE_GRAPH)
        engine.reset()
        yield
        db.reset_graph(token)


@pytestmark_db
def test_refusal_opens_an_approval_request_and_human_approval_closes_it(sample):
    t.apply_safe_fix("F4", "choke point")
    assert [p.finding_id for p in t.list_pending_approvals().pending] == ["F4"]
    main.fix_approve(main.FixRequest(finding_id="F4"))  # what the dashboard's Approve button calls
    assert t.list_pending_approvals().pending == []


@pytestmark_db
def test_escalation_is_deduplicated_and_only_for_approval_tier(sample):
    first = t.escalate_to_human("F4", "needs the platform owner")
    assert first.status == "requested" and first.request_id
    assert t.escalate_to_human("F4", "again").status == "already_pending"
    assert t.escalate_to_human("F3", "leaf host").status == "not_needed"
    assert len(t.list_pending_approvals().pending) == 1


@pytestmark_db
def test_webhook_posts_once_and_never_from_a_non_https_url(sample, monkeypatch):
    sent = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: (sent.append(req.full_url), Resp())[1])
    monkeypatch.setenv("ESCALATION_WEBHOOK_URL", "http://insecure.test/hook")
    assert t.escalate_to_human("F4", "x1").notified is False and sent == []
    memory.cancel_pending()
    monkeypatch.setenv("ESCALATION_WEBHOOK_URL", "https://hooks.test/abc")
    assert t.escalate_to_human("F4", "x2").notified is True and sent == ["https://hooks.test/abc"]
    assert t.escalate_to_human("F4", "x3").notified is False and len(sent) == 1  # already pending: no second message


@pytestmark_db
def test_a_silent_refusal_still_lets_the_first_escalation_notify_the_team(sample, monkeypatch):
    sent = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: (sent.append(req.full_url), Resp())[1])
    monkeypatch.setenv("ESCALATION_WEBHOOK_URL", "https://hooks.test/abc")
    t.apply_safe_fix("F4", "refused first, request opened silently")
    assert sent == []
    out = t.escalate_to_human("F4", "now tell the team")
    assert out.notified is True and out.status == "requested" and sent == ["https://hooks.test/abc"]
    assert t.escalate_to_human("F4", "again").notified is False and len(sent) == 1


@pytestmark_db
def test_restoring_the_sample_cancels_pending_requests(sample):
    t.escalate_to_human("F4", "before restore")
    engine.reset()
    assert t.list_pending_approvals().pending == []


@pytestmark_db
def test_blast_zone_uses_reachability(sample):
    gw = t.get_blast_zone("api-gateway")
    assert gw.reaches_crown_jewel and [r.node for r in gw.reachable] == ["db-customers"] and gw.on_attack_paths == 3
    ftp = t.get_blast_zone("legacy-ftp")
    assert not ftp.reaches_crown_jewel and [r.node for r in ftp.reachable] == ["archive-ftp"]
    assert t.get_blast_zone("cache-redis").reachable == []
    with pytest.raises(t.ToolNotFound):
        t.get_blast_zone("nope")


# ------------------------------------------------------------------ Terraform import and playbook (integration)
@pytestmark_db
def test_terraform_state_becomes_a_scannable_workspace():
    import test_terraform as tf
    spec, warnings = ingest.parse({"terraform": tf.STATE, "findings": [{"host": "front", "cve": "CVE-2021-23017", "cvss": 8.1},
                                                                       {"host": "api", "cve": "CVE-2021-44228", "cvss": 10.0}]})
    token = db.use_graph(db.workspace_graph(f"tf-{uuid.uuid4().hex[:8]}"))
    try:
        ingest.build(spec)
        scan = engine.scan()
        assert warnings == [] and scan["workspace"] == "own"
        assert scan["paths"] == [["internet", "front", "api", "orders"]]  # internet -> load balancer -> api -> database, from security groups
        assert t.get_blast_zone("front").reaches_crown_jewel
    finally:
        db.delete_graph()
        db.reset_graph(token)


@pytestmark_db
def test_playbook_lists_applied_fixes_with_osv_versions(sample, monkeypatch):
    import remediation
    remediation._cache.clear()
    rec = {"affected": [{"package": {"ecosystem": "npm", "name": "qs"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "6.10.3"}]}]}]}
    monkeypatch.setattr(remediation, "_osv", lambda vid: rec if vid == "CVE-2022-24999" else None)
    assert "Nothing to remediate" in t.generate_remediation_playbook("applied").playbook_yaml
    engine.apply_fix("F3", "auto")  # CVE-2022-24999 on edge-node
    out = t.generate_remediation_playbook("applied")
    assert [(f.cve_id, f.package, f.fixed_version) for f in out.fixes] == [("CVE-2022-24999", "qs", "6.10.3")]
    assert "npm install --save qs@6.10.3" in out.playbook_yaml and "edge-node" in out.playbook_yaml


@pytestmark_db
def test_import_rate_limit_is_enforced(monkeypatch):
    import main
    monkeypatch.setattr(main, "MAX_IMPORTS_PER_HOUR", 1)
    main._IMPORTS.clear()
    token = db.use_graph(db.workspace_graph(f"rl-{uuid.uuid4().hex[:8]}"))
    raw = {"hosts": [{"id": "web", "exposed": True}], "datastores": [{"id": "db", "crown": True}], "edges": [["web", "db"]]}
    try:
        monkeypatch.setattr(enrich, "ENABLED", False)
        assert main.import_inventory(raw)["imported"]["hosts"] == 1
        with pytest.raises(main.HTTPException) as err:
            main.import_inventory(raw)
        assert err.value.status_code == 429
    finally:
        db.delete_graph()
        db.reset_graph(token)
