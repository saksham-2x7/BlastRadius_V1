"""End-to-end behaviour against a real FalkorDB (skipped when none is reachable): the agent's tools, the safety guard,
per-tenant memory and per-user workspaces. CI runs these with a FalkorDB service container."""
import uuid

import pytest

from blastradius_db import db

try:
    db.run("RETURN 1")
    UP = True
except Exception:  # no database here
    UP = False

pytestmark = pytest.mark.skipif(not UP, reason="needs a reachable FalkorDB")

import engine  # noqa: E402
import ingest  # noqa: E402
import threat_tools as t  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_sample():
    token = db.use_graph(db.SAMPLE_GRAPH)
    engine.reset()
    yield
    db.reset_graph(token)


def test_sample_story_four_paths_and_choke_point():
    s = engine.scan()
    assert s["summary"]["paths"] == 4 and s["workspace"] == "sample"
    assert t.get_choke_points(1).ranking[0].host == "api-gateway"  # the host on 3 of 4 live paths, on any FalkorDB version


def test_algorithm_tools_return_routes_and_centrality():
    top = t.get_choke_points(3).ranking[0]
    assert top.betweenness > 0 and top.pagerank >= 0
    out = t.explain_attack_path(3)
    assert out.routes and all(r.route[0] == "internet" and r.route[-1] == "db-customers" for r in out.routes)


def test_only_the_real_choke_point_is_flagged_as_one():
    rows = t.get_choke_points(5).ranking
    assert [r.host for r in rows if r.is_choke_point] == ["api-gateway"]  # edge-apache and worker-java are just high-exposure hosts


def test_routes_tie_deterministically_and_never_include_cut_routes():
    first = t.explain_attack_path(5)
    assert first.shortest_hops == 3 and first.tied_routes == 4  # nginx, apache (x2) and node routes all tie at 3 hops
    assert [r.route for r in first.routes] == [r.route for r in t.explain_attack_path(5).routes]  # same answer every time
    engine.apply_fix("F3", "auto")  # cuts the edge-node route
    engine.apply_fix("F1", "auto")  # cuts the edge-nginx route
    later = t.explain_attack_path(5)
    assert all(r.still_exploitable for r in later.routes)
    assert all(r.route[1] not in ("edge-node", "edge-nginx") for r in later.routes)  # routes through fixed hosts are gone
    engine.apply_fix("F4", "approved")
    engine.apply_fix("F2", "auto")
    assert t.explain_attack_path(3).routes == []  # all four fixes in the pitch: no route remains


def test_agent_refuses_approval_tier_and_applies_auto_tier():
    refused = t.apply_safe_fix("F4", "choke point, should be refused")
    assert refused.decision == "needs_human_approval" and refused.paths_after == refused.paths_before
    applied = t.apply_safe_fix("F3", "leaf host, one path")
    assert applied.decision == "applied" and applied.paths_after < applied.paths_before


def test_agent_ignores_unreachable_decoy():
    assert t.apply_safe_fix("F7", "loud but unreachable").decision == "not_applicable"


def test_the_two_fixes_in_the_pitch_take_four_paths_to_zero():
    engine.apply_fix("F4", "approved")
    engine.apply_fix("F2", "auto")  # becomes auto once the choke point is gone
    assert engine.scan()["summary"]["paths"] == 0


def test_memory_records_decisions_and_survives_restore():
    t.apply_safe_fix("F4", "refused on purpose")
    engine.reset()
    assert any(a.decision == "needs_human_approval" for a in t.recall_agent_memory(10).actions)


SPEC = {"hosts": [{"id": "web", "exposed": True}], "datastores": [{"id": "db", "crown": True}], "edges": [["web", "db"]],
        "findings": [{"host": "web", "cve": "CVE-2021-44228", "cvss": 9.8}]}


def test_workspaces_and_memory_are_isolated_per_user():
    t.apply_safe_fix("F3", "sample action")
    marker = f"it-{uuid.uuid4().hex[:8]}"
    mine = db.use_graph(db.workspace_graph(marker))
    try:
        ingest.build(ingest.ImportSpec.model_validate(SPEC))
        assert engine.scan()["workspace"] == "own" and engine.scan()["summary"]["paths"] == 1
        assert t.recall_agent_memory(10).actions == []  # a new tenant starts with an empty memory
        t.apply_safe_fix("F1", f"marker {marker}")
        assert [a.rationale for a in t.recall_agent_memory(10).actions] == [f"marker {marker}"]
        with pytest.raises(engine.FixError):
            engine.reset()  # restoring the shared sample must not be possible from a user workspace
    finally:
        db.delete_graph()
        db.reset_graph(mine)
    assert engine.scan()["summary"]["patched"] == 1  # the sample kept its own state
    assert all(marker not in a.rationale for a in t.recall_agent_memory(25).actions)  # nothing leaked into the sample


def test_github_filing_is_a_noop_without_configuration():
    r = t.file_github_issue("F4")
    assert r.filed is False and "not configured" in r.message


def test_redundant_internet_edges_do_not_double_count_paths():
    """Regression: listing `internet -> host` for a host already marked `exposed` used to double every path through it."""
    spec = {
        "hosts": [{"id": "vpn", "exposed": True}, {"id": "app"}],
        "datastores": [{"id": "db", "crown": True}],
        "edges": [["internet", "vpn"], ["vpn", "app"], ["vpn", "app"], ["app", "db"]],
        "findings": [{"host": "vpn", "cve": "CVE-2022-40684", "cvss": 9.8}, {"host": "app", "cve": "CVE-2021-44228", "cvss": 10.0}],
    }
    mine = db.use_graph(db.workspace_graph(f"it-{uuid.uuid4().hex[:8]}"))
    try:
        counts = ingest.build(ingest.ImportSpec.model_validate(spec))
        assert counts["edges"] == 2
        assert engine.scan()["summary"]["paths"] == 1
    finally:
        db.delete_graph()
        db.reset_graph(mine)
