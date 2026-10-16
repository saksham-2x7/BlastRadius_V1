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
    routes = t.explain_attack_path(3).routes
    assert routes and all(r.route[0] == "internet" and r.route[-1] == "db-customers" for r in routes)


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
