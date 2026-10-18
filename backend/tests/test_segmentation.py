"""Minimum network cut. Pure functions plus one integration check against FalkorDB's algo.maxFlow."""
import pytest

import segmentation
from blastradius_db import db

SAMPLE_PATHS = [
    ["internet", "edge-apache", "worker-java", "db-customers"],
    ["internet", "edge-node", "api-gateway", "db-customers"],
    ["internet", "edge-apache", "api-gateway", "db-customers"],
    ["internet", "edge-nginx", "api-gateway", "db-customers"],
]


def removed(paths, cut):
    """Does deleting the cut edges leave no route from the internet to a sink?"""
    gone = set(cut)
    return all(any((a, b) in gone for a, b in zip(p, p[1:])) for p in paths)


def test_sample_needs_only_two_connections_cut():
    cut = segmentation.min_cut(SAMPLE_PATHS)
    assert len(cut) == 2 and removed(SAMPLE_PATHS, cut)  # several cuts of size 2 exist; any valid one is correct, and 1 edge is not enough
    assert not any(removed(SAMPLE_PATHS, [e]) for e in {e for p in SAMPLE_PATHS for e in zip(p, p[1:])})


def test_single_chain_is_cut_once():
    cut = segmentation.min_cut([["internet", "web", "app", "db"]])
    assert len(cut) == 1 and removed([["internet", "web", "app", "db"]], cut)


def test_no_paths_means_no_cut_and_it_is_deterministic():
    assert segmentation.min_cut([]) == []
    assert segmentation.min_cut(SAMPLE_PATHS) == segmentation.min_cut(list(reversed(SAMPLE_PATHS)))


def test_parallel_independent_routes_all_need_a_cut():
    paths = [["internet", "a", "db"], ["internet", "b", "db"], ["internet", "c", "db"]]
    cut = segmentation.min_cut(paths)
    assert len(cut) == 3 and removed(paths, cut)


try:
    db.run("RETURN 1")
    UP = True
except Exception:
    UP = False


@pytest.mark.skipif(not UP, reason="needs a reachable FalkorDB")
def test_tool_matches_falkordb_maxflow_on_the_sample():
    import engine
    import threat_tools as t
    token = db.use_graph(db.SAMPLE_GRAPH)
    try:
        engine.reset()
        out = t.suggest_network_cut()
        assert out.paths_now == 4 and len(out.cut) == 2
        assert out.structural_edge_disjoint_routes in (None, 2, 3)  # FalkorDB's whole-network figure (None only if the algorithm is unavailable)
        engine.apply_fix("F4", "approved")
        engine.apply_fix("F2", "auto")
        assert t.suggest_network_cut().cut == []  # after the two fixes no live path is left
    finally:
        db.reset_graph(token)
