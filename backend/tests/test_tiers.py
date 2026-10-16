"""The agent's safety guard: tiers are decided by graph facts only. Pure-function tests, no database needed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("LIVE_FEEDS", "0")

import engine  # noqa: E402


def tier(**kw):
    base = dict(exploitable=True, patched=False, on_paths=1, total=4, host="h", chokes=set(), crown_neighbours=set())
    base.update(kw)
    return engine._tier(**base)[0]


def test_patched_is_patched():
    assert tier(patched=True) == "patched"


def test_not_on_any_path_is_monitor_even_if_exploitable():
    assert tier(on_paths=0) == "monitor"  # the CVSS 10.0 decoy: loud but unreachable


def test_choke_point_needs_approval():
    assert tier(on_paths=3, host="gw", chokes={"gw"}) == "approval"


def test_crown_jewel_neighbour_needs_approval():
    assert tier(host="db-adjacent", crown_neighbours={"db-adjacent"}) == "approval"


def test_wide_blast_radius_needs_approval():
    assert tier(on_paths=2) == "approval"


def test_leaf_host_single_path_is_auto():
    assert tier(on_paths=1) == "auto"


def test_choke_beats_leaf_rule():
    # a single-path host that is also flagged as choke must never be auto
    assert tier(on_paths=1, host="x", chokes={"x"}) == "approval"


def test_notice_falls_back_to_snapshot_without_feed():
    import enrich
    enrich._cache = None
    assert "illustrative snapshot" in enrich.notice()
