"""Build a workspace graph from a user's own inventory (hosts, data stores, reachability, findings).

Same schema as the sample, so every engine query and agent tool works on imported data unchanged.
"""
from typing import Any

from .db import delete_graph, run
from .seed import recompute_exploitable_hosts


def load_workspace(hosts: list[dict[str, Any]], stores: list[dict[str, Any]], edges: list[tuple[str, str]],
                   findings: list[dict[str, Any]]) -> None:
    """Replace the CURRENT graph (the caller selects it with db.use_graph) with this inventory."""
    delete_graph()
    run("CREATE (:Internet {id: 'internet', crown: false, xf: [], software: 'Public internet', role: 'Untrusted network'})")
    run("UNWIND $rows AS r CREATE (:Host {id: r.id, crown: false, xf: [], software: r.software, role: r.role})", {"rows": hosts})
    run("UNWIND $rows AS r CREATE (:DataStore {id: r.id, crown: r.crown, xf: [], software: r.software, role: r.role})", {"rows": stores})
    run("CREATE INDEX FOR (n:Host) ON (n.id)")
    run("CREATE INDEX FOR (n:Finding) ON (n.id)")
    exposed = [{"a": "internet", "b": h["id"]} for h in hosts if h.get("exposed")]
    rows = exposed + [{"a": a, "b": b} for a, b in edges]
    run("UNWIND $rows AS r MATCH (a {id: r.a}), (b {id: r.b}) CREATE (a)-[:CAN_REACH]->(b)", {"rows": rows})
    run(
        """UNWIND $rows AS r MATCH (h:Host {id: r.host})
           CREATE (h)-[:HAS_FINDING]->(:Finding {id: r.id, cve: r.cve, cvss: r.cvss, epss: r.epss, kev: r.kev,
                                                 exploitable: r.exp, patched: false, product: r.product, summary: r.summary})""",
        {"rows": findings},
    )
    recompute_exploitable_hosts()
