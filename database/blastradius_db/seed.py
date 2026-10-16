"""Sample workspace: realistic infrastructure mapped to real CVE ids.

DATA NOTICE: CVE ids, products and descriptions are real public vulnerabilities. The CVSS, CISA-KEV and EPSS values
are an ILLUSTRATIVE SNAPSHOT from memory, not live feeds. EPSS changes daily and KEV grows weekly, so verify against
NVD (CVSS), CISA KEV and FIRST EPSS before relying on any number here. The network topology is synthetic.
"""
from .db import delete_graph, run

DATA_NOTICE = (
    "CVE ids are real. CVSS, KEV and EPSS values are an illustrative snapshot, not live feeds. "
    "The infrastructure topology is synthetic."
)

# id, kind, crown jewel?, software, role
NODES = [
    ("internet", "internet", False, "Public internet", "Untrusted network"),
    ("edge-nginx", "host", False, "nginx 1.18.0 (Ubuntu 20.04)", "Reverse proxy"),
    ("edge-apache", "host", False, "Apache httpd 2.4.49", "Marketing site"),
    ("edge-node", "host", False, "Node.js 14 / Express", "Customer portal"),
    ("api-gateway", "host", False, "OpenSSL 1.0.1f TLS gateway", "Internal API gateway"),
    ("worker-java", "host", False, "Java 11 / Log4j 2.17.0", "Billing worker"),
    ("cache-redis", "host", False, "Redis 6.2", "Session cache"),
    ("legacy-ftp", "host", False, "vsftpd + Log4j 2.14 admin UI", "Legacy file transfer"),
    ("batch-legacy", "host", False, "bash 4.2 CGI scripts", "Decommissioned batch server"),
    ("db-customers", "datastore", True, "PostgreSQL 13", "Customer database (crown jewel)"),
    ("archive-ftp", "datastore", False, "NFS cold archive", "Cold archive"),
]

# who can network-reach whom
EDGES = [
    ("internet", "edge-nginx"), ("internet", "edge-apache"), ("internet", "edge-node"), ("internet", "legacy-ftp"),
    ("edge-nginx", "api-gateway"), ("edge-apache", "api-gateway"), ("edge-node", "api-gateway"),
    ("edge-apache", "worker-java"),
    ("api-gateway", "db-customers"), ("worker-java", "db-customers"), ("worker-java", "cache-redis"),
    ("legacy-ftp", "archive-ftp"),
    ("batch-legacy", "db-customers"),  # scary, but nothing can reach batch-legacy
]

# id, host, cve, cvss, epss (0-1), kev, product, summary        (exploitable = kev OR epss >= 0.1)
FINDINGS = [
    ("F1", "edge-nginx", "CVE-2021-23017", 8.1, 0.12, False, "nginx",
     "Off-by-one in the nginx DNS resolver can lead to memory overwrite"),
    ("F2", "edge-apache", "CVE-2021-41773", 7.5, 0.97, True, "Apache HTTP Server 2.4.49",
     "Path traversal and file disclosure (remote code execution with CGI enabled)"),
    ("F3", "edge-node", "CVE-2022-24999", 7.5, 0.15, False, "qs (npm)",
     "Prototype pollution in the qs query-string parser"),
    ("F4", "api-gateway", "CVE-2014-0160", 7.5, 0.97, True, "OpenSSL",
     "Heartbleed: TLS heartbeat over-read leaks memory, including keys and sessions"),   # the hidden choke point
    ("F5", "worker-java", "CVE-2021-44832", 6.6, 0.20, False, "Apache Log4j 2",
     "Remote code execution via a malicious JDBC appender configuration"),
    ("F6", "legacy-ftp", "CVE-2021-44228", 10.0, 0.97, True, "Apache Log4j 2",
     "Log4Shell: JNDI lookup remote code execution"),                                    # CVSS 10 but leads nowhere
    ("F7", "batch-legacy", "CVE-2014-6271", 9.8, 0.97, True, "GNU Bash",
     "Shellshock: command injection through crafted environment variables"),             # CVSS 9.8 but unreachable
    ("F8", "edge-node", "CVE-2019-10744", 9.1, 0.01, False, "lodash (npm)",
     "Prototype pollution in defaultsDeep"),                                             # scary, rarely exploited
    ("F9", "cache-redis", "CVE-2022-35977", 5.5, 0.02, False, "Redis",
     "Integer overflow in SETRANGE / SORT can exhaust memory"),
]

RECOMPUTE_XF = [
    "MATCH (h:Host) SET h.xf = []",
    """MATCH (h:Host)-[:HAS_FINDING]->(f:Finding)
       WHERE f.exploitable = true AND f.patched = false
       WITH h, collect(f.id) AS xf SET h.xf = xf""",
]


def recompute_exploitable_hosts() -> None:
    """Derive each host's list of still-exploitable finding ids from the findings (single source of truth)."""
    for q in RECOMPUTE_XF:
        run(q)


def load() -> None:
    delete_graph()
    for kind, label in (("internet", "Internet"), ("host", "Host"), ("datastore", "DataStore")):
        rows = [{"id": n, "crown": c, "software": sw, "role": role} for n, k, c, sw, role in NODES if k == kind]
        run(
            f"UNWIND $rows AS r CREATE (:{label} {{id: r.id, crown: r.crown, xf: [], software: r.software, role: r.role}})",
            {"rows": rows},
        )
    run("CREATE INDEX FOR (n:Host) ON (n.id)")
    run("CREATE INDEX FOR (n:Finding) ON (n.id)")
    run(
        "UNWIND $rows AS r MATCH (a {id: r.a}), (b {id: r.b}) CREATE (a)-[:CAN_REACH]->(b)",
        {"rows": [{"a": a, "b": b} for a, b in EDGES]},
    )
    rows = [
        {"id": i, "host": h, "cve": c, "cvss": s, "epss": e, "kev": k, "exp": bool(k or e >= 0.1), "product": p, "summary": sm}
        for i, h, c, s, e, k, p, sm in FINDINGS
    ]
    run(
        """UNWIND $rows AS r MATCH (h:Host {id: r.host})
           CREATE (h)-[:HAS_FINDING]->(:Finding {id: r.id, cve: r.cve, cvss: r.cvss, epss: r.epss, kev: r.kev,
                                                 exploitable: r.exp, patched: false, product: r.product, summary: r.summary})""",
        {"rows": rows},
    )
    recompute_exploitable_hosts()


def is_seeded() -> bool:
    """True only if the graph already holds the current schema (older seeds lack `product`, so they get reloaded)."""
    return run("MATCH (f:Finding) WHERE f.product IS NOT NULL RETURN count(f)")[0][0] > 0
