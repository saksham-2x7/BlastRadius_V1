"""Turn `terraform show -json` output (applied state, or a plan) into BlastRadius hosts, data stores and reachability.

This is real infrastructure-as-code, not a hand-made sample: an instance or load balancer is a host, a database is a crown-jewel
data store, and security groups decide who can reach whom:
  * an ingress rule open to 0.0.0.0/0 (or ::/0) makes the group's members reachable from the internet;
  * an ingress rule whose source is another security group means members of that group can reach this group's members.
Only AWS network resources are understood today. Everything is read from the JSON you provide; nothing is called or fetched.
"""
import re
from typing import Any

HOST_TYPES = {"aws_instance", "aws_lb", "aws_alb", "aws_lambda_function"}
STORE_TYPES = {"aws_db_instance", "aws_rds_cluster", "aws_elasticache_cluster", "aws_redshift_cluster"}
CROWN_TYPES = {"aws_db_instance", "aws_rds_cluster"}  # databases are crown jewels by default; tag a resource crown=true to add more
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
MAX_RESOURCES = 400


def _walk(module: dict[str, Any]) -> list[dict[str, Any]]:
    out = list(module.get("resources") or [])
    for child in module.get("child_modules") or []:
        out.extend(_walk(child))
    return out


def _resources(doc: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """All managed resources, and whether this looks like an unapplied plan (planned_values only)."""
    root = doc.get("values")
    is_plan = False
    if not root:
        root, is_plan = doc.get("planned_values") or {}, True
    res = [r for r in _walk(root.get("root_module") or {}) if r.get("mode", "managed") == "managed"]
    return res[:MAX_RESOURCES], is_plan


def _first(v: Any) -> dict[str, Any]:
    return v[0] if isinstance(v, list) and v and isinstance(v[0], dict) else {}


def _strs(v: Any) -> list[str]:
    return [x for x in (v or []) if isinstance(x, str)]


def _sg_ids(values: dict[str, Any]) -> list[str]:
    ids = _strs(values.get("vpc_security_group_ids")) + _strs(values.get("security_groups"))
    ids += _strs(_first(values.get("vpc_config")).get("security_group_ids"))
    return list(dict.fromkeys(ids))


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name).strip("-.")[:40] or "resource"


def _unique(base: str, rtype: str, used: set[str]) -> str:
    for cand in (base, f"{base}-{rtype.removeprefix('aws_')}"[:40]):
        if cand not in used:
            used.add(cand)
            return cand
    n = 2
    while f"{base[:36]}-{n}" in used:
        n += 1
    used.add(f"{base[:36]}-{n}")
    return f"{base[:36]}-{n}"


def convert(doc: dict[str, Any]) -> dict[str, Any]:
    """Returns {"hosts", "datastores", "edges", "warnings", "mapping"} ready to merge into an import spec."""
    resources, is_plan = _resources(doc)
    open_sgs: set[str] = set()
    sg_edges: set[tuple[str, str]] = set()  # (source security group id, destination security group id)

    def rule(dst: str | None, cidrs: list[str], src: str | None) -> None:
        if not dst:
            return
        if OPEN_CIDRS & set(cidrs):
            open_sgs.add(dst)
        if src and src != dst:
            sg_edges.add((src, dst))

    for r in resources:
        v, t = r.get("values") or {}, r.get("type")
        if t == "aws_security_group":
            for ing in v.get("ingress") or []:
                rule(v.get("id"), _strs(ing.get("cidr_blocks")) + _strs(ing.get("ipv6_cidr_blocks")), None)
                for src in _strs(ing.get("security_groups")):
                    rule(v.get("id"), [], src)
        elif t == "aws_security_group_rule" and v.get("type") == "ingress":
            rule(v.get("security_group_id"), _strs(v.get("cidr_blocks")) + _strs(v.get("ipv6_cidr_blocks")), v.get("source_security_group_id"))
        elif t == "aws_vpc_security_group_ingress_rule":
            rule(v.get("security_group_id"), [v.get("cidr_ipv4") or "", v.get("cidr_ipv6") or ""], v.get("referenced_security_group_id"))

    used: set[str] = set()
    hosts: list[dict[str, Any]] = []
    stores: list[dict[str, Any]] = []
    members: dict[str, list[str]] = {}
    exposed_stores: list[str] = []
    mapping: dict[str, str] = {}
    unknown_sgs = 0
    for r in resources:
        t, v = r.get("type"), r.get("values") or {}
        if t not in HOST_TYPES and t not in STORE_TYPES:
            continue
        node = _unique(_slug(r.get("name") or t), t, used)
        mapping[r.get("address") or node] = node
        sgs = _sg_ids(v)
        if not sgs and is_plan:
            unknown_sgs += 1
        tags = v.get("tags") or {}
        role = str(tags.get("Name") or tags.get("name") or t.removeprefix("aws_"))[:80]
        is_open = any(s in open_sgs for s in sgs)
        if t in HOST_TYPES:
            if t == "aws_instance":
                software = str(v.get("instance_type") or "ec2 instance")
            elif t in ("aws_lb", "aws_alb"):
                software = f"aws_lb ({v.get('load_balancer_type') or 'application'})"
            else:
                software = f"lambda {v.get('runtime') or ''}".strip()
            internal = bool(v.get("internal")) if t in ("aws_lb", "aws_alb") else False
            hosts.append({"id": node, "software": software[:80], "role": role, "exposed": bool(is_open and not internal)})
        else:
            engine = " ".join(str(x) for x in (v.get("engine"), v.get("engine_version")) if x) or t.removeprefix("aws_")
            crown = t in CROWN_TYPES or str(tags.get("crown", "")).lower() == "true"
            stores.append({"id": node, "crown": crown, "software": engine[:80], "role": role})
            if is_open:
                exposed_stores.append(node)
        for s in sgs:
            members.setdefault(s, []).append(node)

    edges: list[tuple[str, str]] = [("internet", s) for s in exposed_stores]
    for src, dst in sorted(sg_edges):
        for a in members.get(src, []):
            for b in members.get(dst, []):
                if a != b and (a, b) not in edges:
                    edges.append((a, b))
    warnings: list[str] = []
    if is_plan:
        warnings.append("This looks like an unapplied plan (planned_values). Security group ids are unknown until apply, so "
                        "reachability may be incomplete. Import `terraform show -json` from applied state for full edges.")
    if unknown_sgs:
        warnings.append(f"{unknown_sgs} resource(s) had no known security groups.")
    if not hosts and not stores:
        warnings.append("No supported AWS resources found (aws_instance, aws_lb/aws_alb, aws_lambda_function, aws_db_instance, aws_rds_cluster, aws_elasticache_cluster, aws_redshift_cluster).")
    if stores and not any(s["crown"] for s in stores):
        warnings.append("No crown jewel found: tag a data store resource with crown=true.")
    return {"hosts": hosts, "datastores": stores, "edges": edges, "warnings": warnings, "mapping": mapping}
