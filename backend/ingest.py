"""Validate and convert a user-supplied inventory (JSON, optionally with Trivy or Grype reports) into a workspace graph.

Rule 6 of the hackathon: only load public, synthetic or your own data. Everything here is size-capped.
"""
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

import tfimport
from blastradius_db import importer, memory

ID = r"^[A-Za-z0-9_.-]{1,40}$"
CVE = r"^CVE-[0-9]{4}-[0-9]{4,7}$"
MAX_FINDINGS = 1000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostIn(_Strict):
    id: str = Field(pattern=ID)
    software: str | None = Field(default=None, max_length=80)
    role: str | None = Field(default=None, max_length=80)
    exposed: bool = Field(default=False, description="Reachable directly from the internet.")


class StoreIn(_Strict):
    id: str = Field(pattern=ID)
    crown: bool = Field(default=False, description="A crown jewel: the asset attackers are after.")
    software: str | None = Field(default=None, max_length=80)
    role: str | None = Field(default=None, max_length=80)


class FindingIn(_Strict):
    host: str = Field(pattern=ID)
    cve: str = Field(pattern=CVE)
    cvss: float = Field(default=5.0, ge=0, le=10)
    product: str | None = Field(default=None, max_length=80)
    summary: str | None = Field(default=None, max_length=240)


class TrivyIn(_Strict):
    host: str = Field(pattern=ID)
    report: dict[str, Any]


class GrypeIn(_Strict):
    host: str = Field(pattern=ID)
    report: dict[str, Any]


class ImportSpec(_Strict):
    hosts: list[HostIn] = Field(min_length=1, max_length=500)
    datastores: list[StoreIn] = Field(min_length=1, max_length=50)
    edges: list[tuple[str, str]] = Field(default_factory=list, max_length=2000, description="[from, to] network reachability.")
    findings: list[FindingIn] = Field(default_factory=list, max_length=MAX_FINDINGS)
    trivy: list[TrivyIn] = Field(default_factory=list, max_length=20, description="Trivy JSON reports, one per host.")
    grype: list[GrypeIn] = Field(default_factory=list, max_length=20, description="Grype JSON reports, one per host.")

    @model_validator(mode="after")
    def _consistent(self) -> "ImportSpec":
        ids = [h.id for h in self.hosts] + [s.id for s in self.datastores]
        if len(set(ids)) != len(ids) or "internet" in ids:
            raise ValueError("Host and datastore ids must be unique and not 'internet'.")
        if not any(s.crown for s in self.datastores):
            raise ValueError("Mark at least one datastore as crown: true.")
        known = set(ids) | {"internet"}
        for a, b in self.edges:
            if a not in known or b not in known:
                raise ValueError(f"Edge [{a}, {b}] mentions an unknown node.")
        hosts = {h.id for h in self.hosts}
        for f in [*self.findings, *self.trivy, *self.grype]:
            if f.host not in hosts:
                raise ValueError(f"Finding/report references unknown host '{f.host}'.")
        return self


def _trivy_findings(t: TrivyIn) -> list[FindingIn]:
    out: list[FindingIn] = []
    for res in (t.report.get("Results") or [])[:50]:
        for v in (res.get("Vulnerabilities") or [])[:200]:
            cve = str(v.get("VulnerabilityID", ""))
            if not re.fullmatch(CVE, cve):
                continue
            scores = [c.get("V3Score") or c.get("V2Score") for c in (v.get("CVSS") or {}).values() if isinstance(c, dict)]
            scores = [s for s in scores if isinstance(s, (int, float))]
            out.append(FindingIn(host=t.host, cve=cve, cvss=float(max(scores)) if scores else 5.0,
                                 product=str(v.get("PkgName") or "")[:80] or None,
                                 summary=str(v.get("Title") or v.get("Description") or "")[:240] or None))
    return out


def _grype_findings(g: GrypeIn) -> list[FindingIn]:
    out: list[FindingIn] = []
    for m in (g.report.get("matches") or [])[:500]:
        v = m.get("vulnerability") or {}
        cve = str(v.get("id", ""))
        if not re.fullmatch(CVE, cve):
            continue
        scores = [c.get("metrics", {}).get("baseScore") for c in (v.get("cvss") or []) if isinstance(c, dict)]
        scores = [s for s in scores if isinstance(s, (int, float))]
        out.append(FindingIn(host=g.host, cve=cve, cvss=float(max(scores)) if scores else 5.0,
                             product=str((m.get("artifact") or {}).get("name") or "")[:80] or None,
                             summary=str(v.get("description") or "")[:240] or None))
    return out


def normalize_edges(spec: ImportSpec) -> list[tuple[str, str]]:
    """Drop repeated edges, self-loops and `internet -> host` edges already implied by `exposed: true`. A duplicate edge
    would otherwise be walked twice and double-count every attack path through it."""
    exposed = {h.id for h in spec.hosts if h.exposed}
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for a, b in spec.edges:
        if a == b or (a, b) in seen or (a == "internet" and b in exposed):
            continue
        seen.add((a, b))
        out.append((a, b))
    return out


def build(spec: ImportSpec) -> dict[str, int]:
    """Write the CURRENT graph (selected by the caller) from the spec. Returns counts for the response."""
    findings = [*spec.findings, *(f for t in spec.trivy for f in _trivy_findings(t)), *(f for g in spec.grype for f in _grype_findings(g))]
    seen: set[tuple[str, str]] = set()
    unique = []
    for f in findings:
        if (f.host, f.cve) not in seen:
            seen.add((f.host, f.cve))
            unique.append(f)
    unique = unique[:MAX_FINDINGS]
    rows = [
        # Fallback until live KEV/EPSS are applied: CVSS >= 7 counts as exploitable.
        {"id": f"F{i + 1}", "host": f.host, "cve": f.cve, "cvss": f.cvss, "epss": 0.0, "kev": False, "exp": f.cvss >= 7.0,
         "product": f.product or "", "summary": f.summary or ""}
        for i, f in enumerate(unique)
    ]
    edges = normalize_edges(spec)
    importer.load_workspace([h.model_dump() for h in spec.hosts], [s.model_dump() for s in spec.datastores], edges, rows)
    try:  # a re-import replaces the graph, so earlier approval requests no longer refer to anything
        memory.cancel_pending()
    except Exception:
        pass
    return {"hosts": len(spec.hosts), "datastores": len(spec.datastores), "edges": len(edges), "findings": len(rows)}


def parse(raw: dict[str, Any]) -> tuple[ImportSpec, list[str]]:
    """Validate an import payload. A `terraform` key (the JSON from `terraform show -json`) is converted to hosts, data
    stores and edges first; anything you list explicitly wins over what Terraform produced for the same id."""
    raw = dict(raw)
    tf = raw.pop("terraform", None)
    warnings: list[str] = []
    if tf is not None:
        if not isinstance(tf, dict):
            raise ValueError("terraform must be the JSON object printed by `terraform show -json`.")
        conv = tfimport.convert(tf)
        warnings = conv["warnings"]
        for key in ("hosts", "datastores"):
            mine = {x["id"]: x for x in conv[key]}
            mine.update({x["id"]: x for x in raw.get(key, []) if isinstance(x, dict) and "id" in x})
            raw[key] = list(mine.values())
        raw["edges"] = [list(e) for e in conv["edges"]] + [e for e in raw.get("edges", [])]
    return ImportSpec.model_validate(raw), warnings
