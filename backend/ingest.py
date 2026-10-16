"""Validate and convert a user-supplied inventory (JSON, optionally with Trivy reports) into a workspace graph.

Rule 6 of the hackathon: only load public, synthetic or your own data. Everything here is size-capped.
"""
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from blastradius_db import importer

ID = r"^[A-Za-z0-9_.-]{1,40}$"
CVE = r"^CVE-[0-9]{4}-[0-9]{4,7}$"
MAX_FINDINGS = 300


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


class ImportSpec(_Strict):
    hosts: list[HostIn] = Field(min_length=1, max_length=60)
    datastores: list[StoreIn] = Field(min_length=1, max_length=20)
    edges: list[tuple[str, str]] = Field(default_factory=list, max_length=300, description="[from, to] network reachability.")
    findings: list[FindingIn] = Field(default_factory=list, max_length=MAX_FINDINGS)
    trivy: list[TrivyIn] = Field(default_factory=list, max_length=20, description="Trivy JSON reports, one per host.")

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
        for f in [*self.findings, *self.trivy]:
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


def build(spec: ImportSpec) -> dict[str, int]:
    """Write the CURRENT graph (selected by the caller) from the spec. Returns counts for the response."""
    findings = [*spec.findings, *(f for t in spec.trivy for f in _trivy_findings(t))]
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
    importer.load_workspace(
        [h.model_dump() for h in spec.hosts], [s.model_dump() for s in spec.datastores], list(spec.edges), rows
    )
    return {"hosts": len(spec.hosts), "datastores": len(spec.datastores), "edges": len(spec.edges), "findings": len(rows)}
