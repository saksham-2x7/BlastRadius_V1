"""Live-feed client with the network mocked: parsing, batching and the never-break-the-demo fallback."""
import json

import enrich


def fake_get(url, timeout=12.0):
    if "known_exploited" in url:
        return json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode()
    cves = url.split("cve=")[1].split(",")
    return json.dumps({"data": [{"cve": c, "epss": "0.5"} for c in cves]}).encode()


def test_fetch_parses_kev_and_epss(monkeypatch):
    monkeypatch.setattr(enrich, "_get", fake_get)
    data = enrich.fetch(["CVE-2021-44228", "CVE-2020-8177"])
    assert data["kev"] == {"CVE-2021-44228"}
    assert data["epss"] == {"CVE-2021-44228": 0.5, "CVE-2020-8177": 0.5}


def test_fetch_batches_epss_requests(monkeypatch):
    urls = []
    monkeypatch.setattr(enrich, "_get", lambda u, t=12.0: (urls.append(u), fake_get(u))[1])
    enrich.fetch([f"CVE-2020-{1000 + i}" for i in range(120)])
    assert len([u for u in urls if "epss" in u]) == 3  # 50 + 50 + 20


def test_fetch_returns_none_when_a_feed_is_down(monkeypatch):
    def boom(url, timeout=12.0):
        raise OSError("network down")
    monkeypatch.setattr(enrich, "_get", boom)
    assert enrich.fetch(["CVE-2021-44228"]) is None


def test_fetch_returns_none_on_malformed_payload(monkeypatch):
    monkeypatch.setattr(enrich, "_get", lambda u, t=12.0: b"<html>rate limited</html>")
    assert enrich.fetch(["CVE-2021-44228"]) is None


def test_disabled_feeds_do_nothing(monkeypatch):
    monkeypatch.setattr(enrich, "ENABLED", False)
    assert enrich.enrich_current_graph() is False
