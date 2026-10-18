"""Terraform state -> topology. Pure functions, no database needed."""
import ingest
import tfimport

STATE = {"format_version": "1.0", "values": {"root_module": {"resources": [
    {"address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group", "name": "web",
     "values": {"id": "sg-web", "ingress": [{"cidr_blocks": ["0.0.0.0/0"], "security_groups": []}]}},
    {"address": "aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
     "values": {"id": "sg-app", "ingress": [{"cidr_blocks": [], "security_groups": ["sg-web"]}]}},
    {"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
     "values": {"id": "sg-db", "ingress": [{"cidr_blocks": [], "security_groups": ["sg-app"]}]}},
    {"address": "aws_lb.front", "mode": "managed", "type": "aws_lb", "name": "front",
     "values": {"internal": False, "load_balancer_type": "application", "security_groups": ["sg-web"], "tags": {"Name": "public lb"}}},
    {"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api",
     "values": {"instance_type": "t3.small", "vpc_security_group_ids": ["sg-app"], "tags": {"Name": "orders api"}}},
    {"address": "aws_db_instance.orders", "mode": "managed", "type": "aws_db_instance", "name": "orders",
     "values": {"engine": "postgres", "engine_version": "13.7", "vpc_security_group_ids": ["sg-db"]}},
    {"address": "aws_s3_bucket.logs", "mode": "managed", "type": "aws_s3_bucket", "name": "logs", "values": {}},
]}}}


def test_converts_hosts_stores_and_reachability():
    c = tfimport.convert(STATE)
    assert {h["id"]: h["exposed"] for h in c["hosts"]} == {"front": True, "api": False}  # only the open-to-internet group is exposed
    assert [(d["id"], d["crown"], d["software"]) for d in c["datastores"]] == [("orders", True, "postgres 13.7")]
    assert ("front", "api") in c["edges"] and ("api", "orders") in c["edges"]  # security-group-to-security-group rules become edges
    assert c["warnings"] == []


def test_internal_load_balancer_is_not_exposed():
    doc = {"values": {"root_module": {"resources": [
        {"type": "aws_security_group", "name": "w", "values": {"id": "sg-1", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}},
        {"type": "aws_lb", "name": "internal", "values": {"internal": True, "security_groups": ["sg-1"]}},
    ]}}}
    assert tfimport.convert(doc)["hosts"][0]["exposed"] is False


def test_child_modules_and_rule_resources_are_read():
    doc = {"values": {"root_module": {"resources": [], "child_modules": [{"resources": [
        {"type": "aws_security_group", "name": "w", "values": {"id": "sg-1", "ingress": []}},
        {"type": "aws_security_group_rule", "name": "r", "values": {"type": "ingress", "security_group_id": "sg-1", "cidr_blocks": ["0.0.0.0/0"]}},
        {"type": "aws_instance", "name": "box", "values": {"instance_type": "t3.micro", "vpc_security_group_ids": ["sg-1"]}},
    ]}]}}}
    assert tfimport.convert(doc)["hosts"][0]["exposed"] is True


def test_plan_without_ids_warns_instead_of_guessing():
    plan = {"planned_values": {"root_module": {"resources": [{"type": "aws_instance", "name": "box", "values": {"instance_type": "t3.micro"}}]}}}
    c = tfimport.convert(plan)
    assert c["edges"] == [] and any("unapplied plan" in w for w in c["warnings"])


def test_parse_merges_terraform_with_explicit_findings():
    spec, warnings = ingest.parse({"terraform": STATE, "findings": [{"host": "api", "cve": "CVE-2021-44228", "cvss": 10.0}]})
    assert {h.id for h in spec.hosts} == {"front", "api"} and [f.host for f in spec.findings] == ["api"] and warnings == []


def test_explicit_entries_win_over_terraform_for_the_same_id():
    spec, _ = ingest.parse({"terraform": STATE, "hosts": [{"id": "api", "software": "my override", "role": "x"}]})
    assert next(h for h in spec.hosts if h.id == "api").software == "my override"
