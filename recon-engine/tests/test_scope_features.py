import json
import pytest
from pathlib import Path
from ipaddress import ip_address, ip_network

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"

def load_fixtures_by_kind(*kinds):
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [f for f in data["fixtures"] if f["kind"] in kinds]

def evaluate_scope(scope_rules, candidate):
    for rule in scope_rules:
        if rule.startswith("tcp/") and "-" in rule:
            if not candidate.startswith("tcp/"):
                continue
            try:
                cand_port = int(candidate.split("/")[1])
            except (IndexError, ValueError):
                continue
            port_part = rule.split("/")[1]
            if "-" in port_part:
                low_str, high_str = port_part.split("-")
                try:
                    low = int(low_str)
                    high = int(high_str)
                except ValueError:
                    continue
                if low <= cand_port <= high:
                    return "allow"
            continue

        #CIDR check
        if "/" in rule:
            try:
                network = ip_network(rule, strict=False)
                if ip_address(candidate) in network:
                    return "allow"
            except ValueError:
                continue
            continue

        #Hostname
        if candidate == rule:
            return "allow"

    return "deny"

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("cidr", "hostname", "port"))
def test_scope_features(fixture):
    result = evaluate_scope(fixture["scope"], fixture["candidate"])
    assert result == fixture["expected"]
