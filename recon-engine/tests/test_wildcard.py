import json
import pytest
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"

def load_fixtures_by_kind(*kinds):
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [f for f in data["fixtures"] if f["kind"] in kinds]

def is_wildcard_dns(random_responses, candidate_response):
    return all(r == candidate_response for r in random_responses)

def is_wildcard_vhost(baseline, candidate):
    return candidate == baseline

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("dns"))
def test_dns_wildcard(fixture):
    random_responses = fixture["random_responses"]
    candidate = fixture["candidate_response"]
    is_wildcard = is_wildcard_dns(random_responses, candidate)
    expected_is_wildcard = (fixture["expected"] == "suppress")
    assert is_wildcard == expected_is_wildcard

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("vhost"))
def test_vhost_wildcard(fixture):
    is_wildcard = is_wildcard_vhost(fixture["baseline"], fixture["candidate"])
    expected_is_wildcard = (fixture["expected"] == "suppress")
    assert is_wildcard == expected_is_wildcard
