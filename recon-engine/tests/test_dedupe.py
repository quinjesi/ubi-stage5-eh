import json
import pytest
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"

def load_fixtures_by_kind(kind):
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [f for f in data["fixtures"] if f["kind"] == kind]

def dedupe_count(ids):
    return len(set(ids))

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("records"))
def test_dedupe(fixture):
    input_ids = fixture["input_ids"]
    assert dedupe_count(input_ids) == fixture["expected_count"]
