import json
import pytest
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"
ALL_STEPS = ["dns", "probe", "ports", "fingerprint"]

def load_fixtures_by_kind(kind):
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [f for f in data["fixtures"] if f["kind"] == kind]

def next_step(completed):
    for step in ALL_STEPS:
        if step not in completed:
            return step
    return None

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("checkpoint"))
def test_resume(fixture):
    completed = fixture["completed"]
    assert next_step(completed) == fixture["expected_next"]
