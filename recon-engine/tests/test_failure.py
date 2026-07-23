import json
import pytest
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"

def load_fixtures_by_kind(kind):
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [f for f in data["fixtures"] if f["kind"] == kind]

def tool_behavior(exit_code, fallback_available):
    if exit_code == 0:
        return "success"
    if fallback_available:
        return "fallback"
    return "nonzero_exit"

@pytest.mark.parametrize("fixture", load_fixtures_by_kind("tool_exit"))
def test_tool_failure(fixture):
    result = tool_behavior(fixture["exit_code"], fixture["fallback_available"])
    assert result == fixture["expected"]
