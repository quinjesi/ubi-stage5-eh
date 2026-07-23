import json
import pytest
from pathlib import Path
from engine.parsers import parse

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "parser-fixtures.json"

PARSER_KINDS = {"nmap_xml", "naabu_json", "httpx_json", "line"}
MAPPED_KINDS = {"malformed_json": "naabu_json", "missing_port": "naabu_json"}

def load_parser_fixtures():
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    return [
        f for f in data["fixtures"]
        if f["kind"] in PARSER_KINDS or f["kind"] in MAPPED_KINDS
    ]

@pytest.mark.parametrize("fixture", load_parser_fixtures(), ids=lambda f: f["id"])
def test_parser_fixtures(fixture):
    kind = fixture["kind"]
    actual_kind = MAPPED_KINDS.get(kind, kind)
    raw_input = fixture["input"]
    expected = fixture.get("expected")
    expected_error = fixture.get("expected_error")

    if expected_error:
        with pytest.raises(ValueError) as excinfo:
            parse(actual_kind, raw_input)
        assert expected_error in str(excinfo.value)
    else:
        result = parse(actual_kind, raw_input)
        if isinstance(expected, dict):
            assert len(result) == 1
            for key, val in expected.items():
                assert result[0][key] == val
        else:
            assert result == expected
