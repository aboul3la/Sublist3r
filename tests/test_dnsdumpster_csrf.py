import pytest
from pathlib import Path
import sublist3r

FIXTURE = Path(__file__).parent / "fixtures" / "dnsdumpster_no_token.html"

def test_get_csrftoken_returns_none_for_missing_token():
    html = FIXTURE.read_text(encoding="utf-8")
    token = sublist3r.get_csrftoken(html)
    assert token is None
