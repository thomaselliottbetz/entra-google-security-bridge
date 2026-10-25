import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from identity_governance_ms import build_user_filter


def test_simple_and_multiple_values():
    assert build_user_filter("officeLocation", "Seattle") == "officeLocation eq 'Seattle'"
    assert build_user_filter("department", ["A", "B"]) == "department eq 'A' or department eq 'B'"


def test_quotes_are_doubled_so_value_cannot_break_out():
    out = build_user_filter("displayName", "x' or userType eq 'Guest")
    assert out == "displayName eq 'x'' or userType eq ''Guest'"


def test_url_metacharacters_pass_through_untouched():
    assert build_user_filter("department", "R&D #1") == "department eq 'R&D #1'"


@pytest.mark.parametrize("attribute", ["userType", "officelocation", "id eq 1 or department", "", None])
def test_unknown_attribute_rejected(attribute):
    with pytest.raises(ValueError, match="Unsupported filter attribute"):
        build_user_filter(attribute, "x")


@pytest.mark.parametrize("value", ["", [], None, 5, ["ok", ""], ["ok", 3], "a\nb", "a\x00b"])
def test_bad_values_rejected(value):
    with pytest.raises(ValueError):
        build_user_filter("department", value)
