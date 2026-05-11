"""
Adversarial / edge-case tests.

These tests probe malformed, missing, or extreme inputs to document how the
functions should behave outside the normal happy path. They test desired
behaviour, not current behaviour — if a test fails, the code has a bug.
"""
import pytest
from engine.risk_scorer import calculate_risk_score, get_approval_decision
from engine.decision_engine import make_exception_decision


# ---------------------------------------------------------------------------
# calculate_risk_score — required fields missing or wrong type
# ---------------------------------------------------------------------------

def test_empty_form_raises_key_error():
    """data_stored_level is accessed directly (no .get()), so an empty dict crashes.
    The caller is responsible for validating inputs before calling this function."""
    with pytest.raises(KeyError, match="data_stored_level"):
        calculate_risk_score({})


def test_missing_data_stored_level_raises_key_error(min_risk_form):
    form = min_risk_form.copy()
    del form["data_stored_level"]
    with pytest.raises(KeyError):
        calculate_risk_score(form)


def test_missing_data_access_level_raises_key_error(min_risk_form):
    form = min_risk_form.copy()
    del form["data_access_level"]
    with pytest.raises(KeyError):
        calculate_risk_score(form)


def test_none_data_stored_level_defaults_to_min_approval(min_risk_form):
    """None is not a key in the lookup dict — defaults to 1 (fewest approval points).
    Callers must map UI values to ints before calling this function."""
    form = min_risk_form.copy()
    form["data_stored_level"] = None
    result = calculate_risk_score(form)
    # None → default 1; access Level I → 10
    assert result["breakdown"]["data_classification"] == 11


def test_none_data_access_level_defaults_to_min_approval(min_risk_form):
    form = min_risk_form.copy()
    form["data_access_level"] = None
    result = calculate_risk_score(form)
    # stored Level I → 10; None access → default 1
    assert result["breakdown"]["data_classification"] == 11


def test_string_data_level_defaults_to_min_approval(min_risk_form):
    """Passing the raw UI label 'Level II' (str) instead of the mapped int (2)
    falls through to the default of 1. The form mapping layer must run first."""
    form = min_risk_form.copy()
    form["data_stored_level"] = "Level II"
    result = calculate_risk_score(form)
    # "Level II" not in {1:10, 2:7, 3:1} → default 1; access Level I → 10
    assert result["breakdown"]["data_classification"] == 11


def test_zero_data_stored_level_defaults_to_min_approval(min_risk_form):
    """0 is not a valid level (valid: 1, 2, 3). Defaults to 1."""
    form = min_risk_form.copy()
    form["data_stored_level"] = 0
    result = calculate_risk_score(form)
    assert result["breakdown"]["data_classification"] == 11  # 1 + 10


def test_data_level_4_defaults_to_min_approval(min_risk_form):
    form = min_risk_form.copy()
    form["data_stored_level"] = 4
    result = calculate_risk_score(form)
    assert result["breakdown"]["data_classification"] == 11  # 1 + 10


# ---------------------------------------------------------------------------
# calculate_risk_score — boolean fields with wrong types
# ---------------------------------------------------------------------------

def test_truthy_string_for_vulnerability_scanning(min_risk_form):
    """A non-empty string is truthy in Python, so 'False' (the string) means
    allow_vulnerability_scanning is True — the +5 is still counted."""
    form = min_risk_form.copy()
    form["allow_vulnerability_scanning"] = "False"  # str, not bool
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 40   # all controls still active


def test_zero_int_for_vulnerability_scanning_loses_points(min_risk_form):
    """0 is falsy, so passing 0 instead of False removes the +5 for scanning."""
    form = min_risk_form.copy()
    form["allow_vulnerability_scanning"] = 0
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 35   # 40 - 5


# ---------------------------------------------------------------------------
# calculate_risk_score — score can be negative
# ---------------------------------------------------------------------------

def test_worst_case_score_is_negative(max_risk_form):
    """Patches unavailable (-20) can pull the total below zero."""
    result = calculate_risk_score(max_risk_form)
    assert result["total"] == -15


def test_negative_score_is_denied(max_risk_form):
    """A negative total is below the 16-point threshold and is Denied."""
    result = calculate_risk_score(max_risk_form)
    assert result["decision"] == "Denied"


# ---------------------------------------------------------------------------
# make_exception_decision — extreme and malformed scores
# ---------------------------------------------------------------------------

def test_negative_score_treated_as_denied():
    """Negative scores are below the 16-point floor and are Denied."""
    result = make_exception_decision(-5, {"exception_type": "security"})
    assert result["approval_status"] == "Denied"
    assert result["max_duration"] is None


def test_very_large_score_treated_as_approved():
    """Scores far above 90 are still Approved without error."""
    result = make_exception_decision(1000, {"exception_type": "security"})
    assert result["approval_status"] == "Approve"


# ---------------------------------------------------------------------------
# make_exception_decision — malformed form_data
# ---------------------------------------------------------------------------

def test_empty_form_data_does_not_crash():
    """decision_engine uses .get() with defaults throughout, so an empty dict is safe."""
    result = make_exception_decision(50, {})
    assert result["approval_status"] == "Requires Review"


def test_empty_form_data_routes_to_secops_via_default():
    """Missing exception_type defaults to 'security' → SecOps routing."""
    result = make_exception_decision(50, {})
    assert result["routing"] == "SecOps"


def test_none_exception_type_falls_through_to_grc():
    """None doesn't match any routing keyword list, so GRC is the fallback."""
    result = make_exception_decision(50, {"exception_type": None})
    assert result["routing"] == "GRC"


def test_exception_type_matching_is_case_sensitive():
    """'IAM' (uppercase) does NOT match the lowercase 'iam' keyword → falls to GRC."""
    result = make_exception_decision(50, {"exception_type": "IAM"})
    assert result["routing"] == "GRC"


def test_exception_type_matching_is_case_sensitive_security():
    """'Security' (title-case) does NOT match 'security' → falls to GRC."""
    result = make_exception_decision(50, {"exception_type": "Security"})
    assert result["routing"] == "GRC"


def test_none_patch_frequency_does_not_add_condition():
    """None os_patch_frequency is not in ['yearly+', 'patches unavailable'],
    so no patching condition is appended."""
    result = make_exception_decision(50, {
        "exception_type": "security",
        "allow_vulnerability_scanning": True,
        "os_patch_frequency": None,
    })
    assert not any("patching" in c for c in result["conditions"])


# ---------------------------------------------------------------------------
# get_approval_decision — boundary exhaustiveness
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score", [-1000, -10, -1, 0, 1, 15])
def test_scores_below_16_all_denied(score):
    assert get_approval_decision(score) == "Denied"


@pytest.mark.parametrize("score", [16, 17, 89, 90])
def test_scores_16_to_90_inclusive_require_review(score):
    assert get_approval_decision(score) == "Requires Review"


@pytest.mark.parametrize("score", [91, 92, 100, 1000])
def test_scores_above_90_all_approved(score):
    assert get_approval_decision(score) == "Approve"
