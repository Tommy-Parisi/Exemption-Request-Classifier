import pytest
from engine.decision_engine import make_exception_decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_form(**overrides):
    """Minimal form with controls that trigger no extra conditions."""
    form = {
        "exception_type": "security",
        "allow_vulnerability_scanning": True,
        "os_patch_frequency": "monthly",
    }
    form.update(overrides)
    return form


# ---------------------------------------------------------------------------
# Approval status and recommendation thresholds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected_status,expected_rec", [
    (91,  "Approve",          "APPROVE"),
    (100, "Approve",          "APPROVE"),
    (90,  "Requires Review",  "REVIEW"),
    (50,  "Requires Review",  "REVIEW"),
    (16,  "Requires Review",  "REVIEW"),
    (15,  "Denied",           "DENY"),
    (0,   "Denied",           "DENY"),
])
def test_approval_status_thresholds(score, expected_status, expected_rec):
    result = make_exception_decision(score, _base_form())
    assert result["approval_status"] == expected_status
    assert result["recommendation"] == expected_rec


# ---------------------------------------------------------------------------
# Routing logic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exception_type,expected_routing", [
    ("iam",           "IAM"),
    ("identity",      "IAM"),
    ("access",        "IAM"),
    ("secops",        "SecOps"),
    ("security",      "SecOps"),
    ("vulnerability", "SecOps"),
    ("other",         "GRC"),
    ("compliance",    "GRC"),
    ("network",       "GRC"),
])
def test_routing_by_exception_type(exception_type, expected_routing):
    result = make_exception_decision(50, _base_form(exception_type=exception_type))
    assert result["routing"] == expected_routing


def test_missing_exception_type_defaults_to_secops():
    """Default exception_type is 'security' → SecOps routing."""
    form = {"allow_vulnerability_scanning": True, "os_patch_frequency": "monthly"}
    result = make_exception_decision(50, form)
    assert result["routing"] == "SecOps"


# ---------------------------------------------------------------------------
# Approval required list
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exception_type,expected_approvers", [
    ("iam",      ["Unit Head", "IAM Team"]),
    ("security", ["Unit Head", "SecOps Team"]),
    ("other",    ["Unit Head", "GRC Team"]),
])
def test_approval_required_list(exception_type, expected_approvers):
    result = make_exception_decision(50, _base_form(exception_type=exception_type))
    assert result["approval_required"] == expected_approvers


def test_unit_head_always_first_in_approval_list():
    for et in ["iam", "identity", "secops", "security", "vulnerability", "other"]:
        result = make_exception_decision(50, _base_form(exception_type=et))
        assert result["approval_required"][0] == "Unit Head"


# ---------------------------------------------------------------------------
# max_duration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected_duration", [
    (91,  365),
    (100, 365),
    (16,  180),
    (90,  180),
    (15,  None),
    (0,   None),
])
def test_max_duration_by_score(score, expected_duration):
    result = make_exception_decision(score, _base_form())
    assert result["max_duration"] == expected_duration


# ---------------------------------------------------------------------------
# Conditions (only applied in Requires Review band)
# ---------------------------------------------------------------------------

def test_no_conditions_when_approved():
    result = make_exception_decision(95, _base_form(allow_vulnerability_scanning=False))
    assert result["conditions"] == []


def test_no_conditions_when_denied():
    result = make_exception_decision(10, _base_form(allow_vulnerability_scanning=False))
    assert result["conditions"] == []


def test_no_vuln_scan_adds_condition_in_review_band():
    result = make_exception_decision(50, _base_form(allow_vulnerability_scanning=False))
    assert "Must allow vulnerability scanning within 30 days" in result["conditions"]


def test_vuln_scan_allowed_no_condition(min_risk_form):
    form = _base_form(allow_vulnerability_scanning=True)
    result = make_exception_decision(50, form)
    assert not any("vulnerability scanning" in c for c in result["conditions"])


@pytest.mark.parametrize("patch_freq", ["yearly+", "patches unavailable"])
def test_bad_patch_frequency_adds_condition_in_review_band(patch_freq):
    result = make_exception_decision(50, _base_form(os_patch_frequency=patch_freq))
    assert "Must implement quarterly patching schedule" in result["conditions"]


@pytest.mark.parametrize("patch_freq", ["monthly", "quarterly", "every 3-6 months", "every 6-12 months"])
def test_acceptable_patch_frequency_no_condition(patch_freq):
    result = make_exception_decision(50, _base_form(os_patch_frequency=patch_freq))
    assert not any("patching" in c for c in result["conditions"])


def test_multiple_conditions_accumulate():
    form = _base_form(
        allow_vulnerability_scanning=False,
        os_patch_frequency="patches unavailable",
    )
    result = make_exception_decision(50, form)
    assert len(result["conditions"]) == 2


def test_no_conditions_when_all_good():
    result = make_exception_decision(50, _base_form())
    assert result["conditions"] == []


# ---------------------------------------------------------------------------
# Early return on denial — routing and conditions must be empty
# ---------------------------------------------------------------------------

def test_denied_has_no_routing():
    result = make_exception_decision(10, _base_form())
    assert result["routing"] == ""


def test_denied_has_no_conditions():
    result = make_exception_decision(10, _base_form())
    assert result["conditions"] == []


def test_denied_has_no_approval_required():
    result = make_exception_decision(10, _base_form())
    assert result["approval_required"] == []


def test_denied_has_no_max_duration():
    result = make_exception_decision(10, _base_form())
    assert result["max_duration"] is None


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

def test_result_contains_required_keys():
    result = make_exception_decision(50, _base_form())
    expected = {
        "risk_score", "approval_status", "recommendation",
        "approval_required", "routing", "conditions", "max_duration", "reasoning",
    }
    assert set(result.keys()) == expected


def test_risk_score_is_passed_through():
    result = make_exception_decision(42, _base_form())
    assert result["risk_score"] == 42


def test_reasoning_is_non_empty_list():
    for score in [10, 50, 95]:
        result = make_exception_decision(score, _base_form())
        assert isinstance(result["reasoning"], list)
        assert len(result["reasoning"]) >= 1
