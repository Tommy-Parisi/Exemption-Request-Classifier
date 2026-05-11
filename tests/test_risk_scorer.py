import pytest
from engine.risk_scorer import calculate_risk_score, get_approval_decision


# ---------------------------------------------------------------------------
# get_approval_decision — threshold boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0,   "Denied"),          # < 16 → Denied
    (15,  "Denied"),          # < 16 → Denied
    (16,  "Requires Review"), # >= 16 and not > 90
    (50,  "Requires Review"),
    (90,  "Requires Review"), # not > 90
    (91,  "Approve"),         # > 90
    (100, "Approve"),
])
def test_approval_decision_thresholds(score, expected):
    assert get_approval_decision(score) == expected


# ---------------------------------------------------------------------------
# Data classification — approval model: Level I=10, II=7, III=1
# Higher sensitivity earns fewer approval points
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stored,access,expected_dc", [
    (1, 1, 20),   # 10 + 10
    (2, 1, 17),   # 7  + 10
    (1, 2, 17),   # 10 + 7
    (2, 2, 14),   # 7  + 7
    (3, 1, 11),   # 1  + 10
    (3, 3,  2),   # 1  + 1
])
def test_data_classification_scoring(stored, access, expected_dc, min_risk_form):
    form = min_risk_form.copy()
    form["data_stored_level"] = stored
    form["data_access_level"] = access
    result = calculate_risk_score(form)
    assert result["breakdown"]["data_classification"] == expected_dc


def test_level_i_data_earns_max_approval_points(min_risk_form):
    """Level I (least sensitive) data earns the most approval points: 10+10=20."""
    result = calculate_risk_score(min_risk_form)
    assert result["breakdown"]["data_classification"] == 20


def test_data_classification_unknown_levels_default_to_min_approval(min_risk_form):
    """Unknown level codes default to 1 (worst-case assumption — fewest approval points)."""
    form = min_risk_form.copy()
    form["data_stored_level"] = 99
    form["data_access_level"] = 99
    result = calculate_risk_score(form)
    assert result["breakdown"]["data_classification"] == 2   # 1 + 1


# ---------------------------------------------------------------------------
# Security controls — approval points earned (0–40)
# ---------------------------------------------------------------------------

def test_security_controls_max_when_all_active(min_risk_form):
    """All controls present: 5+5+10+10+10 = 40."""
    result = calculate_risk_score(min_risk_form)
    assert result["breakdown"]["security_controls"] == 40


def test_no_vulnerability_scanning_loses_5(min_risk_form):
    """Disabling scanning removes +5: 40 → 35."""
    form = min_risk_form.copy()
    form["allow_vulnerability_scanning"] = False
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 35


def test_no_edr_loses_5(min_risk_form):
    """Disabling EDR removes +5: 40 → 35."""
    form = min_risk_form.copy()
    form["allow_edr_crowdstrike"] = False
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 35


def test_firewall_no_coverage_earns_zero(min_risk_form):
    """No Coverage firewall contributes 0 instead of 10: 40 → 30."""
    form = min_risk_form.copy()
    form["local_firewall"] = "no"
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 30


def test_firewall_minimal_coverage_earns_3(min_risk_form):
    """Minimal Coverage earns 3 instead of 10: 40 → 33."""
    form = min_risk_form.copy()
    form["local_firewall"] = "minimal"
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 33


def test_firewall_moderate_coverage_earns_7(min_risk_form):
    """Moderate Coverage earns 7 instead of 10: 40 → 37."""
    form = min_risk_form.copy()
    form["local_firewall"] = "moderate"
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 37


def test_firewall_high_coverage_earns_10(min_risk_form):
    """High Coverage earns the full 10 — no change from baseline."""
    form = min_risk_form.copy()
    form["local_firewall"] = "high"
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 40


def test_network_firewall_four_distinct_levels(min_risk_form):
    """Network firewall mirrors local: high=10, moderate=7, minimal=3, no=0."""
    expected_total = {"no": 30, "minimal": 33, "moderate": 37, "high": 40}
    for value, expected in expected_total.items():
        form = min_risk_form.copy()
        form["network_firewall"] = value
        result = calculate_risk_score(form)
        assert result["breakdown"]["security_controls"] == expected, f"network_firewall={value!r}"


def test_os_not_up_to_date_loses_10(min_risk_form):
    """OS not up to date removes +10: 40 → 30."""
    form = min_risk_form.copy()
    form["os_up_to_date"] = False
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 30


def test_all_security_controls_absent_earns_zero(min_risk_form):
    """No controls active: 0+0+0+0+0 = 0."""
    form = min_risk_form.copy()
    form["allow_vulnerability_scanning"] = False
    form["allow_edr_crowdstrike"] = False
    form["local_firewall"] = "no"
    form["network_firewall"] = "no"
    form["os_up_to_date"] = False
    result = calculate_risk_score(form)
    assert result["breakdown"]["security_controls"] == 0


# ---------------------------------------------------------------------------
# Network posture — approval points for absence of exposure (0–10)
# ---------------------------------------------------------------------------

def test_network_posture_max_when_no_exposure(min_risk_form):
    """No public IP and no management access: 5+5 = 10."""
    result = calculate_risk_score(min_risk_form)
    assert result["breakdown"]["network_posture"] == 10


def test_public_ip_loses_5(min_risk_form):
    """Having a public IP removes the +5 for no-public-IP."""
    form = min_risk_form.copy()
    form["has_public_ip"] = True
    result = calculate_risk_score(form)
    assert result["breakdown"]["network_posture"] == 5


def test_management_network_access_loses_5(min_risk_form):
    """Having management network access removes the +5 for no-mgmt-access."""
    form = min_risk_form.copy()
    form["management_network_access"] = True
    result = calculate_risk_score(form)
    assert result["breakdown"]["network_posture"] == 5


def test_both_network_exposures_earns_zero(min_risk_form):
    form = min_risk_form.copy()
    form["has_public_ip"] = True
    form["management_network_access"] = True
    result = calculate_risk_score(form)
    assert result["breakdown"]["network_posture"] == 0


# ---------------------------------------------------------------------------
# Patch management — scores summed directly (not averaged), can be negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("os_freq,app_freq,expected_pm", [
    ("patches unavailable", "patches unavailable", -20),  # -10 + -10
    ("yearly+",             "yearly+",              -2),  # -1  + -1
    ("every 6-12 months",   "every 6-12 months",    6),   # 3   + 3
    ("every 3-6 months",    "every 3-6 months",    12),   # 6   + 6
    ("quarterly",           "quarterly",           16),   # 8   + 8
    ("monthly",             "monthly",             20),   # 10  + 10
    ("patches unavailable", "monthly",              0),   # -10 + 10
    ("yearly+",             "quarterly",            7),   # -1  + 8
    ("every 3-6 months",    "monthly",             16),   # 6   + 10
])
def test_patch_management_scoring(os_freq, app_freq, expected_pm, min_risk_form):
    form = min_risk_form.copy()
    form["os_patch_frequency"] = os_freq
    form["app_patch_frequency"] = app_freq
    result = calculate_risk_score(form)
    assert result["breakdown"]["patch_management"] == expected_pm


def test_monthly_patching_earns_maximum_points(min_risk_form):
    """Monthly patching on both OS and apps earns the maximum: 10+10=20."""
    form = min_risk_form.copy()
    form["os_patch_frequency"] = "monthly"
    form["app_patch_frequency"] = "monthly"
    assert calculate_risk_score(form)["breakdown"]["patch_management"] == 20


def test_unavailable_patches_penalise_total(min_risk_form):
    """Patches unavailable produces the minimum: -10+-10=-20."""
    form = min_risk_form.copy()
    form["os_patch_frequency"] = "patches unavailable"
    form["app_patch_frequency"] = "patches unavailable"
    assert calculate_risk_score(form)["breakdown"]["patch_management"] == -20


def test_patch_management_unknown_frequency_defaults_to_zero(min_risk_form):
    form = min_risk_form.copy()
    form["os_patch_frequency"] = "unknown"
    form["app_patch_frequency"] = "unknown"
    result = calculate_risk_score(form)
    assert result["breakdown"]["patch_management"] == 0


def test_patch_management_missing_keys_defaults_to_zero(min_risk_form):
    form = min_risk_form.copy()
    del form["os_patch_frequency"]
    del form["app_patch_frequency"]
    result = calculate_risk_score(form)
    assert result["breakdown"]["patch_management"] == 0


# ---------------------------------------------------------------------------
# Impact assessment — server/user: low=7, mod=4, exc=1; university: low=1, mod=6, exc=10
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("server,user,university,expected_ia", [
    ("low",      "low",      "low",       15),  # 7+7+1
    ("moderate", "moderate", "moderate",  14),  # 4+4+6
    ("excessive","excessive","excessive", 12),  # 1+1+10
    ("excessive","low",      "low",        9),  # 1+7+1
    ("low",      "excessive","excessive", 18),  # 7+1+10
    ("moderate", "low",      "excessive", 21),  # 4+7+10
])
def test_impact_assessment_scoring(server, user, university, expected_ia, min_risk_form):
    form = min_risk_form.copy()
    form["server_dependencies"] = server
    form["user_dependencies"] = user
    form["university_importance"] = university
    result = calculate_risk_score(form)
    assert result["breakdown"]["impact_assessment"] == expected_ia


def test_university_importance_has_distinct_scale(min_risk_form):
    """University importance (1/6/10) uses a different scale than server/user (7/4/1)."""
    form_server = min_risk_form.copy()
    form_server.update({"server_dependencies": "excessive", "user_dependencies": "low",
                        "university_importance": "low"})
    form_university = min_risk_form.copy()
    form_university.update({"server_dependencies": "low", "user_dependencies": "low",
                            "university_importance": "excessive"})

    server_ia    = calculate_risk_score(form_server)["breakdown"]["impact_assessment"]
    uni_ia       = calculate_risk_score(form_university)["breakdown"]["impact_assessment"]

    assert server_ia == 9   # 1+7+1
    assert uni_ia    == 24  # 7+7+10


def test_impact_assessment_missing_keys_default_to_min(min_risk_form):
    """Missing dependency keys default to 1 each: 1+1+1=3."""
    form = min_risk_form.copy()
    del form["server_dependencies"]
    del form["user_dependencies"]
    del form["university_importance"]
    result = calculate_risk_score(form)
    assert result["breakdown"]["impact_assessment"] == 3


# ---------------------------------------------------------------------------
# End-to-end score bounds using fixtures
# ---------------------------------------------------------------------------

def test_min_risk_form_score_114_approves(min_risk_form):
    """Best-case security posture: 20+40+10+20+24=114 → Approve."""
    result = calculate_risk_score(min_risk_form)
    assert result["total"] == 114
    assert result["decision"] == "Approve"


def test_max_risk_form_score_minus15_denied(max_risk_form):
    """Worst-case security posture: 2+0+0-20+3=-15 → Denied."""
    result = calculate_risk_score(max_risk_form)
    assert result["total"] == -15
    assert result["decision"] == "Denied"


def test_ground_truth_review_band_score_30(review_band_form):
    """Ground truth from TDX ticket 997477: score must equal exactly 30 → Requires Review."""
    result = calculate_risk_score(review_band_form)
    assert result["total"] == 30
    assert result["decision"] == "Requires Review"


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

def test_result_contains_required_keys(min_risk_form):
    result = calculate_risk_score(min_risk_form)
    assert set(result.keys()) == {"total", "breakdown", "decision"}


def test_breakdown_contains_all_categories(min_risk_form):
    result = calculate_risk_score(min_risk_form)
    assert set(result["breakdown"].keys()) == {
        "data_classification",
        "security_controls",
        "network_posture",
        "patch_management",
        "impact_assessment",
    }


def test_total_equals_sum_of_breakdown(min_risk_form):
    result = calculate_risk_score(min_risk_form)
    assert result["total"] == sum(result["breakdown"].values())


def test_total_equals_sum_of_breakdown_at_min(max_risk_form):
    result = calculate_risk_score(max_risk_form)
    assert result["total"] == sum(result["breakdown"].values())


def test_decision_consistent_with_total(min_risk_form):
    result = calculate_risk_score(min_risk_form)
    assert result["decision"] == get_approval_decision(result["total"])
