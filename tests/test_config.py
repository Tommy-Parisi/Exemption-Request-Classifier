import pytest
from config import (
    DATA_LEVEL_MAP,
    DATA_LEVEL_ROMAN,
    PATCH_FREQ_MAP,
    FIREWALL_MAP,
    IMPACT_MAP,
    UNIVERSITY_MAP,
    RISK_LEVEL_MAP,
    ALLOWED_ORIGINS,
)


# ---------------------------------------------------------------------------
# DATA_LEVEL_MAP
# ---------------------------------------------------------------------------

def test_data_level_map_covers_all_levels():
    assert set(DATA_LEVEL_MAP.keys()) == {"Level I", "Level II", "Level III"}


def test_data_level_map_values_are_ordered():
    assert DATA_LEVEL_MAP["Level I"] < DATA_LEVEL_MAP["Level II"] < DATA_LEVEL_MAP["Level III"]


def test_data_level_map_values():
    assert DATA_LEVEL_MAP == {"Level I": 1, "Level II": 2, "Level III": 3}


# ---------------------------------------------------------------------------
# DATA_LEVEL_ROMAN
# ---------------------------------------------------------------------------

def test_data_level_roman_covers_all_numeric_levels():
    assert set(DATA_LEVEL_ROMAN.keys()) == {1, 2, 3}


def test_data_level_roman_values():
    assert DATA_LEVEL_ROMAN == {1: "I", 2: "II", 3: "III"}


def test_data_level_maps_are_inverses():
    """DATA_LEVEL_MAP and DATA_LEVEL_ROMAN must be consistent with each other."""
    for label, num in DATA_LEVEL_MAP.items():
        roman = label.split()[-1]  # "Level II" → "II"
        assert DATA_LEVEL_ROMAN[num] == roman


# ---------------------------------------------------------------------------
# PATCH_FREQ_MAP
# ---------------------------------------------------------------------------

EXPECTED_PATCH_FREQ_KEYS = {
    "Monthly",
    "Quarterly",
    "Every 3-6 months",
    "Every 6-12 months",
    "Yearly",
    "Unavailable",        # frontend form value
    "Patches Unavailable", # TDX API value
}

def test_patch_freq_map_covers_all_ui_options():
    assert set(PATCH_FREQ_MAP.keys()) == EXPECTED_PATCH_FREQ_KEYS


def test_patch_freq_map_values_match_scorer_keys():
    """Values must align with the patch_score_map keys inside risk_scorer."""
    valid_scorer_keys = {
        "monthly",
        "quarterly",
        "every 3-6 months",
        "every 6-12 months",
        "yearly+",
        "patches unavailable",
    }
    assert set(PATCH_FREQ_MAP.values()) == valid_scorer_keys


def test_patch_freq_map_specific_entries():
    assert PATCH_FREQ_MAP["Monthly"] == "monthly"
    assert PATCH_FREQ_MAP["Yearly"] == "yearly+"
    assert PATCH_FREQ_MAP["Unavailable"] == "patches unavailable"


# ---------------------------------------------------------------------------
# FIREWALL_MAP
# ---------------------------------------------------------------------------

EXPECTED_FIREWALL_KEYS = {"High Coverage", "Moderate Coverage", "Minimal Coverage", "No Coverage"}

def test_firewall_map_covers_all_ui_options():
    assert set(FIREWALL_MAP.keys()) == EXPECTED_FIREWALL_KEYS


def test_firewall_map_all_four_levels_are_distinct():
    """Each coverage level must map to a distinct scorer value — the spec has 4 tiers."""
    assert len(set(FIREWALL_MAP.values())) == 4


def test_firewall_map_specific_entries():
    assert FIREWALL_MAP["High Coverage"]     == "high"
    assert FIREWALL_MAP["Moderate Coverage"] == "moderate"
    assert FIREWALL_MAP["Minimal Coverage"]  == "minimal"
    assert FIREWALL_MAP["No Coverage"]       == "no"


def test_firewall_map_values_match_scorer_keys():
    """All values produced by FIREWALL_MAP must be handled by risk_scorer's firewall_score dict."""
    valid_scorer_keys = {"high", "moderate", "minimal", "no"}
    assert set(FIREWALL_MAP.values()) == valid_scorer_keys


# ---------------------------------------------------------------------------
# IMPACT_MAP
# ---------------------------------------------------------------------------

def test_impact_map_covers_all_ui_options():
    assert set(IMPACT_MAP.keys()) == {"Low", "Moderate", "Extensive", "Widespread"}


def test_impact_map_values_match_scorer_keys():
    valid_scorer_keys = {"low", "moderate", "excessive"}
    assert set(IMPACT_MAP.values()).issubset(valid_scorer_keys)


def test_impact_map_specific_entries():
    assert IMPACT_MAP["Low"]        == "low"
    assert IMPACT_MAP["Moderate"]   == "moderate"
    assert IMPACT_MAP["Extensive"]  == "excessive"
    assert IMPACT_MAP["Widespread"] == "excessive"


# ---------------------------------------------------------------------------
# UNIVERSITY_MAP
# ---------------------------------------------------------------------------

def test_university_map_covers_all_ui_options():
    assert set(UNIVERSITY_MAP.keys()) == {"Non-Critical", "Critical", "Mission Critical"}


def test_university_map_values_match_scorer_keys():
    valid_scorer_keys = {"low", "moderate", "excessive"}
    assert set(UNIVERSITY_MAP.values()).issubset(valid_scorer_keys)


def test_university_map_specific_entries():
    assert UNIVERSITY_MAP["Non-Critical"]    == "low"
    assert UNIVERSITY_MAP["Critical"]        == "moderate"
    assert UNIVERSITY_MAP["Mission Critical"] == "excessive"


def test_university_map_values_are_ordered():
    """Higher criticality maps to a higher scorer key (higher approval points in impact model)."""
    order = {"low": 0, "moderate": 1, "excessive": 2}
    assert (
        order[UNIVERSITY_MAP["Non-Critical"]]
        < order[UNIVERSITY_MAP["Critical"]]
        < order[UNIVERSITY_MAP["Mission Critical"]]
    )


# ---------------------------------------------------------------------------
# RISK_LEVEL_MAP — approval model: high approval score = low security risk
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected_label", [
    (100, "LOW"),        # great security posture
    (91,  "LOW"),
    (90,  "LOW-MEDIUM"), # NOT > 90
    (71,  "LOW-MEDIUM"),
    (70,  "MEDIUM"),     # NOT > 70, but > 40
    (41,  "MEDIUM"),
    (40,  "HIGH"),       # NOT > 40, but > 16
    (17,  "HIGH"),
    (16,  "CRITICAL"),   # NOT > 16, but > 0
    (15,  "CRITICAL"),
    (1,   "CRITICAL"),
    (0,   "CRITICAL"),   # fallback (not > 0)
    (-5,  "CRITICAL"),   # negative scores also → CRITICAL
])
def test_risk_level_map_thresholds(score, expected_label):
    """Simulate the _risk_level() lookup used by routes.py and tdx.py."""
    label = None
    for threshold, lbl in RISK_LEVEL_MAP:
        if score > threshold:
            label = lbl
            break
    if label is None:
        label = RISK_LEVEL_MAP[-1][1]
    assert label == expected_label


def test_risk_level_map_is_descending():
    thresholds = [t for t, _ in RISK_LEVEL_MAP]
    assert thresholds == sorted(thresholds, reverse=True)


def test_risk_level_map_covers_full_range():
    """Lowest threshold must be 0 so all positive scores resolve before the fallback."""
    lowest_threshold = RISK_LEVEL_MAP[-1][0]
    assert lowest_threshold == 0


def test_risk_level_map_contains_five_bands():
    assert len(RISK_LEVEL_MAP) == 5


def test_risk_level_map_fallback_is_critical():
    """Scores ≤ 0 fall through to the last entry, which must be CRITICAL."""
    assert RISK_LEVEL_MAP[-1][1] == "CRITICAL"


def test_risk_level_map_top_band_is_low():
    """Scores > 90 are the best security posture and must map to LOW risk."""
    assert RISK_LEVEL_MAP[0][1] == "LOW"


# ---------------------------------------------------------------------------
# ALLOWED_ORIGINS
# ---------------------------------------------------------------------------

def test_allowed_origins_is_list():
    assert isinstance(ALLOWED_ORIGINS, list)


def test_allowed_origins_non_empty():
    assert len(ALLOWED_ORIGINS) >= 1


def test_allowed_origins_no_blank_entries():
    assert all(o.strip() for o in ALLOWED_ORIGINS)


def test_allowed_origins_no_trailing_whitespace():
    assert all(o == o.strip() for o in ALLOWED_ORIGINS)
