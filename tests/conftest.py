import pytest


@pytest.fixture
def min_risk_form():
    """Best possible security posture — maximum approval score.
    Score: 20 (data) + 40 (controls) + 10 (network) + 20 (patches) + 24 (impact) = 114 → Approve.
    """
    return {
        "data_stored_level": 1,
        "data_access_level": 1,
        "allow_vulnerability_scanning": True,
        "allow_edr_crowdstrike": True,
        "local_firewall": "high",
        "network_firewall": "high",
        "os_up_to_date": True,
        "has_public_ip": False,
        "management_network_access": False,
        "os_patch_frequency": "monthly",
        "app_patch_frequency": "monthly",
        "server_dependencies": "low",
        "user_dependencies": "low",
        "university_importance": "excessive",   # mission-critical → +10
    }


@pytest.fixture
def max_risk_form():
    """Worst possible security posture — minimum approval score.
    Score: 2 (data) + 0 (controls) + 0 (network) + -20 (patches) + 3 (impact) = -15 → Denied.
    """
    return {
        "data_stored_level": 3,
        "data_access_level": 3,
        "allow_vulnerability_scanning": False,
        "allow_edr_crowdstrike": False,
        "local_firewall": "no",
        "network_firewall": "no",
        "os_up_to_date": False,
        "has_public_ip": True,
        "management_network_access": True,
        "os_patch_frequency": "patches unavailable",
        "app_patch_frequency": "patches unavailable",
        "server_dependencies": "excessive",
        "user_dependencies": "excessive",
        "university_importance": "low",         # non-critical → +1
    }


@pytest.fixture
def review_band_form():
    """Form that sits in the 16-90 Requires Review band.
    Based on ground-truth ticket 997477: score = 30.
    """
    return {
        "data_stored_level": 1,
        "data_access_level": 1,
        "allow_vulnerability_scanning": False,
        "allow_edr_crowdstrike": False,
        "local_firewall": "no",
        "network_firewall": "no",
        "os_up_to_date": False,
        "has_public_ip": False,
        "management_network_access": False,
        "os_patch_frequency": "patches unavailable",
        "app_patch_frequency": "patches unavailable",
        "server_dependencies": "low",
        "user_dependencies": "low",
        "university_importance": "moderate",    # critical → +6
    }
