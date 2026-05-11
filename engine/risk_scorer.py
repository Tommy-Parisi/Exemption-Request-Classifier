def calculate_risk_score(form_data):
    """
    Calculate approval score per the TDX weight spec.

    Higher score = stronger security posture = more likely to approve the exception.
    Returns a dict with:
      - 'total': int approval score (can be negative for very poor security)
      - 'breakdown': per-category contributions
      - 'decision': 'Approve' | 'Requires Review' | 'Denied'

    Thresholds (from TDX workflow):
      - total > 90: Auto-Approve
      - total 16-90: Requires Review
      - total < 16: Auto-Deny
    """

    # spec IDs 5126 / 5130 — Level I (least sensitive) earns most approval points
    data_stored = {1: 10, 2: 7, 3: 1}
    data_access = {1: 10, 2: 7, 3: 1}
    data_classification = (
        data_stored.get(form_data["data_stored_level"], 1)
        + data_access.get(form_data["data_access_level"], 1)
    )

    # spec ID 5134: scanning allowed → +5
    # spec ID 5135: EDR allowed → +5
    # spec IDs 5146/5147: high→10, moderate→7, minimal→3, no coverage→0
    # spec ID 5140: OS up to date → +10
    security_controls = 0
    if form_data.get("allow_vulnerability_scanning", False):
        security_controls += 5
    if form_data.get("allow_edr_crowdstrike", False):
        security_controls += 5
    firewall_score = {"high": 10, "moderate": 7, "minimal": 3, "no": 0}
    security_controls += firewall_score.get(form_data.get("local_firewall"), 0)
    security_controls += firewall_score.get(form_data.get("network_firewall"), 0)
    if form_data.get("os_up_to_date", False):
        security_controls += 10

    # spec ID 5139: no public IP → +5 (absence of exposure earns points)
    # spec ID 5138: no management network access → +5
    network_posture = 0
    if not form_data.get("has_public_ip", True):
        network_posture += 5
    if not form_data.get("management_network_access", True):
        network_posture += 5

    # spec IDs 5141 / 5142 — patch scores summed directly (not averaged)
    # monthly patching earns a bonus; unavailable patches penalise the total
    patch_score_map = {
        "monthly":             10,
        "quarterly":            8,
        "every 3-6 months":     6,
        "every 6-12 months":    3,
        "yearly+":             -1,
        "patches unavailable": -10,
    }
    os_patch  = patch_score_map.get(form_data.get("os_patch_frequency"),  0)
    app_patch = patch_score_map.get(form_data.get("app_patch_frequency"), 0)
    patch_management = os_patch + app_patch

    # spec IDs 5143 / 5144: low=7, moderate=4, excessive=1
    # spec ID 5145: non-critical=1, critical=6, mission-critical=10
    impact_server_user = {"low": 7, "moderate": 4, "excessive": 1}
    impact_university  = {"low": 1, "moderate": 6, "excessive": 10}
    impact_assessment = (
        impact_server_user.get(form_data.get("server_dependencies"),   1)
        + impact_server_user.get(form_data.get("user_dependencies"),   1)
        + impact_university.get(form_data.get("university_importance"), 1)
    )

    breakdown = {
        "data_classification": data_classification,
        "security_controls":   security_controls,
        "network_posture":     network_posture,
        "patch_management":    patch_management,
        "impact_assessment":   impact_assessment,
    }

    total = sum(breakdown.values())

    return {
        "total":     total,
        "breakdown": breakdown,
        "decision":  get_approval_decision(total),
    }


def get_approval_decision(risk_score):
    """
    Map approval score to workflow decision per the TDX workflow diagram.
    High score = good security posture = approve the exception request.
    """
    if risk_score > 90:
        return "Approve"
    elif risk_score >= 16:
        return "Requires Review"
    else:
        return "Denied"
