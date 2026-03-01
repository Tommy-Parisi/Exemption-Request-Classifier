def calculate_risk_score(form_data):
    """
    Calculate risk score based on weighted factors.

    Returns a dict with:
      - 'total':     int 0-100 composite risk score
      - 'breakdown': per-category point contributions
      - 'decision':  'Approve' | 'Requires Review' | 'Denied'

    Thresholds:
      - total < 16:  Auto-Approve
      - total 16-90: Requires Review
      - total > 90:  Auto-Deny
    """

    # Data Classification (0-30 points)
    data_stored = {1: 0, 2: 10, 3: 20}
    data_access = {1: 0, 2: 5, 3: 10}
    data_classification = (
        data_stored.get(form_data['data_stored_level'], 10)
        + data_access.get(form_data['data_access_level'], 5)
    )

    # Security Controls Gap (0-35 points)
    security_controls_gap = 0
    if not form_data.get('allow_vulnerability_scanning', True):
        security_controls_gap += 8
    if not form_data.get('allow_edr_crowdstrike', True):
        security_controls_gap += 10
    if form_data.get('local_firewall') in ['minimal', 'no']:
        security_controls_gap += 7
    if form_data.get('network_firewall') in ['minimal', 'no']:
        security_controls_gap += 7
    if not form_data.get('os_up_to_date', True):
        security_controls_gap += 3

    # Network Exposure (0-15 points)
    network_exposure = 0
    if form_data.get('has_public_ip', False):
        network_exposure += 10
    if form_data.get('management_network_access', False):
        network_exposure += 5

    # Patch Management (0-10 points)
    patch_risk = {
        'monthly': 0,
        'quarterly': 2,
        'every 3-6 months': 4,
        'every 6-12 months': 6,
        'yearly+': 8,
        'patches unavailable': 10
    }
    os_patch = patch_risk.get(form_data.get('os_patch_frequency'), 5)
    app_patch = patch_risk.get(form_data.get('app_patch_frequency'), 5)
    patch_management = round((os_patch + app_patch) / 2)

    # Impact Assessment (0-10 points)
    # server_dependencies and user_dependencies are each full-weight (max 4 pts each).
    # university_importance is intentionally half-weight (max 2 pts) because it reflects
    # broad institutional concern rather than a direct operational dependency on this
    # specific system — overstating it would unfairly inflate scores for widely-used
    # but otherwise low-risk assets.
    impact = {'low': 0, 'moderate': 2, 'excessive': 4}
    impact_assessment = round(
        impact.get(form_data.get('server_dependencies'), 2)
        + impact.get(form_data.get('user_dependencies'), 2)
        + impact.get(form_data.get('university_importance'), 2) / 2
    )

    breakdown = {
        'data_classification':   data_classification,
        'security_controls_gap': security_controls_gap,
        'network_exposure':      network_exposure,
        'patch_management':      patch_management,
        'impact_assessment':     impact_assessment,
    }

    total = min(100, sum(breakdown.values()))

    return {
        'total':     total,
        'breakdown': breakdown,
        'decision':  get_approval_decision(total),
    }


def get_approval_decision(risk_score):
    """
    Map risk score to workflow decision per the TDX workflow diagram.
    """
    if risk_score > 90:
        return "Denied"
    elif risk_score >= 16:
        return "Requires Review"
    else:
        return "Approve"