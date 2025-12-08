def calculate_risk_score(form_data):
    """
    Calculate risk score based on weighted factors.
    Returns score 0-100 where:
      - < 16: Auto-Approve
      - 16-90: Requires Review  
      - > 90: Auto-Deny
    """
    
    risk_score = 0
    
    # Data Classification (0-30 points)
    data_stored = {1: 0, 2: 10, 3: 20}
    data_access = {1: 0, 2: 5, 3: 10}
    risk_score += data_stored.get(form_data['data_stored_level'], 10)
    risk_score += data_access.get(form_data['data_access_level'], 5)
    
    # Security Controls Gap (0-35 points)
    if not form_data.get('allow_vulnerability_scanning', True):
        risk_score += 8
    if not form_data.get('allow_edr_crowdstrike', True):
        risk_score += 10
    if form_data.get('local_firewall') in ['minimal', 'no']:
        risk_score += 7
    if form_data.get('network_firewall') in ['minimal', 'no']:
        risk_score += 7
    if not form_data.get('os_up_to_date', True):
        risk_score += 3
    
    # Network Exposure (0-15 points)
    if form_data.get('has_public_ip', False):
        risk_score += 10
    if form_data.get('management_network_access', False):
        risk_score += 5
    
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
    risk_score += (os_patch + app_patch) / 2
    
    # Impact Assessment (0-10 points)
    impact = {'low': 0, 'moderate': 2, 'excessive': 4}
    risk_score += impact.get(form_data.get('server_dependencies'), 2)
    risk_score += impact.get(form_data.get('user_dependencies'), 2)
    risk_score += impact.get(form_data.get('university_importance'), 2) / 2
    
    return min(100, round(risk_score))


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