def calculate_risk_score(form_data):
    """
    Calculate risk score based on weighted factors
    Returns score 0-100 where higher = higher risk
    """
    
    risk_score = 0
    
    # Data Classification Risk (0-30 points)
    data_risk = {
        'stored_level': {
            1: 0,   # Level I - Public
            2: 10,  # Level II - Internal/Sensitive  
            3: 20   # Level III - Restricted/Regulated
        },
        'access_level': {
            1: 0,
            2: 5,
            3: 10
        }
    }
    
    risk_score += data_risk['stored_level'][form_data['data_stored_level']]
    risk_score += data_risk['access_level'][form_data['data_access_level']]
    
    # Security Controls Gap (0-35 points)
    if not form_data['allow_vulnerability_scanning']:
        risk_score += 8
    if not form_data['allow_edr_crowdstrike']:
        risk_score += 10
    if form_data['local_firewall'] in ['minimal', 'no']:
        risk_score += 7
    if form_data['network_firewall'] in ['minimal', 'no']:
        risk_score += 7
    if not form_data['os_up_to_date']:
        risk_score += 3
    
    # Network Exposure (0-15 points)
    if form_data['has_public_ip']:
        risk_score += 10
    if form_data['management_network_access']:
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
    risk_score += patch_risk.get(form_data['os_patch_frequency'], 5) * 0.5
    risk_score += patch_risk.get(form_data['app_patch_frequency'], 5) * 0.5
    
    # Impact Assessment (0-10 points)
    impact_map = {'low': 0, 'moderate': 2, 'excessive': 4}
    risk_score += impact_map[form_data['server_dependencies']]
    risk_score += impact_map[form_data['user_dependencies']]
    risk_score += impact_map[form_data['university_importance']] * 0.5
    
    return min(100, risk_score)  # Cap at 100