def make_exception_decision(risk_score, form_data):
    """
    Make decision based on risk score and exception type.
    Routes per TDX workflow diagram thresholds:
      - < 16: Approve
      - 16-90: Requires Review
      - > 90: Denied
    """
    
    decision = {
        'risk_score': risk_score,
        'approval_status': '',
        'recommendation': '',
        'approval_required': [],
        'routing': '',  # IAM, SecOps, or GRC
        'conditions': [],
        'max_duration': None,
        'reasoning': []
    }
    
    exception_type = form_data.get('exception_type', 'security')
    
    # Determine approval status per workflow thresholds
    if risk_score > 90:
        decision['approval_status'] = 'Denied'
        decision['recommendation'] = 'DENY'
        decision['reasoning'].append('Risk score exceeds 90 - automatic denial')
        return decision
        
    elif risk_score >= 16:
        decision['approval_status'] = 'Requires Review'
        decision['recommendation'] = 'REVIEW'
        
    else:
        decision['approval_status'] = 'Approve'
        decision['recommendation'] = 'APPROVE'
    
    # Route to appropriate approval chain based on exception type
    if exception_type in ['iam', 'identity', 'access']:
        decision['routing'] = 'IAM'
        decision['approval_required'] = ['Unit Head', 'IAM Team']
        decision['reasoning'].append('Identity exception routed to IAM Risk Assessment')
        
    elif exception_type in ['secops', 'security', 'vulnerability']:
        decision['routing'] = 'SecOps'
        decision['approval_required'] = ['Unit Head', 'SecOps Team']
        decision['reasoning'].append('Security exception routed to SecOps Risk Assessment')
        
    else:
        decision['routing'] = 'GRC'
        decision['approval_required'] = ['Unit Head', 'GRC Team']
        decision['reasoning'].append('Exception routed to GRC Risk Assessment')
    
    # Set duration based on approval status
    if decision['approval_status'] == 'Approve':
        decision['max_duration'] = 365
    elif decision['approval_status'] == 'Requires Review':
        decision['max_duration'] = 180
        
        # Add conditions for review cases
        if not form_data.get('allow_vulnerability_scanning', True):
            decision['conditions'].append('Must allow vulnerability scanning within 30 days')
        if form_data.get('os_patch_frequency') in ['yearly+', 'patches unavailable']:
            decision['conditions'].append('Must implement quarterly patching schedule')
    
    # Unit Head Acceptance of Risk is always required (per workflow)
    if 'Unit Head' not in decision['approval_required']:
        decision['approval_required'].insert(0, 'Unit Head')
    
    return decision