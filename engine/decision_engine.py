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
        'conditions': [],
        'max_duration': None,
    }

    # Determine approval status per workflow thresholds
    if risk_score > 90:
        decision['approval_status'] = 'Denied'
        decision['recommendation'] = 'DENY'
        return decision

    elif risk_score >= 16:
        decision['approval_status'] = 'Requires Review'
        decision['recommendation'] = 'REVIEW'
        decision['max_duration'] = 180

        if not form_data.get('allow_vulnerability_scanning', True):
            decision['conditions'].append('Must allow vulnerability scanning within 30 days')
        if form_data.get('os_patch_frequency') in ['yearly+', 'patches unavailable']:
            decision['conditions'].append('Must implement quarterly patching schedule')

    else:
        decision['approval_status'] = 'Approve'
        decision['recommendation'] = 'APPROVE'
        decision['max_duration'] = 365

    return decision