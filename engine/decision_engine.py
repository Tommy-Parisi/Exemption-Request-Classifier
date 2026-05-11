def make_exception_decision(risk_score, form_data):
    """
    Make decision based on approval score and exception type.
    Routes per TDX workflow diagram thresholds:
      - > 90: Approve
      - 16-90: Requires Review
      - < 16: Denied
    """

    decision = {
        "risk_score":       risk_score,
        "approval_status":  "",
        "recommendation":   "",
        "approval_required": [],
        "routing":          "",
        "conditions":       [],
        "max_duration":     None,
        "reasoning":        [],
    }

    exception_type = form_data.get("exception_type", "security")

    # Auto-deny: security posture too poor to consider any exception
    if risk_score < 16:
        decision["approval_status"] = "Denied"
        decision["recommendation"]  = "DENY"
        decision["reasoning"].append("Approval score below 16 - automatic denial")
        return decision

    if risk_score > 90:
        decision["approval_status"] = "Approve"
        decision["recommendation"]  = "APPROVE"
    else:
        decision["approval_status"] = "Requires Review"
        decision["recommendation"]  = "REVIEW"

    if exception_type in ["iam", "identity", "access"]:
        decision["routing"] = "IAM"
        decision["approval_required"] = ["Unit Head", "IAM Team"]
        decision["reasoning"].append("Identity exception routed to IAM Risk Assessment")
    elif exception_type in ["secops", "security", "vulnerability"]:
        decision["routing"] = "SecOps"
        decision["approval_required"] = ["Unit Head", "SecOps Team"]
        decision["reasoning"].append("Security exception routed to SecOps Risk Assessment")
    else:
        decision["routing"] = "GRC"
        decision["approval_required"] = ["Unit Head", "GRC Team"]
        decision["reasoning"].append("Exception routed to GRC Risk Assessment")

    if decision["approval_status"] == "Approve":
        decision["max_duration"] = 365
    elif decision["approval_status"] == "Requires Review":
        decision["max_duration"] = 180

        if not form_data.get("allow_vulnerability_scanning", True):
            decision["conditions"].append("Must allow vulnerability scanning within 30 days")
        if form_data.get("os_patch_frequency") in ["yearly+", "patches unavailable"]:
            decision["conditions"].append("Must implement quarterly patching schedule")

    if "Unit Head" not in decision["approval_required"]:
        decision["approval_required"].insert(0, "Unit Head")

    return decision
