"""Pure, versioned, observational policy. Scores are ordinal review priorities."""
POLICY_VERSION = "gnosis-observe-v1"
# Configurable demonstration constants. Changing these requires a policy version bump.
WINDOW_MINUTES = 15
SENSITIVE_THRESHOLD = 3
BULK_THRESHOLD = 10
FREQUENCY_THRESHOLD = 10
DEPARTMENT_THRESHOLD = 3
DENIAL_THRESHOLD = 3
WEIGHTS = {
    "sensitivity": 10, "distinct_records": 10, "repeated_sensitive": 15,
    "bulk": 20, "frequency": 15, "department_hopping": 10,
    "denials": 15, "security_severity": 15,
}


def score_risk(metrics):
    """Missing evidence contributes zero; never interpret zero as proof of safety."""
    predicates = {
        "sensitivity": metrics.get("sensitive", 0) > 0,
        "distinct_records": metrics.get("distinct_records", 0) >= 5,
        "repeated_sensitive": metrics.get("sensitive_responses", 0) >= SENSITIVE_THRESHOLD,
        "bulk": metrics.get("distinct_records", 0) >= BULK_THRESHOLD,
        "frequency": metrics.get("business_attempts", 0) >= FREQUENCY_THRESHOLD,
        "department_hopping": metrics.get("departments", 0) >= DEPARTMENT_THRESHOLD,
        "denials": metrics.get("denials", 0) >= DENIAL_THRESHOLD,
        "security_severity": metrics.get("max_severity", "LOW") in {"HIGH", "CRITICAL"},
    }
    explanations = {
        "sensitivity": "Sensitive application disclosure observed (transport remains unknown).",
        "distinct_records": "At least five distinct business records disclosed.",
        "repeated_sensitive": "Sensitive records disclosed in at least three separate responses.",
        "bulk": "At least ten distinct records disclosed in the assessment window.",
        "frequency": "At least ten business-data request attempts; attempts are not disclosures.",
        "department_hopping": "Activity spans at least three target departments; legitimate grants may explain it.",
        "denials": "At least three denied resource attempts; zero exposure inferred from denials.",
        "security_severity": "Existing HIGH/CRITICAL detection evidence warrants review, not automatic enforcement.",
    }
    factors = [{"factor": key, "weight": WEIGHTS[key], "contribution": WEIGHTS[key] if active else 0,
                "explanation": explanations[key], "active": active} for key, active in predicates.items()]
    score = min(100, sum(item["contribution"] for item in factors))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return {"score": score, "level": level, "policy_version": POLICY_VERSION, "factors": factors}
