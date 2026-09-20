from sqlalchemy.orm import Session

from app.ai import tools
from app.models.user import User
from app.schemas.ai import EvidenceItem, InvestigationResponse


def parse_intent(question: str) -> str:
    """Deterministic, keyword-based intent parsing for Phase 5A."""
    q_lower = question.lower()

    if any(k in q_lower for k in ["denied", "deny", "why was access", "permission", "blocked"]):
        return "ACCESS_DENIAL_ANALYSIS"

    if any(k in q_lower for k in ["incident", "alert", "case", "investigate incident"]):
        return "INCIDENT_INVESTIGATION"

    if any(k in q_lower for k in ["activity", "security event", "events", "logs", "audit"]):
        return "SECURITY_ACTIVITY"

    return "UNKNOWN"


def run_investigation(
    db: Session,
    user: User,
    question: str,
    resource_id: str | None = None,
    incident_id: str | None = None,
) -> InvestigationResponse:
    """Read-only deterministic investigator workflow assembling authorized evidence."""
    intent = parse_intent(question)
    evidence: list[EvidenceItem] = []

    if intent == "ACCESS_DENIAL_ANALYSIS":
        audit_events = (
            tools.get_resource_security_activity(db, user, resource_id, limit=5)
            if resource_id
            else tools.get_recent_audit_events(db, user, limit=5)
        )

        denials = [a for a in audit_events if a.outcome == "DENY"]
        for d in denials:
            evidence.append(
                EvidenceItem(
                    source_type="audit_event",
                    source_id=d.id,
                    action=d.action,
                    outcome=d.outcome,
                    reason=d.reason,
                    timestamp=d.timestamp,
                    description=f"Access denied for action {d.action}. Reason: {d.reason}",
                    details=d.context_data or {},
                )
            )

        if evidence:
            summary = f"Found {len(evidence)} recent access denial record(s) within authorized scope."
            risk_level = "MEDIUM" if len(evidence) > 2 else "LOW"
            confidence = "HIGH"
        else:
            summary = "No access denial records found within authorized scope."
            risk_level = "LOW"
            confidence = "HIGH"

    elif intent == "INCIDENT_INVESTIGATION":
        if incident_id:
            incident = tools.get_incident(db, user, incident_id)
            incidents = [incident] if incident else []
        else:
            incidents = tools.get_recent_incidents(db, user, limit=5)

        for inc in incidents:
            evidence.append(
                EvidenceItem(
                    source_type="incident",
                    source_id=inc.id,
                    severity=inc.severity,
                    timestamp=inc.created_at,
                    description=f"Incident '{inc.title}' status is {inc.status}.",
                    details={
                        "title": inc.title,
                        "status": inc.status,
                        "severity": inc.severity,
                        "resource_id": inc.resource_id,
                    },
                )
            )

        if evidence:
            summary = f"Retrieved {len(evidence)} incident record(s) matching request scope."
            severities = [item.severity for item in evidence if item.severity]
            risk_level = (
                "CRITICAL"
                if "CRITICAL" in severities
                else ("HIGH" if "HIGH" in severities else "MEDIUM")
            )
            confidence = "HIGH"
        else:
            summary = "No authorized incidents found matching the request criteria."
            risk_level = "LOW"
            confidence = "HIGH"

    elif intent == "SECURITY_ACTIVITY":
        sec_events = tools.get_recent_security_events(db, user, limit=5)
        for s in sec_events:
            evidence.append(
                EvidenceItem(
                    source_type="security_event",
                    source_id=s.id,
                    event_type=s.event_type,
                    severity=s.severity,
                    timestamp=s.timestamp,
                    description=s.description,
                    details={"actor_id": s.actor_id, "resource_id": s.resource_id},
                )
            )

        if evidence:
            summary = f"Found {len(evidence)} recent security event(s)."
            severities = [item.severity for item in evidence if item.severity]
            risk_level = (
                "CRITICAL"
                if "CRITICAL" in severities
                else ("HIGH" if "HIGH" in severities else "LOW")
            )
            confidence = "HIGH"
        else:
            summary = "No security events found within authorized scope."
            risk_level = "LOW"
            confidence = "HIGH"

    else:
        summary = "Unable to determine investigation intent from the question provided."
        risk_level = "LOW"
        confidence = "LOW"

    return InvestigationResponse(
        intent=intent,
        question=question,
        summary=summary,
        risk_level=risk_level,
        confidence=confidence,
        evidence=evidence,
    )