from __future__ import annotations
from .normalize import normalize_alert, validate_alert
from .anomaly import score_alerts
from .correlator import correlate, build_incident
from .ranker import rank_incidents
from .ai_guardrails import deterministic_brief, build_evidence_packet, verify_claims

def run_pipeline(alerts):
    normalized=[normalize_alert(a) for a in alerts]
    normalized=score_alerts(normalized)
    errors=[(a.alert_id,validate_alert(a)) for a in normalized if validate_alert(a)]
    groups,g=correlate(normalized)
    incidents=[build_incident(group,i,g) for i,group in enumerate(groups,1)]
    ranked=rank_incidents(incidents,normalized)
    for inc in ranked:
        inc.summary=deterministic_brief(inc,normalized)
        # Every sentence-like factual statement in the deterministic brief is tied to evidence by construction.
        inc.claims=[{"claim":e.statement,"evidence_ids":[e.evidence_id],"confidence":e.confidence} for e in inc.evidence]
        inc.claims,ground=verify_claims(inc.claims,inc)
    return {"alerts":normalized,"incidents":ranked,"graph":g,"validation_errors":errors}
