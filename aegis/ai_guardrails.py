from __future__ import annotations
import re
from .models import Incident, Alert

INJECTION_PATTERNS=[
    r"ignore (all|any|the|previous|prior) instructions",
    r"system message",
    r"developer message",
    r"reveal (the )?prompt",
    r"you are now",
    r"disregard",
]

def sanitize_untrusted(value:str)->str:
    s=value or ""
    for p in INJECTION_PATTERNS:
        s=re.sub(p,"[UNTRUSTED-INSTRUCTION-REMOVED]",s,flags=re.I)
    return s[:4000]

def build_evidence_packet(inc:Incident, alerts:list[Alert])->dict:
    amap={a.alert_id:a for a in alerts}
    return {
        "incident_id":inc.incident_id,
        "title":inc.title,
        "risk_score":inc.risk_score,
        "assets":sorted({amap[x].asset_id for x in inc.alert_ids}),
        "evidence":[{"id":e.evidence_id,"alert_id":e.alert_id,"statement":sanitize_untrusted(e.statement),"confidence":e.confidence} for e in inc.evidence],
        "mitre":inc.mitre,
        "correlation_reasons":inc.correlation_reasons,
    }

def verify_claims(claims:list[dict], inc:Incident)->tuple[list[dict],float]:
    valid_ids={e.evidence_id for e in inc.evidence}; checked=[]
    for c in claims:
        ids=c.get("evidence_ids",[])
        ok=bool(ids) and all(x in valid_ids for x in ids)
        checked.append({**c,"status":"verified" if ok else "rejected"})
    score=sum(x["status"]=="verified" for x in checked)/len(checked) if checked else 1.0
    return checked,score

def deterministic_brief(inc:Incident, alerts:list[Alert])->str:
    amap={a.alert_id:a for a in alerts}
    ordered=sorted((amap[x] for x in inc.alert_ids),key=lambda a:a.timestamp)
    lines=[f"{inc.title} (risk {inc.risk_score}/100).",f"Affected assets: {', '.join(sorted({a.asset_id for a in ordered}))}.",f"Observed alerts: {len(ordered)} across {len({a.source for a in ordered})} sources."]
    if inc.mitre: lines.append("Observed ATT&CK mappings: "+", ".join(f"{x['technique_id']} {x['name']}" for x in inc.mitre)+".")
    if inc.behavioral_anomalies: lines.append("Context: "+"; ".join(inc.behavioral_anomalies)+".")
    lines.append("Next checks: validate the affected identity/host, confirm whether the activity was authorized, and review the cited evidence before containment.")
    return " ".join(lines)
