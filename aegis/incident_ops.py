from __future__ import annotations
from copy import deepcopy
from .models import Incident

def merge_incidents(a:Incident,b:Incident,new_id:str)->Incident:
    merged=deepcopy(a); merged.incident_id=new_id
    merged.alert_ids=list(dict.fromkeys(a.alert_ids+b.alert_ids))
    merged.evidence=a.evidence+b.evidence
    merged.mitre={x['technique_id']:x for x in a.mitre+b.mitre}.values(); merged.mitre=list(merged.mitre)
    merged.correlation_reasons=list(dict.fromkeys(a.correlation_reasons+b.correlation_reasons))
    merged.risk_score=round(max(a.risk_score,b.risk_score)+min(10,len(set(a.alert_ids)&set(b.alert_ids))*2),2)
    merged.risk_score=min(100,merged.risk_score)
    merged.title="Merged analyst investigation"
    merged.analyst_verdict="ANALYST_MERGED"
    return merged

def split_incident(incident:Incident, groups:list[list[str]], ids:list[str])->list[Incident]:
    by_alert={e.alert_id:e for e in incident.evidence}
    out=[]
    for idx,group in enumerate(groups):
        if not group: continue
        x=deepcopy(incident); x.incident_id=ids[idx] if idx<len(ids) else f"{incident.incident_id}-S{idx+1}"; x.alert_ids=group
        x.evidence=[by_alert[a] for a in group if a in by_alert]
        x.title=f"Split from {incident.incident_id}"; x.analyst_verdict="ANALYST_SPLIT"
        out.append(x)
    return out

def counterfactual_risk(incident:Incident, component:str)->dict:
    if component not in incident.risk_components: return {"component":component,"supported":False}
    original=incident.risk_score
    reduced=max(0.0, sum(v for k,v in incident.risk_components.items() if k!=component))
    new=100/(1+__import__('math').exp(-(reduced-62)/12))
    return {"component":component,"original":round(original,2),"without_component":round(new,2),"delta":round(new-original,2)}
