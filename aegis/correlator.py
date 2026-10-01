from __future__ import annotations
from collections import defaultdict
import math
import networkx as nx
from .models import Alert, Evidence, Incident
from .mitre import infer_mitre_mapping

SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ATTACK_STAGE={"failed_login":0,"successful_login":1,"powershell":2,"credential_dump":3,"valid_accounts":4,"privileged_login":4,"internal_scan":5,"remote_service":6,"process_remote":6,"sensitive_access":7,"archive":8,"large_egress":9,"cloud_upload":9,"defender_disabled":7,"shadow_delete":8,"ransomware":10}

def _time_decay(seconds: float, half_life: float = 600.0) -> float:
    return math.exp(-max(0.0, seconds) / half_life)

def _edge_reason(a: Alert, b: Alert) -> tuple[float, list[str]]:
    dt=abs((a.timestamp-b.timestamp).total_seconds())
    if dt > 900:
        return 0.0, []
    score=.25*_time_decay(dt); reasons=[f"time gap {dt:.0f}s"]
    shared=[]
    if a.asset_id and a.asset_id == b.asset_id: score += .35; shared.append("same asset")
    if a.username and a.username == b.username: score += .18; shared.append("same user")
    if a.source_ip and a.source_ip == b.source_ip: score += .14; shared.append("same source IP")
    if a.destination_ip and a.destination_ip == b.destination_ip: score += .10; shared.append("same destination IP")
    if a.file_hash and a.file_hash == b.file_hash: score += .22; shared.append("same file hash")
    if a.process and a.process == b.process and a.process != "": score += .08; shared.append("same process")
    reasons.extend(shared)
    if a.alert_type in ATTACK_STAGE and b.alert_type in ATTACK_STAGE and abs(ATTACK_STAGE[a.alert_type]-ATTACK_STAGE[b.alert_type]) <= 3:
        score += .16; reasons.append("compatible attack-stage progression")
    # Require meaningful context. Time alone or a common username must not create giant components.
    return score, reasons

def correlate(alerts: list[Alert], threshold: float=.62) -> tuple[list[list[Alert]], nx.Graph]:
    g=nx.Graph(); lookup={a.alert_id:a for a in alerts}
    for a in alerts: g.add_node(a.alert_id, alert=a)
    candidates=set()
    # Candidate generation is bounded by time and entity. This avoids O(n^2).
    for field in ["asset_id","username","source_ip","destination_ip"]:
        groups=defaultdict(list)
        for a in alerts:
            v=getattr(a,field)
            if v: groups[v].append(a)
        for group in groups.values():
            group=sorted(group,key=lambda x:x.timestamp)
            for i,a in enumerate(group):
                for b in group[i+1:i+20]:
                    if (b.timestamp-a.timestamp).total_seconds()>900: break
                    candidates.add(tuple(sorted((a.alert_id,b.alert_id))))
    for x,y in candidates:
        a,b=lookup[x],lookup[y]; w,reasons=_edge_reason(a,b)
        # For cross-asset links require a shared identity/indicator plus attack-stage compatibility.
        same_asset=a.asset_id==b.asset_id
        has_shared_entity=any([
            a.username and a.username==b.username,
            a.source_ip and a.source_ip==b.source_ip,
            a.destination_ip and a.destination_ip==b.destination_ip,
            a.file_hash and a.file_hash==b.file_hash,
        ])
        stage_compatible=(a.alert_type in ATTACK_STAGE and b.alert_type in ATTACK_STAGE and abs(ATTACK_STAGE[a.alert_type]-ATTACK_STAGE[b.alert_type])<=3)
        if w>=threshold and (same_asset or (has_shared_entity and stage_compatible)):
            g.add_edge(x,y,weight=w,reasons=reasons)
    comps=[list(c) for c in nx.connected_components(g)]
    # Suppress isolated low-value noise; preserve isolated high/critical alerts for analyst review.
    attackish=[]; noise=[]
    benign_types={"failed_login","scanner_probe","scheduled_task","endpoint_update","blocked_connection","dns_query","backup_transfer","cloud_api","admin_maintenance","data_export","mail_rule_change"}
    for comp in comps:
        members=[lookup[x] for x in comp]
        # Treat a connected component as operational noise when it contains only routine
        # low/medium telemetry. This is a runtime heuristic; no ground-truth label is used.
        if all(a.alert_type in benign_types for a in members) and all(
            a.severity in {"low", "medium"} or a.maintenance_window or a.known_scanner for a in members
        ):
            noise.extend(members)
        elif len(comp)==1 and members[0].severity in {"low","medium"} and (members[0].known_scanner or members[0].maintenance_window or members[0].known_asset or members[0].known_user):
            noise.extend(members)
        else:
            attackish.append(members)
    # Collapse routine noise by source into a few transparent noise bundles.
    by_source=defaultdict(list)
    for a in noise: by_source[a.source].append(a)
    for src, group in by_source.items():
        attackish.append(group)
    return attackish,g

def build_incident(members:list[Alert], idx:int, graph:nx.Graph) -> Incident:
    iid=f"INC-{idx:04d}"
    evid=[]
    for j,a in enumerate(sorted(members,key=lambda x:x.timestamp),1):
        statement=f"{a.timestamp.isoformat()} — {a.source} reported {a.alert_type}: {a.description} on {a.asset_id}."
        evid.append(Evidence(f"EVD-{iid}-{j:03d}",a.alert_id,statement,"observed",a.confidence))
    mitre=infer_mitre_mapping(members)
    reasons=[]
    ids={a.alert_id for a in members}
    for a in members:
        for b in members:
            if a.alert_id >= b.alert_id or not graph.has_edge(a.alert_id,b.alert_id): continue
            reasons.extend(graph[a.alert_id][b.alert_id]["reasons"])
    reasons=list(dict.fromkeys(reasons))[:12]
    crit=max(a.asset_criticality for a in members)
    maxsev=max(SEV.get(a.severity,2) for a in members)
    cross_sources=len({a.source for a in members})
    privileged=any(a.username in {"admin","svc_backup"} for a in members)
    progression=len({x["tactic"] for x in mitre})
    anomalies=[]
    if any(a.alert_type in {"credential_dump","defender_disabled","ransomware","large_egress","shadow_delete"} for a in members): anomalies.append("high-impact behavior")
    if privileged: anomalies.append("privileged identity involved")
    if cross_sources>=3: anomalies.append("cross-source corroboration")
    risk_components={
        "asset_criticality": .35*crit,
        "severity": 6*maxsev,
        "cross_source": min(10,2*cross_sources),
        "attack_progression": min(15,3*progression),
        "confidence": 10*max(a.confidence for a in members),
        "volume": min(5, math.log1p(len(members))*1.6),
    }
    raw=sum(risk_components.values()); risk=100/(1+math.exp(-(raw-62)/12))
    title="Correlated security activity"
    types={a.alert_type for a in members}
    if "ransomware" in types or "shadow_delete" in types: title="Potential ransomware / impact activity"
    elif "large_egress" in types or "cloud_upload" in types: title="Potential sensitive-data exfiltration"
    elif "credential_dump" in types or "valid_accounts" in types: title="Potential credential compromise"
    elif "remote_service" in types or "process_remote" in types: title="Potential lateral movement"
    elif all(a.alert_type in {"failed_login","scanner_probe","scheduled_task","endpoint_update","blocked_connection","dns_query","backup_transfer","cloud_api","admin_maintenance","data_export","mail_rule_change"} for a in members): title=f"Operational activity — {members[0].source}"
    severity="critical" if risk>=85 else "high" if risk>=65 else "medium" if risk>=40 else "low"
    observed=sorted({x["tactic"] for x in mitre})
    return Incident(iid,[a.alert_id for a in members],round(risk,2),title,severity,crit,evid,mitre,[],"","OPEN","UNREVIEWED","",reasons,risk_components,anomalies,observed,[],None,"deterministic-fallback")
