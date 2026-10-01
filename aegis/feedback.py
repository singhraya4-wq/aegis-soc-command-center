from __future__ import annotations
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
import json
from pathlib import Path
from .models import FeedbackRule, Alert

PATH=Path("artifacts/feedback_rules.json")

def save_rule(rule:FeedbackRule):
    PATH.parent.mkdir(parents=True,exist_ok=True)
    data=[]
    if PATH.exists(): data=json.loads(PATH.read_text())
    data.append({**asdict(rule),"created_at":rule.created_at.isoformat(),"expires_at":rule.expires_at.isoformat() if rule.expires_at else None})
    PATH.write_text(json.dumps(data,indent=2))

def active_rules()->list[FeedbackRule]:
    if not PATH.exists(): return []
    now=datetime.now(timezone.utc); out=[]
    for d in json.loads(PATH.read_text()):
        d["created_at"]=datetime.fromisoformat(d["created_at"]); d["expires_at"]=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None
        if d.get("active") and (not d["expires_at"] or d["expires_at"]>now): out.append(FeedbackRule(**d))
    return out

def create_rule(rule_type, field, pattern, description, created_by="analyst", confidence=.9, ttl_days=30)->FeedbackRule:
    now=datetime.now(timezone.utc)
    r=FeedbackRule(f"RULE-{now.strftime('%Y%m%d%H%M%S')}",now,created_by,rule_type,field,pattern,description,confidence,True,now+timedelta(days=ttl_days),0,True)
    save_rule(r); return r

def apply_rules(alerts:list[Alert])->list[Alert]:
    rules=active_rules()
    for a in alerts:
        for r in rules:
            value=str(getattr(a,r.match_field,""))
            if r.match_pattern.lower() in value.lower(): r.hit_count+=1
    return alerts
