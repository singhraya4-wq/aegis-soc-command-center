from __future__ import annotations
from pathlib import Path
import json, joblib, numpy as np
from .models import Incident, Alert

MODEL_PATH=Path("models/ranking_model.joblib")
META_PATH=Path("models/ranking_metadata.json")
FEATURES=["asset_criticality","risk_score","alert_count","severity_num","source_count","mitre_count","behavioral_anomaly","privileged","cross_source","confidence_max","duration_min","anomaly_max","anomaly_mean"]

def feature_row(inc: Incident, alerts: list[Alert]) -> dict[str,float]:
    amap={a.alert_id:a for a in alerts}; members=[amap[x] for x in inc.alert_ids]
    sev={"low":1,"medium":2,"high":3,"critical":4}[inc.severity]
    ts=[a.timestamp for a in members]
    duration=(max(ts)-min(ts)).total_seconds()/60 if len(ts)>1 else 0
    return {
        "asset_criticality":inc.asset_criticality,"risk_score":inc.risk_score,"alert_count":len(members),
        "severity_num":sev,"source_count":len({a.source for a in members}),"mitre_count":len(inc.mitre),
        "behavioral_anomaly":len(inc.behavioral_anomalies),"privileged":int(any(a.username in {"admin","svc_backup"} for a in members)),
        "cross_source":len({a.source for a in members}),"confidence_max":max(a.confidence for a in members),"duration_min":duration,
        "anomaly_max":max(float(a.metadata.get("anomaly_score",0.0)) for a in members),
        "anomaly_mean":float(np.mean([float(a.metadata.get("anomaly_score",0.0)) for a in members])),
    }

def load_model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None

def rank_incidents(incidents:list[Incident], alerts:list[Alert]) -> list[Incident]:
    model=load_model(); meta={}
    if META_PATH.exists(): meta=json.loads(META_PATH.read_text())
    if model is None:
        for i in incidents:
            i.ml_score=None; i.ranking_model="deterministic-fallback"
        return sorted(incidents,key=lambda x:(x.risk_score,x.asset_criticality),reverse=True)
    rows=[feature_row(i,alerts) for i in incidents]
    X=np.array([[r[f] for f in FEATURES] for r in rows])
    if meta.get("model_name") == "LightGBM":
        import pandas as pd
        X_input = pd.DataFrame(X, columns=FEATURES)
    else:
        X_input = X
    scores=model.predict_proba(X_input)[:,1] if hasattr(model,"predict_proba") else model.predict(X_input)
    for i,s in zip(incidents,scores):
        i.ml_score=float(s); i.ranking_model=meta.get("model_name","trained-ranking-model")
    return sorted(incidents,key=lambda x:(x.ml_score or 0,x.risk_score),reverse=True)
