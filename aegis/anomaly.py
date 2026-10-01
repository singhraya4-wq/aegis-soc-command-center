from __future__ import annotations
from collections import Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from .models import Alert

SEV={"low":1,"medium":2,"high":3,"critical":4}

def _features(alerts:list[Alert]):
    source_counts=Counter(a.source for a in alerts)
    type_counts=Counter(a.alert_type for a in alerts)
    X=[]
    for a in alerts:
        X.append([
            SEV.get(a.severity,2), a.confidence, a.asset_criticality/100,
            np.log1p(source_counts[a.source]), np.log1p(type_counts[a.alert_type]),
            int(a.maintenance_window), int(a.known_scanner), int(a.known_asset),
        ])
    return np.asarray(X,dtype=float)

def score_alerts(alerts:list[Alert])->list[Alert]:
    if len(alerts)<20:
        return alerts
    X=_features(alerts)
    model=IsolationForest(n_estimators=150,contamination="auto",random_state=42)
    model.fit(X)
    raw=-model.decision_function(X)
    lo,hi=float(raw.min()),float(raw.max())
    for a,s in zip(alerts,raw):
        a.metadata["anomaly_score"]=round(float((s-lo)/(hi-lo+1e-9)),4)
    return alerts
