from __future__ import annotations
from pathlib import Path
import json, joblib, numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score
from .models import Alert
from .ranker import feature_row, FEATURES

MODEL_DIR = Path("models"); MODEL_DIR.mkdir(exist_ok=True)


def make_dataset(incidents, alerts):
    amap = {a.alert_id: a for a in alerts}; X = []; y = []; times = []
    for inc in incidents:
        row = feature_row(inc, alerts)
        X.append([row[f] for f in FEATURES])
        y.append(int(any(amap[x].ground_truth_label == 1 for x in inc.alert_ids)))
        times.append(min(amap[x].timestamp for x in inc.alert_ids))
    return np.asarray(X, dtype=float), np.asarray(y, dtype=int), np.asarray(times)


def _time_split(times, train=.6, val=.2):
    order = np.argsort(times)
    n = len(order); a = max(2, int(train*n)); b = max(a+1, int((train+val)*n))
    return order[:a], order[a:b], order[b:]


def _ranking_metrics(y, scores, k=5):
    order = np.argsort(-scores); rel = y[order]; top = rel[:k]; ideal = np.sort(rel)[::-1][:k]
    def dcg(v): return sum((2**int(r)-1)/np.log2(i+2) for i,r in enumerate(v))
    ndcg = dcg(top)/dcg(ideal) if dcg(ideal) else 0.0
    recall3 = float(np.sum(rel[:3])/max(1, np.sum(rel)))
    return ndcg, recall3


def train_benchmark(incidents, alerts):
    X, y, times = make_dataset(incidents, alerts)
    if len(set(y.tolist())) < 2:
        raise RuntimeError("Need both benign and attack incidents to train.")
    tr, va, te = _time_split(times)
    # Ensure train/test each contain both classes. If a chronological split is impossible,
    # fail loudly instead of silently leaking labels across time.
    if len(set(y[tr].tolist())) < 2 or len(set(y[te].tolist())) < 2:
        raise RuntimeError("Chronological split lacks both classes; generate more mixed scenarios.")
    results=[]
    try:
        from catboost import CatBoostClassifier
        m=CatBoostClassifier(iterations=350,depth=5,learning_rate=.035,loss_function="Logloss",verbose=False,random_seed=42,l2_leaf_reg=5)
        m.fit(X[tr],y[tr],eval_set=(X[va],y[va]),early_stopping_rounds=40,verbose=False)
        p=m.predict_proba(X[te])[:,1]
        results.append(("CatBoost",roc_auc_score(y[te],p),average_precision_score(y[te],p),m))
    except Exception as e:
        results.append(("CatBoost",None,None,str(e)))
    try:
        from lightgbm import LGBMClassifier
        m=LGBMClassifier(n_estimators=350,num_leaves=15,max_depth=5,learning_rate=.035,subsample=.85,colsample_bytree=.9,reg_lambda=2,random_state=42,verbosity=-1)
        m.fit(X[tr],y[tr],eval_set=[(X[va],y[va])],callbacks=[])
        p=m.predict_proba(X[te])[:,1]
        results.append(("LightGBM",roc_auc_score(y[te],p),average_precision_score(y[te],p),m))
    except Exception as e:
        results.append(("LightGBM",None,None,str(e)))
    valid=[r for r in results if r[1] is not None]
    if not valid: raise RuntimeError(f"No ML backend available: {results}")
    scored=[]
    for name,auc,ap,model in valid:
        scores=model.predict_proba(X[te])[:,1]
        ndcg5,recall3=_ranking_metrics(y[te],scores,5)
        scored.append((name,auc,ap,model,ndcg5,recall3))
    scored.sort(key=lambda r:(r[4],r[5],r[2],r[1]),reverse=True)
    winner=scored[0]
    for r in scored:
        joblib.dump(r[3], MODEL_DIR / f"ranking_model_{r[0].lower()}.joblib")
    joblib.dump(winner[3],MODEL_DIR/"ranking_model.joblib")
    meta={
        "model_name":winner[0],"selection_metric":"NDCG@5 -> Recall@3 -> PR-AUC",
        "test_pr_auc":winner[2],"test_roc_auc":winner[1],"test_ndcg_at_5":winner[4],"test_recall_at_3":winner[5],
        "features":FEATURES,"split":"chronological 60/20/20 by incident start time",
        "dataset_size":len(alerts),"incident_count":len(incidents),
        "training_note":"Ground-truth fields are used only to create offline labels. No ground-truth IDs/labels are runtime model features.",
        "candidates":[{"model":r[0],"roc_auc":r[1],"pr_auc":r[2],"ndcg_at_5":r[4],"recall_at_3":r[5]} for r in scored]
    }
    (MODEL_DIR/"ranking_metadata.json").write_text(json.dumps(meta,indent=2))
    return [(r[0],r[1],r[2],r[4],r[5]) for r in scored],meta
