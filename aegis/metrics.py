from __future__ import annotations
import math
from collections import defaultdict
from .models import Alert, Incident, TriageBenchmark

def pairwise_scores(predicted:list[list[str]], truth:list[list[str]]):
    def pairs(groups):
        s=set()
        for g in groups:
            for i in range(len(g)):
                for j in range(i+1,len(g)): s.add(tuple(sorted((g[i],g[j]))))
        return s
    p,t=pairs(predicted),pairs(truth); tp=len(p&t)
    precision=tp/len(p) if p else 0; recall=tp/len(t) if t else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    return {"precision":precision,"recall":recall,"f1":f1}

def dcg(rels):
    return sum((2**r-1)/math.log2(i+2) for i,r in enumerate(rels))

def ranking_metrics(ranked:list[Incident], alerts:list[Alert], k_values=(3,5,10)):
    amap={a.alert_id:a for a in alerts}
    relevant=[int(any(amap[aid].ground_truth_label==1 for aid in inc.alert_ids)) for inc in ranked]
    out={}
    total=sum(relevant)
    for k in k_values:
        top=relevant[:k]; out[f"Recall@{k}"]=sum(top)/total if total else 0
        ideal=sorted(relevant,reverse=True)[:k]
        out[f"NDCG@{k}"]=dcg(top)/dcg(ideal) if dcg(ideal) else 0
    return out

def attack_clustering_scores(predicted:list[list[str]], alerts:list[Alert], truth_groups:list[list[str]]):
    positive={a.alert_id for a in alerts if a.ground_truth_label==1}
    pred_pos=[[x for x in g if x in positive] for g in predicted]
    pred_pos=[g for g in pred_pos if g]
    truth_pos=[[x for x in g if x in positive] for g in truth_groups]
    truth_pos=[g for g in truth_pos if g]
    return pairwise_scores(pred_pos,truth_pos)

def benchmark(alerts:list[Alert], incidents:list[Incident], ranking):
    amap={a.alert_id:a for a in alerts}
    baseline=sum(2.0 if a.ground_truth_label==0 else 5.0 for a in alerts)
    # Estimate analyst work from incident-level review, explicitly labelled as a replay estimate.
    augmented=10.0 + sum(6.0 if i.risk_score>=65 else 3.0 for i in ranking)
    reduction=max(0.0,1-augmented/baseline)*100
    rm=ranking_metrics(ranking,alerts)
    return TriageBenchmark(len(alerts),len(incidents),len(alerts)/max(1,len(incidents)),baseline,augmented,baseline/60,augmented/60,baseline-augmented,reduction,baseline/max(1,augmented),{k:v for k,v in rm.items() if k.startswith("Recall")},{k:v for k,v in rm.items() if k.startswith("NDCG")})
