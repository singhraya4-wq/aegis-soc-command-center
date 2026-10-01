from __future__ import annotations
import argparse, json
from dataclasses import asdict
from .generator import generate_alerts,write_jsonl,read_jsonl
from .pipeline import run_pipeline
from .ml import train_benchmark
from .metrics import benchmark,pairwise_scores,attack_clustering_scores
from .simulator import attack_replay

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("build-data"); a.add_argument("--out",default="data/alerts.jsonl"); a.add_argument("--n",type=int,default=3000)
    a=sub.add_parser("train"); a.add_argument("--data",default="data/alerts.jsonl")
    a=sub.add_parser("evaluate"); a.add_argument("--data",default="data/alerts.jsonl")
    a=sub.add_parser("demo"); a.add_argument("--data",default="data/alerts.jsonl")
    args=p.parse_args()
    if args.cmd=="build-data":
        write_jsonl(generate_alerts(args.n),args.out); print(f"Generated {args.n} alerts -> {args.out}"); return
    alerts=read_jsonl(args.data)
    result=run_pipeline(alerts)
    if args.cmd=="train":
        results,meta=train_benchmark(result["incidents"],alerts)
        for r in results: print(r[:3])
        print(json.dumps(meta,indent=2)); return
    if args.cmd=="evaluate":
        b=benchmark(alerts,result["incidents"],result["incidents"])
        truth={}
        for a in alerts:
            if a.ground_truth_incident_id: truth.setdefault(a.ground_truth_incident_id,[]).append(a.alert_id)
        clustering=attack_clustering_scores([i.alert_ids for i in result["incidents"]],alerts,list(truth.values()))
        payload=asdict(b); payload["attack_clustering_pairwise"]=clustering
        print(json.dumps(payload,indent=2)); return
    if args.cmd=="demo":
        print(f"Alerts: {len(alerts)} | Incidents: {len(result['incidents'])} | Validation errors: {len(result['validation_errors'])}")
        for inc in result["incidents"][:5]: print(f"{inc.incident_id} | {inc.risk_score:5.1f} | {inc.severity.upper():8} | {inc.title} | {inc.ranking_model}")
        print("\nSimulation:")
        sim=run_pipeline(attack_replay()); print(f"{len(sim['alerts'])} alerts -> {len(sim['incidents'])} incidents"); print(sim['incidents'][0].summary)
if __name__=="__main__": main()
