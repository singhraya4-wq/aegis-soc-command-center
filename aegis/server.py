from __future__ import annotations
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from .generator import generate_alerts
from .pipeline import run_pipeline
from .simulator import attack_replay
from .feedback import create_rule

app=FastAPI(title="AEGIS SOC v2",version="2.0")
app.mount("/static",StaticFiles(directory="static"),name="static")
STATE={"alerts":generate_alerts(3000)}

@app.get("/",response_class=HTMLResponse)
def home(): return open("static/index.html",encoding="utf-8").read()

@app.get("/api/health")
def health(): return {"status":"ok","service":"AEGIS SOC v2","alerts":len(STATE["alerts"])}

@app.get("/api/overview")
def overview():
    r=run_pipeline(STATE["alerts"]); inc=r["incidents"]
    return {"alerts":len(r["alerts"]),"incidents":len(inc),"critical":sum(i.severity=="critical" for i in inc),"models":sorted({i.ranking_model for i in inc}),"validation_errors":len(r["validation_errors"]),"top":[{"id":i.incident_id,"risk":i.risk_score,"title":i.title,"severity":i.severity,"alerts":len(i.alert_ids),"model":i.ranking_model} for i in inc[:10]]}

@app.get("/api/incidents/{incident_id}")
def incident(incident_id:str):
    r=run_pipeline(STATE["alerts"]); i=next(x for x in r["incidents"] if x.incident_id==incident_id)
    return {"incident":i.__dict__,"evidence":[e.__dict__ for e in i.evidence]}

@app.post("/api/simulate")
def simulate():
    r=run_pipeline(attack_replay()); return {"alerts":len(r["alerts"]),"incidents":[i.__dict__ for i in r["incidents"]]}

@app.post("/api/feedback")
async def feedback(request:Request):
    body=await request.json(); rule=create_rule(body["rule_type"],body["match_field"],body["match_pattern"],body.get("description","Analyst feedback"),body.get("created_by","analyst"),float(body.get("confidence",.9)),int(body.get("ttl_days",30)))
    return rule.__dict__
