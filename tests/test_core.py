from aegis.generator import generate_alerts
from aegis.pipeline import run_pipeline

def test_pipeline():
    alerts=generate_alerts(500)
    r=run_pipeline(alerts)
    assert len(r["alerts"])==500
    assert len(r["incidents"])>0
    for i in r["incidents"][:20]:
        assert 0 <= i.risk_score <= 100
        assert all(e.evidence_id for e in i.evidence)

def test_no_ground_truth_leakage():
    from aegis.ranker import FEATURES
    assert "ground_truth_incident_id" not in FEATURES
    assert "ground_truth_label" not in FEATURES
