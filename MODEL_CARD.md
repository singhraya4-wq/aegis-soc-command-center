# AEGIS SOC v2 — Model Card

## Purpose
AEGIS is an AI-assisted SOC alert-triage system. It correlates high-volume telemetry into incidents, ranks incidents for analyst review, maps observed behavior to MITRE ATT&CK, and produces evidence-grounded briefs.

## Trained artifact
- Primary artifact: `models/ranking_model.joblib`
- Candidate artifacts: `models/ranking_model_catboost.joblib`, `models/ranking_model_lightgbm.joblib`
- Metadata: `models/ranking_metadata.json`
- Dataset: `data/alerts.jsonl` (3,000 synthetic alerts)

## Runtime features
The ranking model uses only derived incident features:
- asset criticality
- explainable risk score
- alert count
- severity
- source count
- MITRE technique count
- behavioral anomaly count
- privileged identity indicator
- cross-source count
- maximum confidence
- incident duration
- maximum anomaly score
- mean anomaly score

Ground-truth incident IDs and labels are **not** runtime features.

## Training/evaluation
Training uses an incident-level chronological 60/20/20 split. CatBoost and LightGBM are trained as real gradient-boosting models. Selection is based on NDCG@5, then Recall@3, then PR-AUC.

The current synthetic benchmark selected the model recorded in `ranking_metadata.json`. The reported metrics are synthetic-dataset measurements and must not be presented as production efficacy or real-world MTTT validation.

## Safety
- Telemetry is treated as untrusted data for LLM summarization.
- Evidence IDs are attached to claims.
- MITRE mappings abstain when evidence is insufficient.
- Feedback rules have TTL/provenance/analyst approval fields.
- Prompt-injection regression tests are included.

## Limitations
This is a hackathon-grade synthetic system, not a production SOC platform. Real deployment requires organization-specific telemetry connectors, authenticated storage, access control, secrets management, monitoring, model drift evaluation, and validation against real incident labels.
