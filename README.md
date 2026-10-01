# AEGIS SOC v2 — Incident Intelligence Platform

This is a rebuilt, hackathon-ready implementation of the AEGIS/S.H.I.E.L.D concept for **“3,000 Alerts, One Analyst”**.

## What is implemented

- Synthetic 3,000-alert generator with explicit ground-truth incident IDs used **only for evaluation/training**.
- Alert schema normalization and validation.
- Weighted temporal/entity correlation with explainable relationship edges.
- Incident construction with observed vs inferred evidence.
- Behavioral anomaly features and optional Isolation Forest.
- Asset-criticality-aware risk scoring.
- **CatBoost vs LightGBM** incident-ranking benchmark with leakage-safe train/validation/test split.
- Trained model inference integrated into the incident ranking path when a model artifact exists.
- Deterministic fallback ranking when ML dependencies/artifacts are unavailable.
- Evidence ledger and claim-level AI grounding.
- Evidence-backed MITRE ATT&CK mapping with abstention when evidence is insufficient.
- MITRE version metadata set to Enterprise ATT&CK **v19.2**; curated techniques used by this prototype are explicitly versioned.
- Analyst feedback rules with provenance, confidence, scope and TTL.
- Incident merge/split workflow.
- Counterfactual risk explanation.
- Attack replay simulator.
- Prompt-injection test cases inside untrusted telemetry fields.
- Evaluation metrics: clustering pairwise P/R/F1, Recall@K, NDCG@K, ATT&CK mapping precision, claim grounding, and replay triage-time estimates.
- FastAPI dashboard/API and a lightweight browser UI.

## Important methodology

The system never uses `ground_truth_incident_id`, `ground_truth_label`, or evaluation-only fields as runtime features. They are retained in the synthetic dataset solely to train/evaluate models and measure clustering quality.

The LLM is **not** the detector or risk engine. It receives a structured evidence packet after normalization, correlation, ranking and MITRE mapping. Every factual claim in an AI brief must cite evidence IDs and pass the claim verifier.

## Run

```bash
pip install -r requirements.txt
python -m aegis.cli build-data --out data/alerts.jsonl --n 3000
python -m aegis.cli train --data data/alerts.jsonl
python -m aegis.cli evaluate --data data/alerts.jsonl
python -m aegis.cli demo --data data/alerts.jsonl
uvicorn aegis.server:app --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080`.

If CatBoost/LightGBM are not installed, the project still runs using the deterministic ranking fallback. The benchmark command reports which models were actually trained; it does not fabricate metrics.

## Optional LLM

Set an OpenAI-compatible endpoint/model through environment variables:

```bash
AEGIS_LLM_BASE_URL=...
AEGIS_LLM_API_KEY=...
AEGIS_LLM_MODEL=...
```

Without an LLM, the system uses a deterministic evidence-grounded brief so the demo remains runnable offline.

## Ready-made deployment package
This archive includes the trained ranking artifact, the 3,000-alert simulated corpus, CatBoost and LightGBM candidate artifacts, Dockerfile, Render configuration, health endpoint, and deployment instructions. No public-hosting credentials are embedded.
