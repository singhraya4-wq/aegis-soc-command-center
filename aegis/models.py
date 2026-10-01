from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional

@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    source: str
    alert_type: str
    description: str
    severity: str
    confidence: float
    asset_id: str
    asset_type: str
    asset_criticality: float
    hostname: str = ""
    username: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_domain: str = ""
    port: int = 0
    protocol: str = ""
    process: str = ""
    parent_process: str = ""
    command_line: str = ""
    file_hash: str = ""
    authentication_result: str = ""
    country: str = ""
    maintenance_window: bool = False
    known_asset: bool = False
    known_user: bool = False
    known_scanner: bool = False
    ground_truth_incident_id: Optional[str] = None
    ground_truth_label: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

@dataclass
class Evidence:
    evidence_id: str
    alert_id: str
    statement: str
    kind: str = "observed"
    confidence: float = 1.0

@dataclass
class Incident:
    incident_id: str
    alert_ids: list[str]
    risk_score: float
    title: str
    severity: str
    asset_criticality: float
    evidence: list[Evidence] = field(default_factory=list)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    status: str = "OPEN"
    analyst_verdict: str = "UNREVIEWED"
    analyst_notes: str = ""
    correlation_reasons: list[str] = field(default_factory=list)
    risk_components: dict[str, float] = field(default_factory=dict)
    behavioral_anomalies: list[str] = field(default_factory=list)
    observed_stages: list[str] = field(default_factory=list)
    inferred_stages: list[str] = field(default_factory=list)
    ml_score: Optional[float] = None
    ranking_model: str = "deterministic-fallback"

@dataclass
class FeedbackRule:
    rule_id: str
    created_at: datetime
    created_by: str
    rule_type: str
    match_field: str
    match_pattern: str
    description: str
    confidence: float
    active: bool = True
    expires_at: Optional[datetime] = None
    hit_count: int = 0
    analyst_approved: bool = True

@dataclass
class TriageBenchmark:
    raw_alerts: int
    incidents: int
    alerts_per_incident: float
    baseline_minutes: float
    augmented_minutes: float
    baseline_hours: float
    augmented_hours: float
    estimated_minutes_saved: float
    estimated_mttt_reduction_pct: float
    throughput_multiplier: float
    recall_at_k: dict[str, float]
    ndcg_at_k: dict[str, float]
