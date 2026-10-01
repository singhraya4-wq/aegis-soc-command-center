from __future__ import annotations
import ipaddress
from dataclasses import replace
from .models import Alert

REQUIRED = ["alert_id", "timestamp", "source", "alert_type", "asset_id", "asset_criticality"]

def normalize_alert(a: Alert) -> Alert:
    source = (a.source or "UNKNOWN").upper().strip()
    severity = (a.severity or "medium").lower().strip()
    severity = severity if severity in {"low","medium","high","critical"} else "medium"
    conf = max(0.0, min(1.0, float(a.confidence)))
    crit = max(0.0, min(100.0, float(a.asset_criticality)))
    return replace(a, source=source, severity=severity, confidence=conf, asset_criticality=crit,
                   description=" ".join((a.description or "").split()))

def validate_alert(a: Alert) -> list[str]:
    errors=[]
    for k in REQUIRED:
        if getattr(a,k,None) in (None, ""): errors.append(f"missing:{k}")
    for value, field in [(a.source_ip,"source_ip"),(a.destination_ip,"destination_ip")]:
        if value:
            try: ipaddress.ip_address(value)
            except ValueError: errors.append(f"invalid_ip:{field}")
    if not 0 <= a.confidence <= 1: errors.append("confidence_out_of_range")
    if not 0 <= a.asset_criticality <= 100: errors.append("asset_criticality_out_of_range")
    return errors
