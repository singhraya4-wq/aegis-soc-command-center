from __future__ import annotations
from dataclasses import dataclass
from .models import Alert

MITRE_VERSION = "Enterprise ATT&CK v19.2"
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
]

@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

CATALOG = {
    "T1059.001": Technique("T1059.001", "PowerShell", "Execution"),
    "T1003": Technique("T1003", "OS Credential Dumping", "Credential Access"),
    "T1078": Technique("T1078", "Valid Accounts", "Initial Access"),
    "T1562.001": Technique("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Impairment"),
    "T1070.004": Technique("T1070.004", "File and Directory Discovery", "Stealth"),
    "T1021.002": Technique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    "T1046": Technique("T1046", "Network Service Scanning", "Discovery"),
    "T1560": Technique("T1560", "Archive Collected Data", "Collection"),
    "T1567": Technique("T1567", "Exfiltration Over Web Service", "Exfiltration"),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "Impact"),
}

def infer_mitre_mapping(alerts: list[Alert]) -> list[dict]:
    """Evidence-first mapping. It abstains instead of forcing a technique from a weak keyword."""
    out=[]
    for a in alerts:
        text=f"{a.alert_type} {a.description} {a.process} {a.command_line}".lower()
        candidates=[]
        if a.alert_type == "powershell" or ("powershell" in text and "-enc" in text):
            candidates.append(("T1059.001", .98, "Observed PowerShell execution"))
        if a.alert_type == "credential_dump" or "lsass" in text or "credential access" in text:
            candidates.append(("T1003", .97, "Observed credential-dumping behavior"))
        if a.alert_type in {"valid_accounts", "privileged_login"} and a.authentication_result == "success":
            candidates.append(("T1078", .88, "Successful account authentication observed"))
        if a.alert_type == "defender_disabled":
            candidates.append(("T1562.001", .99, "Security-control disablement observed"))
        if a.alert_type == "internal_scan":
            candidates.append(("T1046", .96, "Network service scanning behavior observed"))
        if a.alert_type == "remote_service":
            candidates.append(("T1021.002", .90, "Remote service execution observed"))
        if a.alert_type == "archive":
            candidates.append(("T1560", .94, "Archive creation observed"))
        if a.alert_type in {"large_egress", "cloud_upload"}:
            candidates.append(("T1567", .82, "Web/cloud exfiltration-like transfer observed"))
        if a.alert_type == "ransomware":
            candidates.append(("T1486", .99, "File-encryption impact behavior observed"))
        for tid, conf, evidence in candidates:
            t=CATALOG[tid]
            out.append({"technique_id":t.id,"name":t.name,"tactic":t.tactic,"confidence":conf,"alert_id":a.alert_id,"evidence":evidence,"status":"observed"})
    # Deduplicate by technique and keep highest confidence evidence.
    best={}
    for x in out:
        best.setdefault(x["technique_id"], x)
        if x["confidence"] > best[x["technique_id"]]["confidence"]: best[x["technique_id"]]=x
    return list(best.values())
