from __future__ import annotations
import json, random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from .models import Alert

RNG = random.Random(20261001)
SOURCES = ["IAM", "EDR", "NETWORK", "FIREWALL", "EMAIL", "CLOUD", "WEB", "DATA"]
ASSETS = [
    ("PAY-DB", "Database", 100), ("IAM-01", "Identity", 96), ("ADMIN-01", "Endpoint", 94),
    ("STUDENT-PORTAL", "WebApp", 78), ("LMS-01", "WebApp", 70), ("FACULTY-PORTAL", "WebApp", 74),
    ("MAIL-01", "Email", 72), ("DEV-17", "Endpoint", 45), ("LAB-22", "Endpoint", 35),
    ("WS-102", "Endpoint", 62), ("WS-205", "Endpoint", 58), ("CLOUD-CTRL", "Cloud", 92),
]
USERS = ["student01", "faculty07", "svc_backup", "admin", "analyst", "dev17", "finance02", "research11", "itops03"]
IPS = ["10.10.1.14", "10.10.2.18", "10.10.4.9", "10.10.7.44", "172.16.4.20", "192.0.2.31", "192.0.2.52"]
DOMAINS = ["updates.example.test", "cdn.example.test", "rare-domain.test", "sync.example.test", "files.example.test"]

BENIGN_TYPES = [
    ("failed_login", "Repeated failed authentication", "low"),
    ("scanner_probe", "Approved vulnerability scanner probe", "low"),
    ("scheduled_task", "Known scheduled administrative task", "low"),
    ("endpoint_update", "Managed endpoint update activity", "low"),
    ("blocked_connection", "Firewall blocked connection", "medium"),
    ("dns_query", "Routine DNS query", "low"),
    ("backup_transfer", "Scheduled backup transfer", "medium"),
    ("cloud_api", "Routine cloud API operation", "low"),
    ("admin_maintenance", "Approved privileged maintenance activity", "high"),
    ("data_export", "Approved scheduled data export", "high"),
    ("mail_rule_change", "Approved mailbox rule change", "medium"),
]

SCENARIOS = {
    "CRED": [
        ("failed_login", "Multiple failed logins", "medium"),
        ("successful_login", "Successful login following failed attempts", "high"),
        ("powershell", "PowerShell execution with encoded command", "high"),
        ("credential_dump", "LSASS credential access", "critical"),
        ("valid_accounts", "Privileged account authentication", "critical"),
        ("privileged_login", "Privileged login to unusual endpoint", "high"),
    ],
    "EXFIL": [
        ("sensitive_access", "Unusual sensitive database access", "high"),
        ("archive", "Archive created from sensitive files", "high"),
        ("large_egress", "Large outbound transfer to rare destination", "critical"),
        ("cloud_upload", "Unusual cloud object upload", "high"),
    ],
    "RANSOM": [
        ("powershell", "Suspicious PowerShell execution", "high"),
        ("defender_disabled", "Security controls disabled", "critical"),
        ("shadow_delete", "Volume shadow copies deleted", "critical"),
        ("ransomware", "High-volume file encryption behavior", "critical"),
    ],
    "LATERAL": [
        ("internal_scan", "Internal host discovery spike", "medium"),
        ("remote_service", "Remote service execution on new host", "high"),
        ("privileged_login", "Privileged login to unusual endpoint", "high"),
        ("process_remote", "Remote process creation", "high"),
    ],
    "CLOUD": [
        ("cloud_api", "Unusual cloud API sequence", "medium"),
        ("iam_change", "Unexpected identity-policy modification", "high"),
        ("secret_access", "Unusual cloud secret access", "critical"),
        ("cloud_upload", "Unusual cloud object upload", "high"),
        ("large_egress", "Large outbound cloud transfer", "critical"),
    ],
}


def _asset_map():
    return {x[0]: x for x in ASSETS}


def _base_alert(i: int, ts: datetime, *, asset_id: str | None = None, username: str | None = None,
                source_ip: str | None = None, destination_ip: str | None = None,
                high_noise: bool = False) -> Alert:
    amap = _asset_map()
    asset_id = asset_id or RNG.choice(ASSETS)[0]
    asset_type, criticality = amap[asset_id][1], amap[asset_id][2]
    source = RNG.choice(SOURCES)
    typ, desc, sev = RNG.choice(BENIGN_TYPES)
    if high_noise and typ in {"admin_maintenance", "data_export"}:
        sev = RNG.choice(["high", "critical"])
    known_scanner = typ == "scanner_probe" or RNG.random() < 0.03
    return Alert(
        alert_id=f"ALT-{i:05d}", timestamp=ts, source=source, alert_type=typ, description=desc,
        severity=sev, confidence=round(RNG.uniform(.55, .98), 3), asset_id=asset_id,
        asset_type=asset_type, asset_criticality=criticality, hostname=asset_id,
        username=username or RNG.choice(USERS), source_ip=source_ip or RNG.choice(IPS),
        destination_ip=destination_ip or RNG.choice(IPS), destination_domain=RNG.choice(DOMAINS),
        port=RNG.choice([53, 80, 443, 445, 3389]), protocol=RNG.choice(["TCP", "UDP", "HTTPS"]),
        process=RNG.choice(["svchost.exe", "chrome.exe", "python.exe", "powershell.exe"]),
        parent_process="explorer.exe", command_line="",
        authentication_result="failure" if typ == "failed_login" else "",
        country=RNG.choice(["IN", "US", "GB", "SG"]),
        maintenance_window=typ in {"scheduled_task", "endpoint_update", "admin_maintenance", "data_export"} and RNG.random() < .8,
        known_asset=RNG.random() < .97, known_user=RNG.random() < .94, known_scanner=known_scanner,
        ground_truth_incident_id=None, ground_truth_label=0,
    )


def _attack_alert(i: int, ts: datetime, incident_id: str, typ: str, desc: str, sev: str,
                  asset_id: str, username: str, source_ip: str, destination_ip: str) -> Alert:
    amap = _asset_map(); asset_type, crit = amap[asset_id][1], amap[asset_id][2]
    a = Alert(
        alert_id=f"ALT-{i:05d}", timestamp=ts, source=RNG.choice(SOURCES), alert_type=typ,
        description=desc, severity=sev, confidence=round(RNG.uniform(.72, .995), 3),
        asset_id=asset_id, asset_type=asset_type, asset_criticality=crit, hostname=asset_id,
        username=username, source_ip=source_ip, destination_ip=destination_ip,
        destination_domain=RNG.choice(DOMAINS), port=RNG.choice([443, 445, 3389, 5985]), protocol="TCP",
        process="powershell.exe" if typ == "powershell" else "",
        parent_process="cmd.exe" if typ == "powershell" else "",
        command_line="powershell -enc REDACTED" if typ == "powershell" else "",
        authentication_result="success" if typ in {"successful_login", "valid_accounts", "privileged_login"} else "",
        country="IN", known_asset=True, known_user=True, ground_truth_incident_id=incident_id, ground_truth_label=1,
    )
    if typ == "large_egress": a.destination_ip = destination_ip; a.port = 443
    if typ == "credential_dump": a.process = "procdump.exe"
    if typ == "shadow_delete": a.process = "vssadmin.exe"
    if typ in {"ransomware", "defender_disabled"}: a.process = "cmd.exe"
    if typ == "iam_change": a.process = "cloudctl.exe"
    if typ == "secret_access": a.process = "cloud-agent.exe"
    return a


def generate_alerts(n: int = 3000) -> list[Alert]:
    """Generate a deliberately noisy, leakage-safe synthetic SOC corpus.

    Ground truth is attached only for offline evaluation/training. Runtime pipeline code
    must ignore these fields. The corpus contains overlapping benign activity, high-severity
    decoys, partial attack stories, missing-ish telemetry, and shared entities.
    """
    n = max(300, n)
    start = datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)
    alerts: list[Alert] = []
    i = 1
    incident_no = 0
    scenario_names = list(SCENARIOS)

    # 50 attack stories: enough positive incidents to train while retaining a large benign majority.
    for story in range(50):
        scenario_id = scenario_names[story % len(scenario_names)]
        steps = SCENARIOS[scenario_id]
        incident_no += 1
        base = start + timedelta(minutes=10 + story * 27 + RNG.randint(0, 8))
        asset = ASSETS[(story * 3) % len(ASSETS)][0]
        username = f"svc_{scenario_id.lower()}_{story:02d}" if story % 3 else RNG.choice(["admin", "finance02", "research11"])
        source_ip = f"198.18.{story // 200}.{20 + (story % 200)}"
        destination_ip = f"198.19.{story // 200}.{20 + (story % 200)}"
        # Partial observability: some stories intentionally omit 1-2 middle stages.
        observed_steps = list(steps)
        if story % 4 == 1 and len(observed_steps) > 4:
            observed_steps.pop(2)
        if story % 7 == 0 and len(observed_steps) > 5:
            observed_steps.pop(-2)
        for k, (typ, desc, sev) in enumerate(observed_steps):
            ts = base + timedelta(minutes=k * RNG.randint(2, 7) + RNG.randint(0, 3))
            alerts.append(_attack_alert(i, ts, f"ATTACK-{incident_no:03d}", typ, desc, sev,
                                        asset, username, source_ip, destination_ip))
            i += 1
            # Benign decoy sharing one entity with the attack story.
            if k == 1 and story % 3 == 0:
                decoy = _base_alert(i, ts + timedelta(minutes=1), asset_id=asset, username=username,
                                    source_ip=source_ip, destination_ip=destination_ip, high_noise=True)
                alerts.append(decoy); i += 1

    # Fill remaining volume with realistic operational noise and high-severity decoys.
    while i <= n:
        ts = start + timedelta(minutes=RNG.randint(0, 1439), seconds=RNG.randint(0, 59))
        if i % 17 == 0:
            # High severity does not automatically mean malicious.
            a = _base_alert(i, ts, high_noise=True)
            a.description = "Approved emergency maintenance event"
            a.alert_type = "admin_maintenance"
            a.severity = "critical"
            a.maintenance_window = True
        elif i % 29 == 0:
            a = _base_alert(i, ts, high_noise=False)
            a.alert_type = "data_export"
            a.description = "Approved scheduled data export"
            a.severity = "high"
            a.maintenance_window = True
        else:
            a = _base_alert(i, ts)
        alerts.append(a); i += 1

    return sorted(alerts, key=lambda x: x.timestamp)


def write_jsonl(alerts: Iterable[Alert], path: str | Path) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a.to_dict()) + "\n")


def read_jsonl(path: str | Path) -> list[Alert]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line); d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        out.append(Alert(**d))
    return out
