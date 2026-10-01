from __future__ import annotations
from datetime import datetime, timezone, timedelta
from .models import Alert

def attack_replay():
    t=datetime.now(timezone.utc); specs=[
        ("SIM-01","IAM","failed_login","Repeated failed login", "medium"),
        ("SIM-02","IAM","successful_login","Successful login after failures", "high"),
        ("SIM-03","EDR","powershell","Encoded PowerShell execution", "high"),
        ("SIM-04","EDR","credential_dump","LSASS credential access", "critical"),
        ("SIM-05","NETWORK","internal_scan","Internal host discovery spike", "medium"),
        ("SIM-06","EDR","remote_service","Remote service execution", "high"),
        ("SIM-07","DATA","large_egress","Large outbound transfer", "critical"),
    ]
    out=[]
    for i,(aid,src,typ,desc,sev) in enumerate(specs):
        out.append(Alert(aid,t+timedelta(minutes=i),src,typ,desc,sev,.96,"PAY-DB" if i>=6 else "ADMIN-01","Database" if i>=6 else "Endpoint",100 if i>=6 else 94,hostname="PAY-DB" if i>=6 else "ADMIN-01",username="admin",source_ip="10.10.1.14",destination_ip="203.0.113.10" if i>=6 else "10.10.2.18",process="powershell.exe" if typ=="powershell" else "",command_line="powershell -enc REDACTED" if typ=="powershell" else "",authentication_result="success" if typ=="successful_login" else "",ground_truth_incident_id="SIM-ATTACK",ground_truth_label=1))
    return out
