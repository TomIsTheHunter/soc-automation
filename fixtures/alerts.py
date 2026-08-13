from typing import Any

from app.enrichment.table import SYNTHETIC_HASH_BENIGN, SYNTHETIC_HASH_MALICIOUS

HIGH_RISK_ALERT: dict[str, Any] = {
    "alert_id": "synthetic-high-001",
    "timestamp": "2026-01-15T12:00:00Z",
    "hostname": "workstation-07",
    "username": "synthetic.user",
    "severity": "HIGH",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -EncodedCommand synthetic-payload",
    "source_ip": "192.0.2.25",
    "destination_ip": "198.51.100.10",
    "file_hash": SYNTHETIC_HASH_MALICIOUS,
    "detection_description": (
        "Synthetic encoded PowerShell command contacted a known synthetic C2 indicator."
    ),
    "source": "crowdstrike-style-synthetic",
}

BENIGN_ALERT: dict[str, Any] = {
    "alert_id": "synthetic-benign-001",
    "timestamp": "2026-01-15T12:05:00Z",
    "hostname": "workstation-08",
    "username": "synthetic.user",
    "severity": "LOW",
    "process_name": "notepad.exe",
    "command_line": "notepad.exe C:\\Users\\synthetic.user\\Documents\\notes.txt",
    "source_ip": "192.0.2.26",
    "destination_ip": "203.0.113.10",
    "file_hash": SYNTHETIC_HASH_BENIGN,
    "detection_description": ("Synthetic benign document activity."),
    "source": "crowdstrike-style-synthetic",
}

AMBIGUOUS_ALERT: dict[str, Any] = {
    "alert_id": "synthetic-ambiguous-001",
    "timestamp": "2026-01-15T12:10:00Z",
    "hostname": "workstation-09",
    "username": "synthetic.user",
    "severity": "HIGH",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -File synthetic-maintenance.ps1",
    "source_ip": "192.0.2.27",
    "destination_ip": "203.0.113.10",
    "detection_description": (
        "Synthetic mixed-signal PowerShell activity with benign destination enrichment."
    ),
    "source": "crowdstrike-style-synthetic",
}
