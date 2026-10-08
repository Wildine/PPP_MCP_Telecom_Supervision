"""Rapport d'incident (cahier des charges B.5, B.8).

Le rapport est assemblé à partir de l'analyse de cause racine et du runbook retenu par les
règles de `analysis.rca`, pas à partir d'un texte rédigé par le modèle. La remédiation est une
PROPOSITION : le serveur ne dispose d'aucun outil qui modifie un équipement, et le rapport reste
« en attente de validation humaine ».
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from collector.common.schema import make_error_response, make_response

from analysis.context import read_runbook, remediation_section
from analysis.rca import UNTRUSTED_FIELDS_RCA, analyze_root_cause

UNTRUSTED_FIELDS_REPORT = [
    "data.chronology[].device", "data.chronology[].message", "data.evidence",
    "data.probable_consequences", "data.active_findings[].detail",
]


def generate_incident_report(incident_id: str, window_seconds: int | None = None) -> dict[str, Any]:
    """Rapport structuré pour un incident : chronologie, preuves, cause, runbook, validation."""
    rca = analyze_root_cause(incident_id, window_seconds)
    if rca["status"] != "ok":
        return rca
    d = rca["data"]
    primary = d["candidate_causes"][0] if d["candidate_causes"] else None

    runbook = None
    if primary and primary["runbook"]:
        text = read_runbook(primary["runbook"])
        if text is not None:
            runbook = {
                "name": primary["runbook"],
                "uri": primary["runbook_uri"],
                "proposed_remediation": remediation_section(text),
            }

    if runbook:
        action = "Remédiation proposée par le runbook, à valider et exécuter par un opérateur (voir proposed_remediation)."
    else:
        action = "Aucune remédiation automatique : remonter à un ingénieur NOC."

    report = {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": f"Incident impliquant {', '.join(d['devices_involved'])} ({len(d['chronology'])} événements).",
        "verdict": d["verdict"],
        "devices_involved": d["devices_involved"],
        "chronology": d["chronology"],
        "root_cause": primary["cause"] if primary else None,
        "evidence": primary["evidence"] if primary else [],
        "probable_consequences": d["probable_consequences"],
        "active_findings": d["active_findings"],
        "notes": primary["notes"] if primary else [],
        "runbook": runbook,
        "recommended_action": action,
        "data_gaps": d["data_gaps"],
        "sources": d["sources"],
        "validation": {"status": "EN_ATTENTE_DE_VALIDATION_HUMAINE", "applied_by_ai": False},
    }
    return make_response("analysis", incident_id, report, simulated=rca["simulated"],
                         untrusted_fields=UNTRUSTED_FIELDS_REPORT)
