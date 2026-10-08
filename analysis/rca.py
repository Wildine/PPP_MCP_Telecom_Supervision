"""Analyse de cause racine (cahier des charges B.7).

La RCA est une recommandation structurée, documentée par les sorties des équipements et par
les runbooks officiels. Les règles ci-dessous sont déterministes : elles désignent des causes
CANDIDATES, chacune avec ses preuves et son runbook. Le modèle les interprète et les cite ;
il ne doit rien ajouter qui n'y figure pas.

Règles (alignées sur les runbooks `interface_down` et `bgp_flap`) :
  1. une interface tombée (Syslog LINK ou état SNMP) sur un équipement de l'incident est la
     cause candidate principale ; les chutes OSPF et BGP du même équipement en sont les
     conséquences probables ;
  2. à défaut, une session BGP tombée ou non établie, sans interface en cause, relève du
     runbook `bgp_flap` ;
  3. une chute OSPF seule n'a pas de runbook : escalade à un ingénieur NOC ;
  4. un incident sans événement de panne est un retour à la normale : aucune cause à chercher.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from collector.common.schema import make_error_response, make_response

from analysis.context import read_runbook
from analysis.correlation import build_incidents

_INCIDENT_ID = re.compile(r"^INC-[0-9a-f]{8}$")
DOWN_KINDS = {"link_down", "bgp_down", "ospf_down"}


def _cause(name: str, runbook: str | None, evidence: list[str], notes: list[str]) -> dict[str, Any]:
    return {"cause": name, "runbook": runbook, "runbook_uri": f"noc://runbook/{runbook}" if runbook else None,
            "evidence": evidence, "notes": notes}


def _first_down(events: list[dict[str, Any]], device: str) -> dict[str, Any] | None:
    return next((e for e in events if e["device"] == device and e["kind"] in DOWN_KINDS), None)


def derive_causes(incident: dict[str, Any]) -> dict[str, Any]:
    """Applique les règles à un incident et retourne causes candidates, conséquences et lacunes."""
    events, findings = incident["events"], incident["findings"]
    link_events = [e for e in events if e["kind"] == "link_down"]
    iface_findings = [f for f in findings if f["type"] == "interface_down"]
    bgp_events = [e for e in events if e["kind"] == "bgp_down"]
    bgp_findings = [f for f in findings if f["type"] == "bgp_peer_down"]
    ospf_events = [e for e in events if e["kind"] == "ospf_down"]
    ospf_findings = [f for f in findings if f["type"] == "ospf_neighbor_down"]

    def ev(e: dict[str, Any]) -> str:
        return f"Syslog {e['device']} {e['time']} : {e['facility']}-{e['mnemonic']} {e['message']}"

    def fd(f: dict[str, Any]) -> str:
        return f"{f['source']} {f['device']} : {f['detail']}"

    causes: list[dict[str, Any]] = []
    consequences: list[str] = []

    if link_events or iface_findings:
        notes = []
        for device in sorted({e["device"] for e in link_events} | {f["device"] for f in iface_findings}):
            first = _first_down(events, device)
            link = next((e for e in link_events if e["device"] == device), None)
            if first and link and first["kind"] != "link_down":
                delta = int((datetime.fromisoformat(link["time"])
                             - datetime.fromisoformat(first["time"])).total_seconds())
                notes.append(f"{device} : l'événement {first['kind']} ({first['time']}) précède la chute du lien "
                             f"({link['time']}, écart {delta} s). La chronologie attendue (lien, puis OSPF, puis BGP) "
                             "n'est pas confirmée à la seconde près : à vérifier sur les horloges des équipements.")
        causes.append(_cause("Interface ou lien en panne", "interface_down",
                             [ev(e) for e in link_events] + [fd(f) for f in iface_findings], notes))
        consequences += [ev(e) for e in bgp_events + ospf_events] + [fd(f) for f in bgp_findings + ospf_findings]
    elif bgp_events or bgp_findings:
        causes.append(_cause("Instabilité ou chute d'une session BGP", "bgp_flap",
                             [ev(e) for e in bgp_events] + [fd(f) for f in bgp_findings],
                             ["Aucune interface tombée n'est observée dans cet incident."]))
        consequences += [ev(e) for e in ospf_events] + [fd(f) for f in ospf_findings]
    elif ospf_events or ospf_findings:
        causes.append(_cause("Perte d'adjacence OSPF", None,
                             [ev(e) for e in ospf_events] + [fd(f) for f in ospf_findings],
                             ["Aucun runbook ne correspond : escalade à un ingénieur NOC."]))

    recovery = not any(e["kind"] in DOWN_KINDS for e in events)
    return {"causes": causes, "consequences": consequences, "recovery": recovery}


def find_incident(incident_id: str, window_seconds: int | None = None) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    built = build_incidents(window_seconds)
    return next((i for i in built["incidents"] if i["incident_id"] == incident_id), None), built


def analyze_root_cause(incident_id: str, window_seconds: int | None = None) -> dict[str, Any]:
    """Preuves et causes candidates pour un incident issu de correlate_alarms."""
    if not _INCIDENT_ID.fullmatch(str(incident_id)):
        return make_error_response("analysis", "noc", "Identifiant d'incident invalide (format attendu : INC-xxxxxxxx).")
    try:
        incident, built = find_incident(incident_id, window_seconds)
    except Exception as exc:  # noqa: BLE001
        return make_error_response("analysis", "noc", f"Analyse impossible : {exc}")
    if incident is None:
        return make_error_response(
            "analysis", incident_id,
            "Incident introuvable avec cette fenêtre. Relance correlate_alarms avec la même fenêtre de temps.",
            simulated=built["simulated"])

    result = derive_causes(incident)
    runbooks = {}
    for cause in result["causes"]:
        name = cause["runbook"]
        if name and name not in runbooks:
            text = read_runbook(name)
            if text is None:
                cause["notes"].append(f"Le runbook {name} est introuvable.")
            runbooks[name] = text is not None

    if result["recovery"]:
        verdict = "Retour à la normale : aucun événement de panne dans cet incident."
    elif not result["causes"]:
        verdict = "Preuves insuffisantes pour désigner une cause : escalade à un ingénieur NOC."
    else:
        verdict = "Cause candidate désignée par des règles déterministes. À valider par l'opérateur."

    data = {
        "incident_id": incident_id,
        "devices_involved": incident["devices_involved"],
        "verdict": verdict,
        "candidate_causes": result["causes"],
        "probable_consequences": result["consequences"],
        "chronology": incident["events"],
        "active_findings": incident["findings"],
        "topology_links": incident["topology_links"],
        "data_gaps": built["gaps"],
        "sources": built["sources"],
        "guidance": "Conclus uniquement à partir de ces preuves et cite-les. Ne spécule pas. Une remédiation "
                    "ne vient que du runbook indiqué, que tu proposes sans l'appliquer.",
    }
    return make_response("analysis", incident_id, data, simulated=built["simulated"],
                         untrusted_fields=UNTRUSTED_FIELDS_RCA)


UNTRUSTED_FIELDS_RCA = [
    "data.chronology[].device", "data.chronology[].message", "data.active_findings[].detail",
    "data.candidate_causes[].evidence", "data.probable_consequences",
]
