"""Corrélation multi-sources (cahier des charges B.3, B.5).

Sources, toutes lues par le collecteur (lecture seule) :
  - Syslog (`get_recent_syslog`) : chronologie des événements ;
  - SNMP (`get_interface_stats`) : état des interfaces ;
  - CLI (`get_bgp_peers`, `get_ospf_neighbors`) : voisins BGP et OSPF.

Les « alarmes actives » sont calculées ici par des règles à seuils déterministes sur l'état
courant. Aucun calcul statistique n'est confié au modèle. Les incidents candidats regroupent
les événements Syslog proches dans le temps ; leur identifiant est dérivé du contenu des
événements, donc stable d'un appel à l'autre (aucun état n'est conservé en mémoire).

Données non fiables (B.6) : tout texte venu des équipements est nettoyé puis signalé dans
`untrusted_fields`.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any

from collector import config
from collector.cli.cli_collector import get_bgp_peers, get_ospf_neighbors
from collector.common.schema import make_error_response, make_response
from collector.common.utils import sanitize_untrusted_text
from collector.snmp.snmp_collector import get_interface_stats
from collector.syslog.syslog_collector import get_recent_syslog

from analysis.context import inventory_devices, topology_links

DEFAULT_WINDOW_SECONDS = 120
MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS = 10, 3600
SYSLOG_LIMIT = 200

UNTRUSTED_FIELDS = [
    "data.incidents[].events[].device",
    "data.incidents[].events[].message",
    "data.incidents[].findings[].detail",
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_TS = re.compile(r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$")
_ROUTER_ID = re.compile(r"router identifier\s+(\d+\.\d+\.\d+\.\d+)", re.I)


def clamp_window(window_seconds: int | None) -> int:
    """Borne la fenêtre fournie par le modèle."""
    try:
        value = int(window_seconds) if window_seconds is not None else DEFAULT_WINDOW_SECONDS
    except (TypeError, ValueError):
        value = DEFAULT_WINDOW_SECONDS
    return max(MIN_WINDOW_SECONDS, min(MAX_WINDOW_SECONDS, value))


def _parse_ts(ts: str, year: int) -> datetime | None:
    match = _TS.match(ts.strip())
    if not match or match["mon"].title() not in _MONTHS:
        return None
    try:
        return datetime(year, _MONTHS[match["mon"].title()], int(match["day"]),
                        int(match["h"]), int(match["m"]), int(match["s"]))
    except ValueError:
        return None


def classify(facility: str, mnemonic: str, message: str) -> str:
    """Type d'événement, par expressions régulières sur le Syslog structuré."""
    msg = message.lower()
    if facility == "LINK" and mnemonic == "UPDOWN":
        if re.search(r"state to down", msg):
            return "link_down"
        if re.search(r"state to up", msg):
            return "link_up"
    elif facility == "BGP" and mnemonic == "ADJCHANGE":
        if re.search(r"\bdown\b", msg):
            return "bgp_down"
        if re.search(r"\bup\b", msg):
            return "bgp_up"
    elif facility == "OSPF" and mnemonic == "ADJCHG":
        if re.search(r"to down", msg):
            return "ospf_down"
        if re.search(r"to full", msg):
            return "ospf_up"
    return "other"


def _clean(value: Any, max_len: int = 300) -> str:
    return sanitize_untrusted_text(str(value), max_len)


def selected_devices(devices: list[str] | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Équipements à analyser : ceux de l'inventaire, restreints à la liste du modèle si elle est fournie."""
    inventory = inventory_devices()
    if not devices:
        return inventory, []
    wanted = {str(d).lower() for d in devices}
    chosen = [d for d in inventory if str(d.get("name", "")).lower() in wanted]
    known = {str(d.get("name", "")).lower() for d in inventory}
    gaps = [f"Équipement ignoré (absent de l'inventaire) : {_clean(d, 50)}" for d in devices
            if str(d).lower() not in known]
    return chosen, gaps


def _address(device: dict[str, Any], simulated: bool) -> str:
    """Adresse à donner au collecteur : le nom en simulation, l'IP de gestion ou le router-id en réel."""
    if simulated:
        return str(device["name"])
    return str(device.get("mgmt_ip") or device.get("router_id") or device["name"])


def collect_events(year: int | None = None) -> tuple[list[dict[str, Any]], list[str], dict[str, Any] | None]:
    """Événements Syslog (tous équipements), triés par heure."""
    year = year or datetime.now().year
    response = get_recent_syslog(None, SYSLOG_LIMIT)
    if response["status"] != "ok":
        return [], [f"Syslog indisponible : {response['error']}"], response
    events, gaps = [], []
    for entry in response["data"]["entries"]:
        when = _parse_ts(str(entry.get("timestamp", "")), year)
        if when is None:
            gaps.append("Événement Syslog ignoré : horodatage illisible.")
            continue
        facility, mnemonic = str(entry.get("facility", "")), str(entry.get("mnemonic", ""))
        message = _clean(entry.get("message", ""))
        events.append({
            "time": when.isoformat(),
            "device": _clean(entry.get("hostname", ""), 100),
            "facility": _clean(facility, 30),
            "mnemonic": _clean(mnemonic, 30),
            "severity": entry.get("severity"),
            "kind": classify(facility, mnemonic, message),
            "message": message,
        })
    events.sort(key=lambda e: (e["time"], e["device"], e["message"]))
    return events, gaps, response


def collect_findings(devices: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Alarmes actives déduites de l'état courant (SNMP interfaces, voisins BGP et OSPF).

    Retourne (constats, lacunes de données, sources interrogées).
    """
    findings: list[dict[str, Any]] = []
    gaps: list[str] = []
    sources: list[dict[str, Any]] = []

    def record(tool: str, device: str, response: dict[str, Any]) -> None:
        sources.append({"tool": tool, "device": device, "status": response["status"],
                        "simulated": response["simulated"]})

    for dev in devices:
        name = str(dev["name"])
        address = _address(dev, config.is_simulated())

        iface = get_interface_stats(address)
        record("get_interface_stats", name, iface)
        if iface["status"] != "ok":
            gaps.append(f"{name} : statistiques d'interfaces indisponibles ({_clean(iface['error'], 120)}).")
        elif "raw_iftable" in iface["data"]:
            gaps.append(f"{name} : table d'interfaces brute (mode réel), état non interprété.")
        else:
            for if_name, stats in iface["data"].items():
                admin, oper = stats.get("if_admin_status"), stats.get("if_oper_status")
                errors = int(stats.get("in_errors", 0)) + int(stats.get("out_errors", 0))
                if admin == "up" and oper != "up":
                    findings.append({
                        "device": name, "type": "interface_down", "severity": "critical",
                        "detail": f"Interface {_clean(if_name, 60)} : état opérationnel {_clean(oper, 20)} "
                                  f"(administrativement up), erreurs en/sortie : "
                                  f"{stats.get('in_errors', 0)}/{stats.get('out_errors', 0)}.",
                        "source": "get_interface_stats",
                    })
                elif oper == "up" and errors > 0:
                    findings.append({
                        "device": name, "type": "interface_errors", "severity": "warning",
                        "detail": f"Interface {_clean(if_name, 60)} up avec {errors} erreurs cumulées.",
                        "source": "get_interface_stats",
                    })

        bgp = get_bgp_peers(address)
        record("get_bgp_peers", name, bgp)
        if bgp["status"] != "ok":
            gaps.append(f"{name} : voisins BGP indisponibles ({_clean(bgp['error'], 120)}).")
            continue
        # La sortie CLI ne porte pas le nom de l'équipement : on la rattache à un équipement
        # seulement si son router-id correspond à celui de l'inventaire.
        identified = _ROUTER_ID.search(bgp["data"].get("raw", ""))
        if not identified or identified.group(1) != dev.get("router_id"):
            gaps.append(f"{name} : sortie CLI non attribuée (router-id absent ou différent de l'inventaire), "
                        "BGP et OSPF non évalués.")
            continue
        for peer in bgp["data"]["peers"]:
            state = str(peer.get("state_or_prefixes", ""))
            if not state.isdigit():
                findings.append({
                    "device": name, "type": "bgp_peer_down", "severity": "critical",
                    "detail": f"Voisin BGP {_clean(peer.get('neighbor'), 40)} (AS {peer.get('remote_as')}) : "
                              f"état {_clean(state, 30)}, Up/Down {_clean(peer.get('up_down'), 30)}.",
                    "source": "get_bgp_peers",
                })
        ospf = get_ospf_neighbors(address)
        record("get_ospf_neighbors", name, ospf)
        if ospf["status"] != "ok":
            gaps.append(f"{name} : voisins OSPF indisponibles ({_clean(ospf['error'], 120)}).")
            continue
        for nbr in ospf["data"]["neighbors"]:
            state = str(nbr.get("state", ""))
            # Full est l'état normal ; 2-Way entre routeurs DROTHER est normal aussi.
            if not (state.startswith("Full") or "DROTHER" in state):
                findings.append({
                    "device": name, "type": "ospf_neighbor_down", "severity": "major",
                    "detail": f"Voisin OSPF {_clean(nbr.get('neighbor_id'), 40)} : état {_clean(state, 30)}.",
                    "source": "get_ospf_neighbors",
                })
    return findings, gaps, sources


def cluster_events(events: list[dict[str, Any]], window_seconds: int) -> list[list[dict[str, Any]]]:
    """Regroupe les événements : un nouvel incident commence quand l'écart avec l'événement précédent dépasse la fenêtre."""
    clusters: list[list[dict[str, Any]]] = []
    last: datetime | None = None
    for event in events:
        when = datetime.fromisoformat(event["time"])
        if last is None or (when - last).total_seconds() > window_seconds:
            clusters.append([])
        clusters[-1].append(event)
        last = when
    return clusters


def incident_id(events: list[dict[str, Any]]) -> str:
    """Identifiant déterministe, dérivé uniquement du contenu des événements."""
    digest = hashlib.sha1("\n".join(
        f"{e['time']}|{e['device']}|{e['facility']}|{e['mnemonic']}|{e['kind']}" for e in events
    ).encode("utf-8")).hexdigest()
    return f"INC-{digest[:8]}"


def build_incidents(window_seconds: int | None = None, devices: list[str] | None = None) -> dict[str, Any]:
    """Construit les incidents candidats. Retourne un dict interne (voir correlate_alarms pour le format public)."""
    window = clamp_window(window_seconds)
    chosen, gaps = selected_devices(devices)
    names = {str(d["name"]) for d in chosen}

    events, event_gaps, syslog_resp = collect_events()
    gaps += event_gaps
    events = [e for e in events if e["device"] in names]
    findings, finding_gaps, sources = collect_findings(chosen)
    gaps += finding_gaps
    if syslog_resp is not None:
        sources.append({"tool": "get_recent_syslog", "device": "all", "status": syslog_resp["status"],
                        "simulated": syslog_resp["simulated"]})

    links = topology_links()
    incidents = []
    for group in cluster_events(events, window):
        involved = sorted({e["device"] for e in group})
        incidents.append({
            "incident_id": incident_id(group),
            "start": group[0]["time"],
            "end": group[-1]["time"],
            "devices_involved": involved,
            "event_count": len(group),
            "events": group,
            "findings": [f for f in findings if f["device"] in involved],
            "topology_links": [l for l in links if l.get("source") in involved or l.get("target") in involved],
        })
    return {"window_seconds": window, "incidents": incidents, "gaps": gaps, "sources": sources,
            "simulated": any(s["simulated"] for s in sources) if sources else True}


def correlate_alarms(window_seconds: int | None = None, devices: list[str] | None = None) -> dict[str, Any]:
    """Regroupe les événements Syslog et les alarmes actives en incidents candidats."""
    try:
        built = build_incidents(window_seconds, devices)
    except Exception as exc:  # noqa: BLE001 - ne jamais laisser remonter une exception brute
        return make_error_response("analysis", "noc", f"Corrélation impossible : {exc}")
    data = {
        "window_seconds": built["window_seconds"],
        "incident_count": len(built["incidents"]),
        "incidents": built["incidents"],
        "data_gaps": built["gaps"],
        "sources": built["sources"],
        "note": "Regroupement déterministe par proximité dans le temps. Un incident candidat n'est pas "
                "confirmé : lance analyze_root_cause pour obtenir les preuves et les causes candidates.",
    }
    return make_response("analysis", "noc", data, simulated=built["simulated"], untrusted_fields=UNTRUSTED_FIELDS)
