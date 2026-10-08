"""
Collecteur QoS - outil MCP cible : qos_stats.

Lecture seule via SNMP (SNMPv3). En mode réel, lit deux colonnes de la MIB
QoS (paquets et paquets rejetés, OIDs configurables dans config.py) et
regroupe les valeurs par index de classe/interface. Les noms de classes
sont des textes venant de l'équipement : ils sont nettoyés et signalés
comme non fiables.
"""

from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_json_fixture, logger, sanitize_untrusted
from collector.snmp.snmp_collector import _real_snmp_walk

FIXTURES = fixtures_dir(__file__)


def _real_qos_stats(device_ip: str) -> dict[str, Any]:
    pkts = _real_snmp_walk(device_ip, config.QOS_PKTS_OID)
    drops = _real_snmp_walk(device_ip, config.QOS_DROPS_OID)
    entries = []
    for oid, value in pkts.items():
        index = oid[len(config.QOS_PKTS_OID):].lstrip(".")
        total = int(value) if str(value).isdigit() else 0
        dropped_raw = drops.get(f"{config.QOS_DROPS_OID}.{index}", "0")
        dropped = int(dropped_raw) if str(dropped_raw).isdigit() else 0
        entries.append(
            {
                "index": index,
                "packets": total,
                "drops": dropped,
                "drop_percent": round(100 * dropped / total, 2) if total else 0.0,
            }
        )
    return {"entries": entries}


def qos_stats(device_ip: str, interface: str | None = None, mode: str | None = None) -> dict[str, Any]:
    """Statistiques QoS (paquets, rejets par classe) d'un équipement."""
    simulated = config.is_simulated(mode)
    try:
        if simulated:
            device_data = load_json_fixture(FIXTURES / "qos_stats.json").get(device_ip)
            if device_data is None:
                return make_error_response("snmp", device_ip, "Équipement inconnu dans les fixtures", simulated=True)
            if interface:
                if interface not in device_data:
                    return make_error_response("snmp", device_ip, f"Interface {interface} introuvable", simulated=True)
                device_data = {interface: device_data[interface]}
            return make_response(
                "snmp", device_ip, sanitize_untrusted(device_data),
                simulated=True, untrusted_fields=["data.*.classes[].class"],
            )

        data = _real_qos_stats(device_ip)
        return make_response("snmp", device_ip, data, simulated=False)
    except Exception as exc:  # noqa: BLE001
        logger.error("qos_stats failed for %s: %s", device_ip, exc)
        return make_error_response("snmp", device_ip, str(exc), simulated=simulated)
