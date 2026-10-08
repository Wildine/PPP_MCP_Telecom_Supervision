"""
Détection d'anomalies de trafic - outil MCP cible : detect_anomalies.

Cahier des charges B.7 : le calcul statistique n'est PAS confié au LLM.
Les flux bruts sont agrégés par nfdump (voir analyze_netflow) ; ici, des
règles à seuils déterministes (config.ANOMALY_*) produisent des alertes
structurées, avec les chiffres qui les justifient. Le LLM (bloc 4) se
limite à interpréter, qualifier et corréler ces alertes.

Règles :
  - dominant_flow : un seul flux porte plus de ANOMALY_TOP_TALKER_RATIO des octets ;
  - small_packets : beaucoup de paquets de très petite taille moyenne
    (profil de scan ou de flood) ;
  - flow_count_spike : nombre de flux supérieur à ANOMALY_MAX_FLOWS.
"""

from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import logger, sanitize_untrusted_text
from collector.netflow.netflow_collector import analyze_netflow


def _talker_label(talker: dict[str, Any]) -> str:
    src = sanitize_untrusted_text(talker.get("src_ip", "?"), 64)
    dst = sanitize_untrusted_text(talker.get("dst_ip", "?"), 64)
    return f"{src} -> {dst}"


def compute_anomalies(flow_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Applique les règles à un résultat d'analyse NetFlow. Fonction pure, testable."""
    talkers = flow_data.get("top_talkers", [])
    total_bytes = flow_data.get("total_bytes") or sum(t.get("bytes", 0) for t in talkers)
    anomalies: list[dict[str, Any]] = []

    if total_bytes and talkers:
        top = max(talkers, key=lambda t: t.get("bytes", 0))
        ratio = top.get("bytes", 0) / total_bytes
        if ratio > config.ANOMALY_TOP_TALKER_RATIO:
            anomalies.append(
                {
                    "type": "dominant_flow",
                    "severity": "medium",
                    "description": f"Un seul flux porte {ratio:.0%} du trafic (seuil {config.ANOMALY_TOP_TALKER_RATIO:.0%})",
                    "evidence": {"flow": _talker_label(top), "bytes": top.get("bytes", 0), "ratio": round(ratio, 3)},
                }
            )

    for talker in talkers:
        packets, size = talker.get("packets", 0), talker.get("bytes", 0)
        if packets >= config.ANOMALY_MIN_PACKETS:
            avg = size / packets
            if avg < config.ANOMALY_MIN_AVG_PACKET_BYTES:
                anomalies.append(
                    {
                        "type": "small_packets",
                        "severity": "high",
                        "description": f"{packets} paquets de {avg:.0f} octets en moyenne (seuil {config.ANOMALY_MIN_AVG_PACKET_BYTES})",
                        "evidence": {"flow": _talker_label(talker), "packets": packets, "avg_packet_bytes": round(avg, 1)},
                    }
                )

    flows = flow_data.get("total_flows", 0)
    if flows > config.ANOMALY_MAX_FLOWS:
        anomalies.append(
            {
                "type": "flow_count_spike",
                "severity": "high",
                "description": f"{flows} flux observés (seuil {config.ANOMALY_MAX_FLOWS})",
                "evidence": {"total_flows": flows},
            }
        )
    return anomalies


def detect_anomalies(device_ip: str, window: str = "last_5_minutes", mode: str | None = None) -> dict[str, Any]:
    """Détecte des anomalies de trafic par règles déterministes sur les flux NetFlow."""
    simulated = config.is_simulated(mode)
    try:
        flows = analyze_netflow(device_ip, window=window, mode=mode)
        if flows["status"] != "ok":
            return make_error_response("netflow", device_ip, flows["error"] or "analyse NetFlow impossible", simulated=simulated)

        anomalies = compute_anomalies(flows["data"])
        data = {
            "window": window,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "thresholds": {
                "top_talker_ratio": config.ANOMALY_TOP_TALKER_RATIO,
                "min_avg_packet_bytes": config.ANOMALY_MIN_AVG_PACKET_BYTES,
                "min_packets": config.ANOMALY_MIN_PACKETS,
                "max_flows": config.ANOMALY_MAX_FLOWS,
            },
        }
        return make_response(
            "netflow", device_ip, data, simulated=simulated,
            untrusted_fields=["data.anomalies[].evidence.flow"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("detect_anomalies failed for %s: %s", device_ip, exc)
        return make_error_response("netflow", device_ip, str(exc), simulated=simulated)
