"""
Collecteur PCAP - outil MCP cible : capture_pcap.

Contrainte de sécurité du cahier des charges : la capture doit
être strictement bridée en durée et en volume, pour éviter la
capture accidentelle de données sensibles et l'engorgement du
réseau. Les plafonds PCAP_MAX_DURATION_SECONDS et
PCAP_MAX_PACKETS (config.py) ne sont jamais dépassés, même si
l'appelant en demande plus.

Pré-requis pour le mode réel :
    tshark installé sur la machine (paquet wireshark-common /
    tshark), et droits suffisants pour capturer (cap_net_raw ou
    root selon l'OS).
"""

import os
import subprocess
from pathlib import Path
from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_json_fixture, logger

FIXTURES = fixtures_dir(__file__)


def _clamp(value: int, maximum: int) -> int:
    return min(value, maximum)


def _real_capture_pcap(device_ip: str, interface: str, duration_seconds: int, max_packets: int, capture_filter: str | None) -> dict[str, Any]:
    """Lance une capture tshark bridée en durée et en nombre de paquets."""
    Path(config.PCAP_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    output_file = os.path.join(config.PCAP_OUTPUT_DIR, f"{device_ip}_{interface}.pcap")

    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration_seconds}",
        "-c", str(max_packets),
        "-w", output_file,
    ]
    if capture_filter:
        cmd.extend(["-f", capture_filter])

    subprocess.run(cmd, capture_output=True, text=True, timeout=duration_seconds + 15, check=True)

    # Résumé rapide via tshark -r (comptage par protocole)
    summary_cmd = ["tshark", "-r", output_file, "-q", "-z", "io,phs"]
    summary = subprocess.run(summary_cmd, capture_output=True, text=True, timeout=30, check=True)

    return {
        "interface": interface,
        "duration_seconds": duration_seconds,
        "max_packets": max_packets,
        "file_path": output_file,
        "protocol_summary_raw": summary.stdout,
    }


def capture_pcap(
    device_ip: str,
    interface: str = "eth0",
    duration_seconds: int = 10,
    max_packets: int = 200,
    capture_filter: str | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Capture un échantillon de trafic, borné en durée et en volume.

    Les valeurs demandées sont systématiquement plafonnées par
    PCAP_MAX_DURATION_SECONDS et PCAP_MAX_PACKETS - un appelant
    ne peut jamais dépasser ces limites, même en le demandant
    explicitement.
    """
    simulated = config.is_simulated(mode)

    safe_duration = _clamp(duration_seconds, config.PCAP_MAX_DURATION_SECONDS)
    safe_packets = _clamp(max_packets, config.PCAP_MAX_PACKETS)

    try:
        if simulated:
            table = load_json_fixture(FIXTURES / "capture_summary.json")
            device_data = table.get(device_ip)
            if device_data is None:
                return make_error_response("pcap", device_ip, "Équipement inconnu dans les fixtures", simulated=True)
            return make_response("pcap", device_ip, device_data, simulated=True)

        data = _real_capture_pcap(device_ip, interface, safe_duration, safe_packets, capture_filter)
        return make_response("pcap", device_ip, data, simulated=False)

    except subprocess.CalledProcessError as exc:
        logger.error("capture_pcap failed for %s: %s", device_ip, exc.stderr)
        return make_error_response("pcap", device_ip, f"tshark error: {exc.stderr}", simulated=simulated)
    except Exception as exc:  # noqa: BLE001
        logger.error("capture_pcap failed for %s: %s", device_ip, exc)
        return make_error_response("pcap", device_ip, str(exc), simulated=simulated)
