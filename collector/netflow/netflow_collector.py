"""
Collecteur NetFlow - outil MCP cible : analyze_netflow.

Le calcul statistique brut est délégué à nfdump (outil
déterministe), jamais au LLM - le rôle de l'IA (bloc 4) se
limite à interpréter le résultat structuré qu'on lui fournit ici.

Pré-requis pour le mode réel :
    nfdump installé sur la machine et fichiers de flux
    disponibles dans NETFLOW_DATA_DIR.
"""

import subprocess
from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_json_fixture, logger

FIXTURES = fixtures_dir(__file__)


def _real_analyze_netflow(device_ip: str, window: str, top_n: int) -> dict[str, Any]:
    """Exécute nfdump en subprocess et parse la sortie.

    `window` est un filtre temporel nfdump (ex: "-t 2026/09/14.10:00:00-2026/09/14.10:05:00").
    On utilise ici -a (agrégation) et -n top_n pour les top talkers,
    format de sortie CSV (-o csv) pour un parsing simple.
    """
    cmd = [
        config.NFDUMP_BIN,
        "-R", config.NETFLOW_DATA_DIR,
        "-s", "record/bytes",
        "-n", str(top_n),
        "-o", "csv",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)

    top_talkers = []
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith("ts,")]
    for line in lines[:top_n]:
        fields = line.split(",")
        if len(fields) >= 8:
            top_talkers.append(
                {
                    "src_ip": fields[3],
                    "dst_ip": fields[5],
                    "protocol": fields[7],
                    "bytes": int(fields[-2]) if fields[-2].isdigit() else 0,
                    "packets": int(fields[-3]) if fields[-3].isdigit() else 0,
                }
            )

    return {"window": window, "top_talkers": top_talkers, "raw_stdout": result.stdout}


def analyze_netflow(device_ip: str, window: str = "last_5_minutes", top_n: int = 10, mode: str | None = None) -> dict[str, Any]:
    """Retourne un résumé des flux (top talkers, volumes) pour un équipement."""
    simulated = config.is_simulated(mode)
    try:
        if simulated:
            table = load_json_fixture(FIXTURES / "netflow_sample.json")
            device_data = table.get(device_ip)
            if device_data is None:
                return make_error_response("netflow", device_ip, "Équipement inconnu dans les fixtures", simulated=True)
            return make_response("netflow", device_ip, device_data, simulated=True)

        data = _real_analyze_netflow(device_ip, window, top_n)
        return make_response("netflow", device_ip, data, simulated=False)

    except subprocess.CalledProcessError as exc:
        logger.error("analyze_netflow (nfdump) failed for %s: %s", device_ip, exc.stderr)
        return make_error_response("netflow", device_ip, f"nfdump error: {exc.stderr}", simulated=simulated)
    except Exception as exc:  # noqa: BLE001
        logger.error("analyze_netflow failed for %s: %s", device_ip, exc)
        return make_error_response("netflow", device_ip, str(exc), simulated=simulated)
