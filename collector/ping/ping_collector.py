"""
Collecteur de connectivité - outils MCP cibles : ping_host, traceroute.

Sécurité : la cible est validée AVANT tout appel système (pas de shell,
liste d'arguments, rejet des cibles commençant par "-" ou contenant des
caractères hors hostname/IP). Le nombre de paquets et de sauts est
plafonné (PING_MAX_COUNT, TRACEROUTE_MAX_HOPS), quoi que demande l'appelant.

Pré-requis pour le mode réel : binaires `ping` et `traceroute` installés.
"""

import re
import subprocess
from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_json_fixture, logger

FIXTURES = fixtures_dir(__file__)

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:\-]{0,252}$")
_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
_RTT_RE = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)")
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_ADDR_RE = re.compile(r"\(?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\)?")
_MS_RE = re.compile(r"([\d.]+) ms")


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise ValueError("Cible invalide (IP ou nom d'hôte attendu)")
    return host


def _real_ping(host: str, count: int) -> dict[str, Any]:
    cmd = ["ping", "-c", str(count), "-W", str(config.PING_TIMEOUT_SECONDS), host]
    timeout = count * (config.PING_TIMEOUT_SECONDS + 1) + 5
    # returncode 1 = pertes totales : résultat valide, pas une erreur
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ping a échoué (code {result.returncode})")
    out = result.stdout
    loss = _LOSS_RE.search(out)
    rtt = _RTT_RE.search(out)
    loss_pct = float(loss.group(1)) if loss else 100.0
    return {
        "packets_sent": count,
        "packets_received": round(count * (100 - loss_pct) / 100),
        "loss_percent": loss_pct,
        "rtt_min_ms": float(rtt.group(1)) if rtt else None,
        "rtt_avg_ms": float(rtt.group(2)) if rtt else None,
        "rtt_max_ms": float(rtt.group(3)) if rtt else None,
    }


def _parse_traceroute(output: str, target: str) -> dict[str, Any]:
    hops = []
    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        addr = _ADDR_RE.search(rest) if "*" not in rest.split()[0:1] else None
        ms = _MS_RE.search(rest)
        hops.append(
            {
                "hop": int(m.group(1)),
                "address": addr.group(1) if addr else None,
                "rtt_ms": float(ms.group(1)) if ms else None,
            }
        )
    reached = bool(hops) and hops[-1]["address"] == target
    return {"reached": reached, "hops": hops}


def _real_traceroute(host: str) -> dict[str, Any]:
    cmd = [
        "traceroute", "-n",
        "-m", str(config.TRACEROUTE_MAX_HOPS),
        "-w", str(config.TRACEROUTE_TIMEOUT_SECONDS),
        host,
    ]
    timeout = config.TRACEROUTE_MAX_HOPS * (config.TRACEROUTE_TIMEOUT_SECONDS * 3 + 1) + 5
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    return _parse_traceroute(result.stdout, host)


def ping_host(host: str, count: int = 4, mode: str | None = None) -> dict[str, Any]:
    """Teste l'accessibilité d'un hôte (ICMP). `count` est plafonné à PING_MAX_COUNT."""
    simulated = config.is_simulated(mode)
    try:
        host = _validate_host(host)
        count = max(1, min(int(count), config.PING_MAX_COUNT))
        if simulated:
            data = load_json_fixture(FIXTURES / "ping_results.json").get(host)
            if data is None:
                return make_error_response("ping", host, "Hôte inconnu dans les fixtures", simulated=True)
            return make_response("ping", host, {**data, "reachable": data["packets_received"] > 0}, simulated=True)

        data = _real_ping(host, count)
        return make_response("ping", host, {**data, "reachable": data["packets_received"] > 0}, simulated=False)
    except Exception as exc:  # noqa: BLE001
        logger.error("ping_host failed for %s: %s", host, exc)
        return make_error_response("ping", str(host), str(exc), simulated=simulated)


def traceroute(host: str, mode: str | None = None) -> dict[str, Any]:
    """Trace le chemin vers un hôte. Nombre de sauts plafonné à TRACEROUTE_MAX_HOPS."""
    simulated = config.is_simulated(mode)
    try:
        host = _validate_host(host)
        if simulated:
            data = load_json_fixture(FIXTURES / "traceroute.json").get(host)
            if data is None:
                return make_error_response("ping", host, "Hôte inconnu dans les fixtures", simulated=True)
            return make_response("ping", host, data, simulated=True)

        return make_response("ping", host, _real_traceroute(host), simulated=False)
    except Exception as exc:  # noqa: BLE001
        logger.error("traceroute failed for %s: %s", host, exc)
        return make_error_response("ping", str(host), str(exc), simulated=simulated)
