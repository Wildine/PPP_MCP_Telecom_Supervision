"""
Collecteur Syslog.

Ne fait pas partie des 8 outils MCP minimum du cahier des
charges, mais reste indispensable : B.1 et B.3 identifient
explicitement la corrélation Syslog + alarmes comme le fil
conducteur central du diagnostic NOC (bloc 4).

En mode réel, lit le fichier vers lequel les équipements FRR
exportent leurs logs (rsyslog/syslog-ng configuré côté labo,
bloc 1) plutôt que d'ouvrir un port UDP 514 directement dans le
collecteur - plus simple et plus sûr à tester.
"""

import re
from typing import Any, Optional

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_text_fixture, logger

FIXTURES = fixtures_dir(__file__)

# <PRI>Mon DD HH:MM:SS HOSTNAME %FACILITY-SEVERITY-MNEMONIC: message
_SYSLOG_LINE_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"%(?P<facility>[\w-]+)-(?P<severity>\d+)-(?P<mnemonic>[\w-]+):\s+"
    r"(?P<message>.*)$"
)


def _parse_line(line: str) -> Optional[dict[str, Any]]:
    match = _SYSLOG_LINE_RE.match(line.strip())
    if not match:
        return None
    entry = match.groupdict()
    entry["severity"] = int(entry["severity"])
    return entry


def _parse_log_text(raw_text: str) -> list[dict[str, Any]]:
    entries = []
    for line in raw_text.splitlines():
        parsed = _parse_line(line)
        if parsed:
            entries.append(parsed)
    return entries


def get_recent_syslog(device_ip: str | None = None, limit: int = 50, mode: str | None = None) -> dict[str, Any]:
    """Récupère les entrées syslog récentes, filtrées par équipement (hostname) si fourni.

    Utilisé par le bloc 4 (analyse IA) pour corréler avec les
    alarmes actives. Le parsing structuré (facility/severity/
    mnemonic) est fait ici ; l'interprétation reste du côté de
    l'analyse.
    """
    simulated = config.is_simulated(mode)
    label = device_ip or "all"
    try:
        if simulated:
            raw_text = load_text_fixture(FIXTURES / "syslog_sample.log")
        else:
            with open(config.SYSLOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
                raw_text = f.read()

        entries = _parse_log_text(raw_text)
        if device_ip:
            entries = [e for e in entries if e["hostname"] == device_ip]
        entries = entries[-limit:]

        return make_response("syslog", label, {"entries": entries, "count": len(entries)}, simulated=simulated)

    except FileNotFoundError as exc:
        logger.error("get_recent_syslog: fichier introuvable (%s)", exc)
        return make_error_response("syslog", label, str(exc), simulated=simulated)
    except Exception as exc:  # noqa: BLE001
        logger.error("get_recent_syslog failed: %s", exc)
        return make_error_response("syslog", label, str(exc), simulated=simulated)
