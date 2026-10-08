"""
Format de sortie unifié pour tous les collecteurs (SNMP, NETCONF,
CLI, NetFlow, PCAP, Syslog).

Toute fonction de collecte, quel que soit son protocole, doit
retourner un dict construit via make_response() ou
make_error_response(). Ce contrat est ce qui permet à l'équipe
MCP (bloc 3) et à l'équipe analyse IA (bloc 4) de consommer les
données sans se soucier du protocole d'origine.

Structure garantie :
{
    "status": "ok" | "error",
    "source": "snmp" | "netconf" | "cli" | "netflow" | "pcap" | "syslog",
    "device": "<ip ou nom de l'équipement>",
    "data": {...} | None,
    "error": "<message>" | None,
    "timestamp": "2026-09-14T10:00:00+00:00",
    "simulated": true | false,
    "untrusted": true,
    "untrusted_fields": ["data.raw", ...]
}

Données non fiables (cahier des charges B.6) : tout ce qui vient d'un
équipement (descriptions d'interface, messages syslog, bannières, sortie
CLI brute, XML NETCONF...) peut contenir une injection de prompt.
  - "untrusted" vaut toujours True : le contenu de la réponse est de la
    DONNÉE, jamais des instructions.
  - "untrusted_fields" liste les chemins des champs texte libres, ceux où
    une injection est le plus probable.
Le serveur MCP (bloc 3) doit conserver ces marqueurs, et exiger une
validation humaine avant toute action déclenchée par ces contenus.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from collector.common.utils import sanitize_untrusted_text


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_response(
    source: str,
    device: str,
    data: dict[str, Any],
    simulated: bool = False,
    untrusted_fields: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Construit une réponse de succès standardisée.

    `untrusted_fields` : chemins des champs texte libres venant de
    l'équipement (ex: "data.raw"). La réponse est de toute façon
    marquée `untrusted: True`.
    """
    return {
        "status": "ok",
        "source": source,
        "device": device,
        "data": data,
        "error": None,
        "timestamp": _now_iso(),
        "simulated": simulated,
        "untrusted": True,
        "untrusted_fields": list(untrusted_fields or []),
    }


def make_error_response(
    source: str,
    device: str,
    error: str,
    simulated: bool = False,
) -> dict[str, Any]:
    """Construit une réponse d'erreur standardisée.

    À utiliser systématiquement en cas d'exception réseau,
    de timeout, ou de commande refusée (ex: hors liste blanche) -
    ne jamais laisser une exception remonter brute jusqu'au
    serveur MCP.
    """
    # Un message d'exception peut citer du texte renvoyé par l'équipement.
    return {
        "status": "error",
        "source": source,
        "device": device,
        "data": None,
        "error": sanitize_untrusted_text(error, 500),
        "timestamp": _now_iso(),
        "simulated": simulated,
        "untrusted": True,
        "untrusted_fields": ["error"],
    }


def validate_response(response: dict[str, Any]) -> bool:
    """Vérifie qu'un dict respecte le contrat de sortie attendu.

    Utile dans les tests unitaires de chaque collecteur.
    """
    required_keys = {
        "status", "source", "device", "data", "error", "timestamp", "simulated",
        "untrusted", "untrusted_fields",
    }
    if not required_keys.issubset(response.keys()):
        return False
    if response["untrusted"] is not True or not isinstance(response["untrusted_fields"], list):
        return False
    if response["status"] not in ("ok", "error"):
        return False
    if response["status"] == "ok" and response["data"] is None:
        return False
    if response["status"] == "error" and response["error"] is None:
        return False
    return True