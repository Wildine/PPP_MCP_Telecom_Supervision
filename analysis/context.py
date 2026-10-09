"""Accès aux Resources du projet (inventaire, topologie, runbooks) pour le bloc analyse.

Source unique : `mcp_server/resources/`, la même que celle publiée par le serveur MCP.
Aucun doublon de données n'est conservé dans `analysis/`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from collector import config

REPO_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = REPO_ROOT / "mcp_server" / "resources"
RUNBOOKS_DIR = RESOURCES_DIR / "runbooks"

_RUNBOOK_NAME = re.compile(r"^[a-z0-9_]+$")


def resource_file(name: str) -> Path:
    """Fichier de ressource à utiliser : `<nom>.real.json` en mode réel s'il existe, sinon `<nom>.json`.

    Les ressources simulées (fixtures) et celles du laboratoire réel ont des adresses et des
    router-id différents : on ne les mélange pas.
    """
    if not config.is_simulated():
        real = RESOURCES_DIR / name.replace(".json", ".real.json")
        if real.is_file():
            return real
    return RESOURCES_DIR / name


def _load_json(name: str) -> dict[str, Any]:
    return json.loads(resource_file(name).read_text(encoding="utf-8"))


def inventory_devices() -> list[dict[str, Any]]:
    return list(_load_json("inventory.json").get("devices", []))


def topology_links() -> list[dict[str, Any]]:
    return list(_load_json("topology.json").get("links", []))


def read_runbook(name: str) -> str | None:
    """Texte d'un runbook, ou None s'il n'existe pas. Le nom est validé (pas de traversée de dossier)."""
    if not _RUNBOOK_NAME.fullmatch(name):
        return None
    path = RUNBOOKS_DIR / f"{name}.md"
    return path.read_text(encoding="utf-8") if path.is_file() else None


def remediation_section(runbook_text: str) -> str:
    """Extrait la section « Remédiation proposée » d'un runbook (jusqu'au titre suivant)."""
    match = re.search(r"^## Remédiation proposée[^\n]*\n(.*?)(?=^## |\Z)", runbook_text, re.S | re.M)
    return match.group(1).strip() if match else ""
