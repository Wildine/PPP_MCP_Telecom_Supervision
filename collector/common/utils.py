"""Utilitaires partagés par tous les collecteurs."""

import json
import logging
import unicodedata
from pathlib import Path
from typing import Any

logger = logging.getLogger("collector")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def load_json_fixture(fixture_path: str | Path) -> Any:
    """Charge un fichier JSON de données simulées (fixtures/*.json)."""
    path = Path(fixture_path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_text_fixture(fixture_path: str | Path) -> str:
    """Charge un fichier texte de données simulées (ex: sortie CLI, syslog)."""
    path = Path(fixture_path)
    return path.read_text(encoding="utf-8")


def fixtures_dir(module_file: str) -> Path:
    """Retourne le dossier fixtures/ voisin du module appelant.

    Usage dans un collecteur : fixtures_dir(__file__) / "interface_stats.json"
    """
    return Path(module_file).resolve().parent / "fixtures"


# --- Données non fiables (B.6 : injection indirecte par la télémétrie) -------
TRUNCATION_MARKER = " …[tronqué]"
_ALLOWED_WHITESPACE = {"\n", "\t"}


def sanitize_untrusted_text(text: str, max_len: int = 2000) -> str:
    """Nettoie un texte venant d'un équipement (description, syslog, bannière...).

    Ce nettoyage NE rend PAS le texte digne de confiance : il retire seulement
    ce qui sert à le dissimuler (caractères de contrôle, séquences ANSI,
    caractères Unicode invisibles ou de réorientation du texte) et borne sa
    taille. Le contenu reste une donnée non fiable, à signaler comme telle
    (champs "untrusted"/"untrusted_fields" du schéma).
    """
    cleaned = []
    for char in str(text):
        if char in _ALLOWED_WHITESPACE:
            cleaned.append(char)
        elif unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp"):
            continue  # contrôle, format invisible/bidi, séparateurs de ligne/paragraphe
        else:
            cleaned.append(char)
    result = "".join(cleaned)
    if len(result) > max_len:
        result = result[:max_len] + TRUNCATION_MARKER
    return result


def sanitize_untrusted(value: Any, max_len: int = 2000) -> Any:
    """Applique sanitize_untrusted_text récursivement à toute structure JSON."""
    if isinstance(value, str):
        return sanitize_untrusted_text(value, max_len)
    if isinstance(value, dict):
        return {
            sanitize_untrusted_text(str(k), 200): sanitize_untrusted(v, max_len) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_untrusted(v, max_len) for v in value]
    return value