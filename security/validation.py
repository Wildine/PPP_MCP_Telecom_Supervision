"""Détection et neutralisation des injections de prompt dans les sorties d'outils.

Complète collector.common.utils.sanitize_untrusted_text (qui retire les
caractères invisibles et borne la taille) : ici on repère les PHRASES
d'injection ("ignore previous instructions"...) dans le contenu venant des
équipements et on les remplace par un marqueur. La réponse reçoit une clé
`security` indiquant ce qui a été détecté. Le contenu reste de la donnée non
fiable dans tous les cas.
"""

import re
from typing import Any

MARKER = "[CONTENU_SUSPECT_NEUTRALISE]"

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"ignore\s+(toutes\s+)?(tes|les|vos)\s+instructions?\s+pr[ée]c[ée]dentes?",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"you\s+are\s+now\s+(a|an|the|in)\b",
    r"tu\s+es\s+maintenant\s+(un|une|le|la|en)\b",
    r"new\s+instructions?\s*:",
    r"nouvelles?\s+instructions?\s*:",
    r"^\s*(system|assistant)\s*:",
    r"\bact\s+as\s+(a|an|the)\b",
    r"<\|[^|>]{0,40}\|>",
    r"###\s*(system|instruction)",
    r"forget\s+(everything|all)\b",
    r"oublie\s+(tout|tes\s+instructions)",
    r"execute\s+the\s+following\s+command",
    r"ex[ée]cute\s+la\s+commande\s+suivante",
    r"(reveal|print|show|r[ée]v[èe]le|affiche)\s+(your|the|ton|le)\s+(system\s+prompt|prompt\s+syst[èe]me)",
]
_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in INJECTION_PATTERNS]


def neutralize_text(text: str) -> tuple[str, list[str]]:
    """Retourne (texte nettoyé, motifs détectés)."""
    flags = []
    for pattern in _COMPILED:
        if pattern.search(text):
            flags.append(pattern.pattern)
            text = pattern.sub(MARKER, text)
    return text, flags


def neutralize(value: Any) -> tuple[Any, list[str]]:
    """Applique neutralize_text à toutes les chaînes d'une structure JSON."""
    if isinstance(value, str):
        return neutralize_text(value)
    if isinstance(value, dict):
        out, flags = {}, []
        for k, v in value.items():
            out[k], f = neutralize(v)
            flags += f
        return out, flags
    if isinstance(value, (list, tuple)):
        items, flags = [], []
        for v in value:
            n, f = neutralize(v)
            items.append(n)
            flags += f
        return items, flags
    return value, []
