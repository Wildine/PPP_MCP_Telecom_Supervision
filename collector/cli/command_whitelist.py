"""
Liste blanche des commandes CLI autorisées.

Le cahier des charges impose que les accès CLI via netmiko
soient bridés à des commandes d'affichage ("show") uniquement.
Toute commande hors de cette liste doit être rejetée AVANT
d'être envoyée à l'équipement - jamais après coup.
"""

import re

# Commandes autorisées : correspondance EXACTE (lecture seule uniquement).
# Pas de préfixes : "show ip bgp" + n'importe quoi derrière serait accepté.
# Étendre cette liste avec prudence - chaque ajout doit être une commande
# d'affichage complète, sans argument libre, et ne jamais exposer de secrets.
#
# "show running-config" est volontairement ABSENT : il affiche les secrets
# de l'équipement (mots de passe, communautés, clés).
ALLOWED_COMMANDS = frozenset(
    {
        "show ip bgp summary",
        "show ip ospf neighbor",
        "show ip route",
        "show interface brief",
        "show version",
    }
)

# Longueur maximale acceptée avant même de comparer.
MAX_COMMAND_LENGTH = 100


class CommandNotAllowedError(Exception):
    """Levée quand une commande ne respecte pas la liste blanche."""


def canonical_command(command: str) -> str | None:
    """Retourne la forme canonique d'une commande autorisée, sinon None.

    Rejette AVANT toute comparaison :
      - tout non-str, toute commande trop longue ;
      - tout caractère de contrôle (\\n, \\r, \\t, \\x00, ESC...) : c'est ce qui
        permettait d'enchaîner une 2e commande ("show version\\nusername ...") ;
      - tout caractère non ASCII imprimable (homoglyphes, Unicode invisible).
    Seuls les espaces simples multiples sont tolérés (réduits à un seul).
    """
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND_LENGTH:
        return None
    if not all(32 <= ord(char) < 127 for char in command):
        return None
    normalized = re.sub(r" +", " ", command.strip()).lower()
    return normalized if normalized in ALLOWED_COMMANDS else None


def is_allowed(command: str) -> bool:
    """Vérifie qu'une commande est exactement l'une des commandes autorisées."""
    return canonical_command(command) is not None


def enforce_whitelist(command: str) -> str:
    """Retourne la commande canonique à envoyer, ou lève CommandNotAllowedError.

    L'appelant doit envoyer la valeur RETOURNÉE à l'équipement, pas la
    chaîne d'origine : ce qui est envoyé est exactement ce qui a été validé.
    """
    canonical = canonical_command(command)
    if canonical is None:
        raise CommandNotAllowedError(f"Commande refusée par la liste blanche : {command!r}")
    return canonical