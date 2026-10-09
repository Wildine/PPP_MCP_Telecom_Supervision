"""Authentification JWT et contrôle d'accès par rôle (RBAC).

Trois rôles hiérarchiques : operateur < superviseur < administrateur.
Un rôle satisfait tout rôle inférieur ou égal.

Le jeton n'est JAMAIS un paramètre d'outil (le modèle ne doit ni le voir ni
le fabriquer). Il est lu :
  - en transport HTTP : dans l'en-tête `Authorization: Bearer <jeton>` ;
  - en transport stdio : dans la variable d'environnement MCP_AUTH_TOKEN
    (un seul utilisateur par processus).

Variables d'environnement :
  SECURITY_ENABLED  "true" par défaut. "false" désactive RBAC/JWT (tests locaux).
  JWT_SECRET        secret HMAC (HS256), 32 caractères minimum, obligatoire.
  MCP_AUTH_TOKEN    jeton utilisé en stdio.

Refus par défaut : sans secret valide, sans jeton, jeton expiré/falsifié, ou
outil absent de TOOL_ROLES, l'appel est refusé.
"""

import os

import jwt

ROLE_HIERARCHY = ["operateur", "superviseur", "administrateur"]
JWT_ALGORITHM = "HS256"
MIN_SECRET_LENGTH = 32

# Rôle minimum par outil. Un outil absent de cette table exige "administrateur".
TOOL_ROLES = {
    # Lecture courante
    "get_device_status": "operateur",
    "ping_host": "operateur",
    "traceroute": "operateur",
    "snmp_get": "operateur",
    "snmp_walk": "operateur",
    "get_interface_stats": "operateur",
    "get_bgp_peers": "operateur",
    "get_ospf_neighbors": "operateur",
    "qos_stats": "operateur",
    "get_recent_syslog": "operateur",
    "detect_anomalies": "operateur",
    # Données plus sensibles ou analyses
    "netconf_get": "superviseur",
    "analyze_netflow": "superviseur",
    "interpret_anomalies": "superviseur",
    "correlate_alarms": "superviseur",
    "analyze_root_cause": "superviseur",
    "generate_incident_report": "superviseur",
    # Peut contenir des données sensibles : consentement humain en plus
    "capture_pcap": "administrateur",
}


class AccessDeniedError(Exception):
    """Accès refusé (jeton absent/invalide, rôle insuffisant, configuration non sûre)."""


def security_enabled() -> bool:
    return os.environ.get("SECURITY_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")


def _secret() -> str:
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise AccessDeniedError(
            f"JWT_SECRET absent ou trop court ({MIN_SECRET_LENGTH} caractères minimum) : "
            "le serveur refuse de fonctionner sans secret fiable."
        )
    return secret


def role_satisfies(user_role: str, required_role: str) -> bool:
    if user_role not in ROLE_HIERARCHY or required_role not in ROLE_HIERARCHY:
        return False
    return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(required_role)


def required_role(tool_name: str) -> str:
    return TOOL_ROLES.get(tool_name, "administrateur")


def create_token(user: str, role: str, minutes: int = 60) -> str:
    """Crée un jeton signé (utilisé par security/generate_token.py et les tests)."""
    import datetime as dt

    if role not in ROLE_HIERARCHY:
        raise ValueError(f"Rôle inconnu : {role!r}. Valeurs : {ROLE_HIERARCHY}")
    now = dt.datetime.now(dt.timezone.utc)
    payload = {"sub": user, "role": role, "iat": now, "exp": now + dt.timedelta(minutes=minutes)}
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def verify_token(token: str | None) -> dict:
    """Retourne les claims du jeton, ou lève AccessDeniedError."""
    if not token:
        raise AccessDeniedError(
            "Jeton absent : en HTTP envoyer 'Authorization: Bearer <jeton>', en stdio définir MCP_AUTH_TOKEN."
        )
    try:
        payload = jwt.decode(
            token, _secret(), algorithms=[JWT_ALGORITHM], options={"require": ["exp", "sub"]}
        )
    except jwt.ExpiredSignatureError:
        raise AccessDeniedError("Jeton expiré.") from None
    except jwt.InvalidTokenError:
        raise AccessDeniedError("Jeton invalide ou signature incorrecte.") from None
    if payload.get("role") not in ROLE_HIERARCHY:
        raise AccessDeniedError("Jeton mal formé : rôle absent ou inconnu.")
    return payload


def current_token() -> str | None:
    """Jeton de la requête en cours (en-tête HTTP), sinon MCP_AUTH_TOKEN (stdio)."""
    try:
        from fastmcp.server.dependencies import get_http_headers

        auth = get_http_headers(include_all=True).get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
    except Exception:  # noqa: BLE001 - pas de requête HTTP (stdio, tests en mémoire)
        pass
    return os.environ.get("MCP_AUTH_TOKEN", "").strip() or None
