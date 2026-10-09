"""Garde appliquée à chaque outil MCP : RBAC/JWT, audit, neutralisation.

Ordre : 1) authentification et rôle (refus journalisé), 2) exécution de
l'outil, 3) neutralisation des injections dans la réponse (alerte journalisée).
"""

import functools
import inspect

from security import audit_log
from security.rbac import (
    AccessDeniedError,
    current_token,
    required_role,
    role_satisfies,
    security_enabled,
    verify_token,
)
from security.validation import neutralize


def _denied(message: str) -> Exception:
    try:
        from fastmcp.exceptions import ToolError

        return ToolError(message)
    except ImportError:  # pragma: no cover
        return PermissionError(message)


def _params(kwargs: dict) -> dict:
    return {k: v for k, v in kwargs.items() if k != "ctx"}


def authorize(tool: str, params: dict) -> str:
    """Retourne l'utilisateur autorisé, ou lève l'erreur d'outil (refus journalisé)."""
    if not security_enabled():
        audit_log.log_action("securite-desactivee", tool, params, "AUTORISE", "SECURITY_ENABLED=false")
        return "securite-desactivee"
    need = required_role(tool)
    try:
        claims = verify_token(current_token())
    except AccessDeniedError as exc:
        audit_log.log_action("inconnu", tool, params, "REFUSE", str(exc))
        raise _denied(f"Accès refusé : {exc}") from None
    user, role = claims["sub"], claims["role"]
    if not role_satisfies(role, need):
        detail = f"Rôle '{role}' insuffisant : '{need}' requis pour '{tool}'."
        audit_log.log_action(user, tool, params, "REFUSE", detail)
        raise _denied(f"Accès refusé : {detail}")
    audit_log.log_action(user, tool, params, "AUTORISE", f"role={role}")
    return user


def screen(tool: str, user: str, result):
    """Neutralise les injections de la réponse et signale ce qui a été trouvé."""
    cleaned, flags = neutralize(result)
    if flags:
        audit_log.log_action(user, tool, {}, "ALERTE_INJECTION", f"{len(flags)} motif(s) neutralisé(s) : {sorted(set(flags))}")
        if isinstance(cleaned, dict):
            cleaned["security"] = {"injection_detected": True, "patterns": sorted(set(flags))}
    return cleaned


def guard(fn):
    """Décorateur pour fonction synchrone ou asynchrone. Conserve la signature (FastMCP)."""
    name = fn.__name__
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def awrapper(*args, **kwargs):
            user = authorize(name, _params(kwargs))
            return screen(name, user, await fn(*args, **kwargs))

        return awrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user = authorize(name, _params(kwargs))
        return screen(name, user, fn(*args, **kwargs))

    return wrapper
