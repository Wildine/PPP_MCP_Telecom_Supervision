"""Journal d'audit : une ligne JSON par décision (autorisée, refusée, alerte).

Chaque entrée contient le hash SHA-256 de la précédente (`prev`) : modifier ou
supprimer une ligne casse la chaîne, ce qui se vérifie avec verify_chain().
Les paramètres dont le nom évoque un secret sont masqués.

Fichier : variable AUDIT_LOG_FILE, sinon <racine du dépôt>/audit.log.
"""

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

_logger = logging.getLogger("noc-audit")
_lock = threading.Lock()
_last_hash: dict[str, str] = {}
_SECRET_KEY = re.compile(r"pass|secret|token|key|community", re.IGNORECASE)
GENESIS = "0" * 64


def audit_path() -> Path:
    return Path(os.environ.get("AUDIT_LOG_FILE", Path(__file__).resolve().parent.parent / "audit.log"))


def _tail_hash(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])["hash"] if lines else GENESIS
    except (OSError, ValueError, KeyError):
        return GENESIS


def log_action(user: str, tool: str, params: dict, status: str, detail: str = "") -> None:
    """status : AUTORISE, REFUSE, ALERTE_INJECTION, VALIDEE_HUMAIN, REFUSEE_HUMAIN..."""
    path = audit_path()
    safe_params = {k: ("***" if _SECRET_KEY.search(str(k)) else v) for k, v in (params or {}).items()}
    with _lock:
        prev = _last_hash.get(str(path)) or _tail_hash(path)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "tool": tool,
            "params": safe_params,
            "status": status,
            "detail": detail,
            "prev": prev,
        }
        body = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            _last_hash[str(path)] = entry["hash"]
        except OSError as exc:  # le journal ne doit pas faire tomber le serveur
            _logger.error("Écriture du journal d'audit impossible : %s", exc)


def verify_chain(path: Path | None = None) -> bool:
    """True si aucune ligne du journal n'a été modifiée, retirée ou réordonnée."""
    path = path or audit_path()
    prev = GENESIS
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        claimed = entry.pop("hash")
        if entry.get("prev") != prev:
            return False
        body = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != claimed:
            return False
        prev = claimed
    return True
