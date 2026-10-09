"""Génère un jeton JWT pour la démo.

Depuis la racine du dépôt :
    export JWT_SECRET="un-secret-d-au-moins-32-caracteres-aleatoires"
    python security/generate_token.py --user wildine --role administrateur
    export MCP_AUTH_TOKEN="<jeton affiché>"      # transport stdio
    # ou, en HTTP : en-tête  Authorization: Bearer <jeton>
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.rbac import ROLE_HIERARCHY, AccessDeniedError, create_token  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--user", required=True)
parser.add_argument("--role", required=True, choices=ROLE_HIERARCHY)
parser.add_argument("--minutes", type=int, default=60, help="durée de validité (défaut : 60)")
args = parser.parse_args()
try:
    print(create_token(args.user, args.role, args.minutes))
except AccessDeniedError as exc:
    sys.exit(f"Erreur : {exc}")
