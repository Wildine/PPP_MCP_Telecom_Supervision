# Sécurité du serveur MCP (bloc 5)

Package `security/`, appliqué à **chaque outil** de `mcp_server/server.py`.

| Mécanisme | Fichier | Rôle |
|---|---|---|
| JWT + RBAC | `security/rbac.py` | Jeton signé HS256 (`sub`, `role`, `exp`). Rôles `operateur` < `superviseur` < `administrateur`. Rôle minimum par outil dans `TOOL_ROLES` ; outil absent de la table = `administrateur`. |
| Garde | `security/guard.py` | Vérifie le jeton et le rôle avant l'outil, neutralise la réponse après. Refus par défaut. |
| Injection de prompt | `security/validation.py` | Repère les phrases d'injection dans les sorties des équipements, les remplace par `[CONTENU_SUSPECT_NEUTRALISE]` et ajoute une clé `security` à la réponse. Complète `collector.common.utils.sanitize_untrusted_text` (caractères invisibles, taille). |
| Audit | `security/audit_log.py` | `audit.log` : une ligne JSON par décision (AUTORISE, REFUSE, ALERTE_INJECTION, VALIDEE_HUMAIN, REFUSEE_HUMAIN). Chaîne de hash SHA-256 (`verify_chain()`), paramètres secrets masqués. |
| Validation humaine | `capture_pcap` | Consentement explicite par Elicitation avant la capture (pas de « toujours autoriser »), décision journalisée. |

Le jeton n'est jamais un paramètre d'outil : en HTTP il vient de l'en-tête
`Authorization: Bearer <jeton>`, en stdio de la variable `MCP_AUTH_TOKEN`
(un utilisateur par processus).

## Rôles par outil

- **operateur** : get_device_status, ping_host, traceroute, snmp_get, snmp_walk, get_interface_stats, get_bgp_peers, get_ospf_neighbors, qos_stats, get_recent_syslog, detect_anomalies
- **superviseur** : netconf_get, analyze_netflow, interpret_anomalies, correlate_alarms, analyze_root_cause, generate_incident_report
- **administrateur** : capture_pcap

## Utilisation

```bash
export JWT_SECRET="un-secret-d-au-moins-32-caracteres-aleatoires"
export MCP_AUTH_TOKEN=$(python security/generate_token.py --user wildine --role administrateur)
fastmcp dev inspector mcp_server/server.py
```

Les variables du fichier `.env` doivent être exportées dans le shell
(`set -a; source .env; set +a`) : le code ne charge pas `.env` lui-même.
`SECURITY_ENABLED=false` désactive RBAC/JWT pour les tests locaux (un
avertissement est journalisé). Démo sans réseau : `python security/demo_security.py`.

## Limites (à dire à l'oral)

- Secret partagé HS256, pas de serveur d'identité : Keycloak (RS256, SSO) est la suite logique, le contrôle de rôle ne changerait pas.
- Les Resources (`noc://...`) et Prompts ne sont pas protégés par rôle.
- La neutralisation repose sur des motifs connus : elle réduit le risque, elle ne le supprime pas ; les sorties restent marquées `untrusted`.
- Le nom d'utilisateur de l'audit pour le consentement `capture_pcap` est `systeme` (l'identité du jeton est dans l'entrée AUTORISE précédente).
