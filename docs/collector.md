# collector - Backend de collecte

Partie "Backend de collecte (Python)" du projet PPP MCP Telecom
Supervision (Groupe 3, EC2LT). Regroupe les collecteurs SNMP,
NETCONF, CLI (netmiko), NetFlow, PCAP et Syslog qui seront
enveloppés par les outils du serveur MCP (bloc 3).

## Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

`nfdump` et `tshark` doivent être installés séparément via le
gestionnaire de paquets du système (`apt install nfdump tshark`
sous Debian/Ubuntu) - ce ne sont pas des paquets pip.

## Mode simulé vs mode réel

Tant que le labo Containerlab/FRRouting (bloc 1) n'est pas prêt,
tout le module fonctionne avec `COLLECTOR_MODE=simulated` (valeur
par défaut) : chaque collecteur lit des données de test dans son
dossier `fixtures/` au lieu d'interroger un vrai équipement.

Quand le labo est prêt, il suffit de passer `COLLECTOR_MODE=real`
dans `.env` (et de renseigner les vraies IPs/credentials) - aucun
code des collecteurs n'a besoin d'être modifié. Le mode peut
aussi être forcé fonction par fonction via l'argument `mode=`.

## Format de sortie unifié

Toutes les fonctions renvoient un dict au même format (voir
`collector/common/schema.py`) :

```python
{
    "status": "ok" | "error",
    "source": "snmp" | "netconf" | "cli" | "netflow" | "pcap" | "syslog",
    "device": "R1",
    "data": {...} | None,
    "error": "message" | None,
    "timestamp": "2026-09-14T10:00:00+00:00",
    "simulated": true | false,
}
```

C'est ce contrat que l'équipe MCP (bloc 3) et l'équipe analyse IA
(bloc 4) doivent pouvoir consommer sans se soucier du protocole
d'origine.

## Structure

```
collector/
├── config.py          # mode simulated/real, credentials, timeouts
├── common/
│   ├── schema.py       # format de sortie unifié
│   └── utils.py
├── snmp/               # snmp_get, snmp_walk, get_interface_stats
├── netconf/            # netconf_get
├── cli/                # get_bgp_peers, get_ospf_neighbors + liste blanche "show"
├── netflow/            # analyze_netflow (wrapper nfdump), detect_anomalies (règles à seuils)
├── ping/               # ping_host, traceroute (cible validée, plafonds)
├── qos/                # qos_stats (SNMP)
├── pcap/               # capture_pcap (durée/volume bridés)
├── syslog/             # get_recent_syslog (corrélation bloc 4)
└── tests/              # tests unitaires (mode simulé)
```

## Fonctions exposées (12, pour les outils MCP du bloc 3)

`snmp_get`, `snmp_walk`, `get_interface_stats`, `netconf_get`,
`get_bgp_peers`, `get_ospf_neighbors`, `ping_host`, `traceroute`,
`analyze_netflow`, `detect_anomalies`, `capture_pcap`, `qos_stats`
(+ `get_recent_syslog` pour la corrélation).

`detect_anomalies` n'utilise aucun LLM : règles à seuils déterministes
(`ANOMALY_*` dans `config.py`) appliquées aux flux nfdump ; le modèle ne
fait qu'interpréter les alertes produites.

## Lancer les tests

```bash
python -m pytest collector/tests -v
```

Tous les tests tournent en mode simulé - aucun accès réseau réel
n'est nécessaire pour les exécuter.

## Sécurité (rappel du cahier des charges)

- **Lecture seule stricte** : aucune fonction n'exécute d'opération
  d'écriture/configuration.
- **Liste blanche CLI** : `cli/command_whitelist.py` bloque toute
  commande qui n'est pas un `show` (voir `enforce_whitelist`).
- **PCAP bridé** : `capture_pcap` plafonne systématiquement la
  durée et le nombre de paquets, quoi que demande l'appelant.
- **Secrets** : jamais en dur dans le code - toujours via `.env`
  / variables d'environnement (voir `.env.example`).

## Prochaine étape

Une fois le labo Containerlab/FRRouting prêt (bloc 1), remplacer
les IPs de test par les vraies loopbacks/IPs de management des
routeurs FRR, passer `COLLECTOR_MODE=real`, et valider chaque
fonction une par une contre le labo réel avant intégration au
serveur MCP (bloc 3).
