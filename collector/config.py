"""
Configuration centrale pour tout le module collector.

Le mode de fonctionnement (simulé ou réel) se pilote via la
variable d'environnement COLLECTOR_MODE. Quand le labo
Containerlab/FRRouting (bloc 1) sera prêt, il suffit de changer
cette variable - aucun code des collecteurs n'a besoin d'être
modifié.

Secrets : AUCUNE valeur par défaut. Les identifiants SNMPv3, NETCONF
et CLI sont lus uniquement dans l'environnement, au moment de
l'utilisation en mode réel (voir get_*_credentials). S'ils manquent,
une ConfigError est levée - jamais de repli sur "admin/admin".

Exemple (.env) :
    COLLECTOR_MODE=simulated
    SNMPV3_USER=<compte lecture seule>
    SNMPV3_AUTH_KEY=<8 caractères minimum>
    SNMPV3_PRIV_KEY=<8 caractères minimum>
    SNMP_PORT=161
    NETCONF_USERNAME=<compte lecture seule>
    NETCONF_PASSWORD=<secret>
    NETCONF_PORT=830
    CLI_USERNAME=<compte lecture seule>
    CLI_PASSWORD=<secret>
    CLI_DEVICE_TYPE=cisco_ios
    NFDUMP_BIN=/usr/bin/nfdump
    NETFLOW_DATA_DIR=/var/netflow
    PCAP_MAX_DURATION_SECONDS=30
    PCAP_MAX_PACKETS=1000
    PCAP_OUTPUT_DIR=/tmp/pcap_captures
    PING_MAX_COUNT=5
    TRACEROUTE_MAX_HOPS=20
"""

import os

# --- Mode global -----------------------------------------------------------
# "simulated" : renvoie des données de test (fixtures) sans toucher au réseau
# "real"      : exécute les vraies requêtes SNMP/NETCONF/CLI/NetFlow/PCAP
COLLECTOR_MODE = os.environ.get("COLLECTOR_MODE", "simulated").lower()


def is_simulated(mode: str | None = None) -> bool:
    """Détermine si on doit utiliser les données simulées.

    Un appel de fonction peut forcer explicitement un mode
    ("simulated" ou "real") ; sinon on retombe sur la variable
    d'environnement COLLECTOR_MODE.
    """
    effective_mode = (mode or COLLECTOR_MODE).lower()
    return effective_mode == "simulated"


class ConfigError(Exception):
    """Configuration manquante ou invalide (ex: secret absent en mode réel)."""


def require_env(name: str) -> str:
    """Lit une variable d'environnement obligatoire (secret ou identifiant).

    Lève ConfigError si elle est absente ou vide. Le message cite le NOM
    de la variable, jamais sa valeur.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Variable d'environnement obligatoire absente : {name}")
    return value


def _require_secret_min_length(name: str, min_length: int = 8) -> str:
    """Comme require_env, avec la longueur minimale imposée par SNMPv3 (USM)."""
    value = require_env(name)
    if len(value) < min_length:
        raise ConfigError(f"{name} doit contenir au moins {min_length} caractères")
    return value


# --- SNMP (SNMPv3 uniquement, niveau authPriv) -----------------------------
# Le compte SNMPv3 doit être configuré en lecture seule côté équipement.
SNMP_PORT = int(os.environ.get("SNMP_PORT", "161"))
SNMP_TIMEOUT = float(os.environ.get("SNMP_TIMEOUT", "2"))
SNMP_RETRIES = int(os.environ.get("SNMP_RETRIES", "1"))
# Algorithmes (valeurs acceptées : SHA, SHA256 / AES, AES256). Pas de MD5/DES.
SNMPV3_AUTH_PROTOCOL = os.environ.get("SNMPV3_AUTH_PROTOCOL", "SHA256").upper()
SNMPV3_PRIV_PROTOCOL = os.environ.get("SNMPV3_PRIV_PROTOCOL", "AES").upper()
# Plafond du nombre d'entrées renvoyées par un snmp_walk
SNMP_WALK_MAX_ENTRIES = int(os.environ.get("SNMP_WALK_MAX_ENTRIES", "500"))


def get_snmpv3_credentials() -> dict[str, str]:
    """Identifiants SNMPv3 (mode réel). Lève ConfigError s'ils manquent."""
    return {
        "user": require_env("SNMPV3_USER"),
        "auth_key": _require_secret_min_length("SNMPV3_AUTH_KEY"),
        "priv_key": _require_secret_min_length("SNMPV3_PRIV_KEY"),
    }

# --- NETCONF -------------------------------------------------------------
NETCONF_PORT = int(os.environ.get("NETCONF_PORT", "830"))
NETCONF_TIMEOUT = int(os.environ.get("NETCONF_TIMEOUT", "10"))
# Vérification de la clé d'hôte SSH : activée par défaut. Ne la désactiver
# (NETCONF_HOSTKEY_VERIFY=false) que dans le labo Containerlab, où les clés
# changent à chaque redéploiement - limite à documenter dans le rapport.
NETCONF_HOSTKEY_VERIFY = os.environ.get("NETCONF_HOSTKEY_VERIFY", "true").strip().lower() != "false"
# Plafond de taille de la réponse XML conservée (caractères)
NETCONF_MAX_XML_CHARS = int(os.environ.get("NETCONF_MAX_XML_CHARS", "50000"))


def get_netconf_credentials() -> dict[str, str]:
    """Identifiants NETCONF (mode réel). Lève ConfigError s'ils manquent."""
    return {"username": require_env("NETCONF_USERNAME"), "password": require_env("NETCONF_PASSWORD")}


# --- CLI (netmiko / NAPALM) ----------------------------------------------
CLI_DEVICE_TYPE = os.environ.get("CLI_DEVICE_TYPE", "cisco_ios")  # ex: "frr" via SSH
CLI_TIMEOUT = int(os.environ.get("CLI_TIMEOUT", "10"))
# Plafond de taille de la sortie CLI conservée (caractères)
CLI_MAX_OUTPUT_CHARS = int(os.environ.get("CLI_MAX_OUTPUT_CHARS", "20000"))


def get_cli_credentials() -> dict[str, str]:
    """Identifiants CLI/SSH (mode réel). Lève ConfigError s'ils manquent."""
    return {"username": require_env("CLI_USERNAME"), "password": require_env("CLI_PASSWORD")}

# --- NetFlow ---------------------------------------------------------------
NFDUMP_BIN = os.environ.get("NFDUMP_BIN", "/usr/bin/nfdump")
NETFLOW_DATA_DIR = os.environ.get("NETFLOW_DATA_DIR", "/var/netflow")

# --- PCAP (contraintes de sécurité : durée/volume bridés, cf. cahier des charges) --
PCAP_MAX_DURATION_SECONDS = int(os.environ.get("PCAP_MAX_DURATION_SECONDS", "30"))
PCAP_MAX_PACKETS = int(os.environ.get("PCAP_MAX_PACKETS", "1000"))
PCAP_OUTPUT_DIR = os.environ.get("PCAP_OUTPUT_DIR", "/tmp/pcap_captures")

# --- Syslog ------------------------------------------------------------
SYSLOG_LISTEN_HOST = os.environ.get("SYSLOG_LISTEN_HOST", "0.0.0.0")
SYSLOG_LISTEN_PORT = int(os.environ.get("SYSLOG_LISTEN_PORT", "514"))
SYSLOG_FILE_PATH = os.environ.get("SYSLOG_FILE_PATH", "/var/log/network_syslog.log")

# --- Connectivité (ping / traceroute) : plafonds fixes, jamais dépassés ------
PING_MAX_COUNT = int(os.environ.get("PING_MAX_COUNT", "5"))
PING_TIMEOUT_SECONDS = int(os.environ.get("PING_TIMEOUT_SECONDS", "2"))  # par paquet
TRACEROUTE_MAX_HOPS = int(os.environ.get("TRACEROUTE_MAX_HOPS", "20"))
TRACEROUTE_TIMEOUT_SECONDS = int(os.environ.get("TRACEROUTE_TIMEOUT_SECONDS", "2"))  # par saut

# --- QoS (SNMP, MIB constructeur) --------------------------------------------
# Par défaut : CISCO-CLASS-BASED-QOS-MIB (cbQosCMPrePolicyPkt / cbQosCMDropPkt).
# À adapter à la MIB réellement exposée par les équipements du labo.
QOS_PKTS_OID = os.environ.get("QOS_PKTS_OID", "1.3.6.1.4.1.9.9.166.1.15.1.1.3")
QOS_DROPS_OID = os.environ.get("QOS_DROPS_OID", "1.3.6.1.4.1.9.9.166.1.15.1.1.13")

# --- Détection d'anomalies (seuils déterministes appliqués aux flux NetFlow) --
ANOMALY_TOP_TALKER_RATIO = float(os.environ.get("ANOMALY_TOP_TALKER_RATIO", "0.80"))   # part d'octets d'un seul flux
ANOMALY_MIN_AVG_PACKET_BYTES = int(os.environ.get("ANOMALY_MIN_AVG_PACKET_BYTES", "100"))  # taille moyenne mini
ANOMALY_MIN_PACKETS = int(os.environ.get("ANOMALY_MIN_PACKETS", "1000"))               # volume mini pour juger la taille moyenne
ANOMALY_MAX_FLOWS = int(os.environ.get("ANOMALY_MAX_FLOWS", "1000"))                   # nombre de flux jugé anormal
