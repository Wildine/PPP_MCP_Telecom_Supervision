"""
Package collector - Backend de collecte pour le projet
PPP MCP Telecom Supervision (Groupe 3, EC2LT).

Regroupe les collecteurs SNMP, NETCONF, CLI (netmiko/NAPALM),
NetFlow, PCAP et Syslog. Chaque collecteur expose des fonctions
en lecture seule qui renvoient un format de sortie unifié
(voir collector.common.schema.make_response).
"""

__version__ = "0.1.0"
