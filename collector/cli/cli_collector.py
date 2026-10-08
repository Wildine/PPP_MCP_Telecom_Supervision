"""
Collecteur CLI multi-vendeurs - outils MCP cibles : get_bgp_peers,
get_ospf_neighbors.

Toute commande passe par command_whitelist.enforce_whitelist()
avant d'être envoyée à l'équipement : seules les commandes
"show" sont autorisées (cf. cahier des charges, bloc sécurité).

Pré-requis pour le mode réel :
    pip install netmiko
"""

import re
from typing import Any

from collector import config
from collector.cli.command_whitelist import CommandNotAllowedError, enforce_whitelist
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_text_fixture, logger, sanitize_untrusted_text

FIXTURES = fixtures_dir(__file__)


def _real_run_show_command(device_ip: str, command: str) -> str:
    """Envoie une commande 'show' via netmiko après vérification whitelist."""
    safe_command = enforce_whitelist(command)  # lève CommandNotAllowedError si refusée
    credentials = config.get_cli_credentials()  # lève ConfigError si secrets absents

    from netmiko import ConnectHandler

    device_params = {
        "device_type": config.CLI_DEVICE_TYPE,
        "host": device_ip,
        "username": credentials["username"],
        "password": credentials["password"],
        "timeout": config.CLI_TIMEOUT,
    }
    with ConnectHandler(**device_params) as conn:
        output = conn.send_command(safe_command)
    # Sortie d'équipement = donnée non fiable : nettoyée et bornée en taille.
    return sanitize_untrusted_text(output, config.CLI_MAX_OUTPUT_CHARS)


def _parse_bgp_summary(raw_output: str) -> list[dict[str, Any]]:
    """Parse une sortie 'show ip bgp summary' en liste de voisins."""
    peers = []
    for line in raw_output.splitlines():
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)", line)
        if match:
            neighbor_ip, remote_as, msg_rcvd, msg_sent, up_down, state_or_pfx = match.groups()
            peers.append(
                {
                    "neighbor": neighbor_ip,
                    "remote_as": int(remote_as),
                    "messages_received": int(msg_rcvd),
                    "messages_sent": int(msg_sent),
                    "up_down": up_down,
                    "state_or_prefixes": state_or_pfx,
                }
            )
    return peers


def _parse_ospf_neighbors(raw_output: str) -> list[dict[str, Any]]:
    """Parse une sortie 'show ip ospf neighbor' en liste de voisins."""
    neighbors = []
    for line in raw_output.splitlines():
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", line)
        if match:
            neighbor_id, priority, state, dead_time, address, interface = match.groups()
            neighbors.append(
                {
                    "neighbor_id": neighbor_id,
                    "priority": int(priority),
                    "state": state,
                    "dead_time": dead_time,
                    "address": address,
                    "interface": interface,
                }
            )
    return neighbors


def get_bgp_peers(device_ip: str, mode: str | None = None) -> dict[str, Any]:
    """Récupère l'état des voisins BGP d'un équipement."""
    simulated = config.is_simulated(mode)
    try:
        if simulated:
            raw_output = sanitize_untrusted_text(
                load_text_fixture(FIXTURES / "show_ip_bgp_summary.txt"), config.CLI_MAX_OUTPUT_CHARS
            )
        else:
            raw_output = _real_run_show_command(device_ip, "show ip bgp summary")

        # Parsing sur la sortie déjà nettoyée : les champs extraits le sont aussi.
        peers = _parse_bgp_summary(raw_output)
        return make_response(
            "cli",
            device_ip,
            {"peers": peers, "raw": raw_output},
            simulated=simulated,
            untrusted_fields=["data.raw", "data.peers[].state_or_prefixes"],
        )

    except CommandNotAllowedError as exc:
        logger.error("get_bgp_peers blocked by whitelist for %s: %s", device_ip, exc)
        return make_error_response("cli", device_ip, str(exc), simulated=simulated)
    except Exception as exc:  # noqa: BLE001
        logger.error("get_bgp_peers failed for %s: %s", device_ip, exc)
        return make_error_response("cli", device_ip, str(exc), simulated=simulated)


def get_ospf_neighbors(device_ip: str, mode: str | None = None) -> dict[str, Any]:
    """Récupère l'état des voisins OSPF d'un équipement."""
    simulated = config.is_simulated(mode)
    try:
        if simulated:
            raw_output = sanitize_untrusted_text(
                load_text_fixture(FIXTURES / "show_ip_ospf_neighbor.txt"), config.CLI_MAX_OUTPUT_CHARS
            )
        else:
            raw_output = _real_run_show_command(device_ip, "show ip ospf neighbor")

        neighbors = _parse_ospf_neighbors(raw_output)
        return make_response(
            "cli",
            device_ip,
            {"neighbors": neighbors, "raw": raw_output},
            simulated=simulated,
            untrusted_fields=["data.raw", "data.neighbors[].interface"],
        )

    except CommandNotAllowedError as exc:
        logger.error("get_ospf_neighbors blocked by whitelist for %s: %s", device_ip, exc)
        return make_error_response("cli", device_ip, str(exc), simulated=simulated)
    except Exception as exc:  # noqa: BLE001
        logger.error("get_ospf_neighbors failed for %s: %s", device_ip, exc)
        return make_error_response("cli", device_ip, str(exc), simulated=simulated)