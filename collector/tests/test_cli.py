import pytest

from collector.cli.cli_collector import get_bgp_peers, get_ospf_neighbors
from collector.cli.command_whitelist import CommandNotAllowedError, enforce_whitelist, is_allowed
from collector.common.schema import validate_response


def test_get_bgp_peers_simulated_ok():
    response = get_bgp_peers("R1", mode="simulated")
    assert validate_response(response)
    assert response["status"] == "ok"
    assert len(response["data"]["peers"]) == 2
    assert response["data"]["peers"][0]["neighbor"] == "10.0.0.2"


def test_get_ospf_neighbors_simulated_ok():
    response = get_ospf_neighbors("R1", mode="simulated")
    assert validate_response(response)
    assert response["data"]["neighbors"][0]["state"] == "Full/DR"


def test_whitelist_allows_show_commands():
    assert is_allowed("show ip bgp summary") is True


def test_whitelist_blocks_running_config():
    # volontairement interdit : affiche les secrets de l'équipement
    assert is_allowed("show running-config") is False


def test_whitelist_blocks_config_commands():
    assert is_allowed("configure terminal") is False
    assert is_allowed("show version; conf t") is False
    assert is_allowed("no shutdown") is False


def test_enforce_whitelist_raises_on_forbidden_command():
    with pytest.raises(CommandNotAllowedError):
        enforce_whitelist("write memory")
