from collector.common.schema import validate_response
from collector.snmp.snmp_collector import get_interface_stats, snmp_get, snmp_walk


def test_snmp_get_simulated_ok():
    response = snmp_get("R1", "1.3.6.1.2.1.1.1.0", mode="simulated")
    assert validate_response(response)
    assert response["status"] == "ok"
    assert response["simulated"] is True


def test_snmp_get_simulated_unknown_oid():
    response = snmp_get("R1", "9.9.9.9.9", mode="simulated")
    assert validate_response(response)
    assert response["status"] == "error"


def test_snmp_walk_simulated_ok():
    response = snmp_walk("R2", "1.3.6.1.2.1.1", mode="simulated")
    assert validate_response(response)
    assert "entries" in response["data"]


def test_get_interface_stats_simulated_all_interfaces():
    response = get_interface_stats("R1", mode="simulated")
    assert validate_response(response)
    assert "GigabitEthernet0/0" in response["data"]


def test_get_interface_stats_simulated_single_interface():
    response = get_interface_stats("R1", interface="GigabitEthernet0/1", mode="simulated")
    assert validate_response(response)
    assert list(response["data"].keys()) == ["GigabitEthernet0/1"]


def test_get_interface_stats_unknown_device():
    response = get_interface_stats("R99", mode="simulated")
    assert response["status"] == "error"
