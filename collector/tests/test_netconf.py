from collector.common.schema import validate_response
from collector.netconf.netconf_collector import netconf_get


def test_netconf_get_simulated_ok():
    response = netconf_get("R1", yang_filter="interfaces", mode="simulated")
    assert validate_response(response)
    assert response["status"] == "ok"
    assert "eth0" in response["data"]["xml"]


def test_netconf_get_simulated_unknown_filter():
    response = netconf_get("R1", yang_filter="bgp", mode="simulated")
    assert response["status"] == "error"
