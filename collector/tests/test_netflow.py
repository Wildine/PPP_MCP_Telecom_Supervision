from collector.common.schema import validate_response
from collector.netflow.netflow_collector import analyze_netflow


def test_analyze_netflow_simulated_ok():
    response = analyze_netflow("R1", mode="simulated")
    assert validate_response(response)
    assert response["data"]["total_flows"] == 87
    assert len(response["data"]["top_talkers"]) == 3


def test_analyze_netflow_unknown_device():
    response = analyze_netflow("R99", mode="simulated")
    assert response["status"] == "error"
