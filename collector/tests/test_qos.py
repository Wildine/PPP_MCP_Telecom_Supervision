from collector.common.schema import validate_response
from collector.qos.qos_collector import qos_stats


def test_qos_stats_simulated_ok():
    r = qos_stats("R1", mode="simulated")
    assert validate_response(r)
    assert len(r["data"]["GigabitEthernet0/0"]["classes"]) == 3


def test_qos_stats_interface_filter_and_unknown():
    assert qos_stats("R2", "GigabitEthernet0/0", mode="simulated")["status"] == "ok"
    assert qos_stats("R2", "Gi9/9", mode="simulated")["status"] == "error"
    assert qos_stats("R99", mode="simulated")["status"] == "error"
