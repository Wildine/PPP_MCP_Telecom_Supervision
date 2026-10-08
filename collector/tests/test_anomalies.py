from collector.common.schema import validate_response
from collector.netflow.anomalies import compute_anomalies, detect_anomalies


def test_device_without_flood_profile():
    r = detect_anomalies("R1", mode="simulated")
    assert validate_response(r)
    types = {a["type"] for a in r["data"]["anomalies"]}
    assert "small_packets" not in types and "flow_count_spike" not in types


def test_anomalous_device_flagged():
    r = detect_anomalies("R2", mode="simulated")
    types = {a["type"] for a in r["data"]["anomalies"]}
    assert {"dominant_flow", "small_packets", "flow_count_spike"} <= types
    assert r["data"]["anomaly_count"] == len(r["data"]["anomalies"])


def test_unknown_device_is_error():
    assert detect_anomalies("R99", mode="simulated")["status"] == "error"


def test_compute_is_deterministic_and_handles_empty():
    assert compute_anomalies({}) == []
    data = {"top_talkers": [{"src_ip": "a", "dst_ip": "b", "bytes": 100, "packets": 5000}], "total_flows": 1}
    assert compute_anomalies(data) == compute_anomalies(data)
