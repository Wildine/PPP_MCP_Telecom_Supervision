from collector.common.schema import validate_response
from collector.syslog.syslog_collector import get_recent_syslog


def test_get_recent_syslog_all_devices():
    response = get_recent_syslog(mode="simulated")
    assert validate_response(response)
    assert response["data"]["count"] == 5


def test_get_recent_syslog_filtered_by_device():
    response = get_recent_syslog(device_ip="R2", mode="simulated")
    assert validate_response(response)
    assert response["data"]["count"] == 2
    assert all(e["hostname"] == "R2" for e in response["data"]["entries"])


def test_get_recent_syslog_respects_limit():
    response = get_recent_syslog(limit=2, mode="simulated")
    assert response["data"]["count"] == 2
