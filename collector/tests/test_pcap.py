from collector import config
from collector.common.schema import validate_response
from collector.pcap.pcap_collector import _clamp, capture_pcap


def test_capture_pcap_simulated_ok():
    response = capture_pcap("R1", mode="simulated")
    assert validate_response(response)
    assert response["data"]["packet_count"] == 342


def test_clamp_never_exceeds_configured_max():
    assert _clamp(9999, config.PCAP_MAX_DURATION_SECONDS) == config.PCAP_MAX_DURATION_SECONDS
    assert _clamp(1, config.PCAP_MAX_DURATION_SECONDS) == 1
