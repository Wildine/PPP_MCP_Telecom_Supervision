from collector.common.schema import validate_response
from collector.ping.ping_collector import ping_host, traceroute


def test_ping_reachable():
    r = ping_host("10.0.1.1", mode="simulated")
    assert validate_response(r) and r["data"]["reachable"] is True


def test_ping_packet_loss():
    r = ping_host("10.0.2.1", mode="simulated")
    assert r["data"]["loss_percent"] == 50.0


def test_ping_unreachable():
    r = ping_host("10.0.9.1", mode="simulated")
    assert r["status"] == "ok" and r["data"]["reachable"] is False


def test_ping_rejects_injection():
    for bad in ["10.0.1.1; rm -rf /", "-f 10.0.1.1", "$(id)", "a b", "", "10.0.1.1\nid"]:
        r = ping_host(bad, mode="simulated")
        assert validate_response(r) and r["status"] == "error"


def test_traceroute_ok_and_broken_path():
    ok = traceroute("10.0.2.1", mode="simulated")
    assert ok["data"]["reached"] is True and len(ok["data"]["hops"]) == 2
    ko = traceroute("10.0.9.1", mode="simulated")
    assert ko["data"]["reached"] is False


def test_traceroute_rejects_bad_host():
    assert traceroute("--help", mode="simulated")["status"] == "error"


def test_parse_traceroute_output():
    from collector.ping.ping_collector import _parse_traceroute

    raw = "traceroute to 10.0.2.1\n 1  10.0.1.1  0.5 ms  0.4 ms  0.4 ms\n 2  * * *\n 3  10.0.2.1  1.2 ms\n"
    parsed = _parse_traceroute(raw, "10.0.2.1")
    assert parsed["reached"] is True
    assert parsed["hops"][1]["address"] is None
