"""Tests du pont Syslog (sans docker). Depuis la racine : python -m pytest lab -q"""

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import syslog_bridge as b  # noqa: E402
from collector.syslog.syslog_collector import _parse_line  # noqa: E402
from analysis.correlation import classify  # noqa: E402

NOW = datetime(2026, 10, 9, 5, 40, 1)
UP = ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
      "2: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
      "3: eth1@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9500 qdisc noqueue state UP mode DEFAULT\n")
DOWN = UP.replace("<BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9500 qdisc noqueue state UP", "<BROADCAST,MULTICAST> mtu 9500 qdisc noqueue state DOWN")
OSPF_FULL = json.dumps({"neighbors": {"10.255.0.2": [{"nbrState": "Full/Backup", "ifaceName": "eth1:10.0.12.1"}]}})
OSPF_NONE = json.dumps({"neighbors": {}})
BGP_UP = json.dumps({"ipv4Unicast": {"peers": {"10.255.0.2": {"state": "Established"}}}})
BGP_DOWN = json.dumps({"ipv4Unicast": {"peers": {"10.255.0.2": {"state": "Active"}}}})


def state(links, ospf, bgp):
    return {"links": b.parse_links(links), "ospf": b.parse_ospf(ospf), "bgp": b.parse_bgp(bgp)}


def test_parsers():
    assert b.parse_links(UP) == {"eth1": "up"}
    assert b.parse_links(DOWN) == {"eth1": "down"}
    assert b.parse_ospf(OSPF_FULL) == {"10.255.0.2": {"state": "up", "iface": "eth1"}}
    assert b.parse_bgp(BGP_DOWN) == {"10.255.0.2": "down"}
    assert b.parse_ospf("") == {} and b.parse_bgp("") == {}


def test_no_event_without_change():
    s = state(UP, OSPF_FULL, BGP_UP)
    assert b.diff_state("R1", s, s, NOW) == []


def test_link_down_produces_link_and_ospf_events_readable_by_the_collector_and_analysis():
    lines = b.diff_state("R1", state(UP, OSPF_FULL, BGP_UP), state(DOWN, OSPF_NONE, BGP_UP), NOW)
    assert len(lines) == 2
    kinds = []
    for line in lines:
        entry = _parse_line(line)
        assert entry is not None, line
        assert entry["hostname"] == "R1" and entry["timestamp"] == "Oct  9 05:40:01"
        kinds.append(classify(entry["facility"], entry["mnemonic"], entry["message"]))
    assert kinds == ["link_down", "ospf_down"]


def test_recovery_and_bgp_events():
    lines = b.diff_state("R2", state(DOWN, OSPF_NONE, BGP_UP), state(UP, OSPF_FULL, BGP_DOWN), NOW)
    kinds = [classify(*(lambda e: (e["facility"], e["mnemonic"], e["message"]))(_parse_line(l))) for l in lines]
    assert sorted(kinds) == ["bgp_down", "link_up", "ospf_up"]


def test_missing_category_emits_nothing():
    prev = state(UP, OSPF_FULL, BGP_UP)
    cur = {"links": prev["links"]}  # vtysh injoignable
    assert b.diff_state("R1", prev, cur, NOW) == []
