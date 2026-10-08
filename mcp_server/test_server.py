"""Tests du serveur MCP, en mémoire (aucun réseau, collecteur en mode simulé).

Lancer depuis la racine du dépôt :
    COLLECTOR_MODE=simulated python -m pytest mcp_server -v
"""

import asyncio
import os
import sys
from pathlib import Path

os.environ["COLLECTOR_MODE"] = "simulated"
os.environ.setdefault("MCP_LOG_FILE", str(Path(__file__).resolve().parent / "test_server.log"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError

from mcp_server.server import mcp

# Les 8 outils exigés par le cahier des charges (B.5, fonctions de supervision).
REQUIRED_SUPERVISION = {
    "snmp_get", "snmp_walk", "ping_host", "traceroute",
    "get_interface_stats", "get_bgp_peers", "get_ospf_neighbors", "netconf_get",
}
# Fonctions d'analyse de trafic (B.5).
REQUIRED_TRAFFIC = {"analyze_netflow", "capture_pcap", "detect_anomalies", "qos_stats"}
EXPECTED_TOOLS = REQUIRED_SUPERVISION | REQUIRED_TRAFFIC | {
    "get_recent_syslog", "get_device_status", "interpret_anomalies",
    "correlate_alarms", "analyze_root_cause", "generate_incident_report",
}


def run(coro):
    return asyncio.run(coro)


async def _call(name, args, **client_kwargs):
    async with Client(mcp, **client_kwargs) as client:
        return await client.call_tool(name, args)


def test_all_expected_tools_are_exposed():
    async def go():
        async with Client(mcp) as client:
            return {t.name for t in await client.list_tools()}

    assert run(go()) == EXPECTED_TOOLS


def test_cahier_des_charges_minimum_tools():
    async def go():
        async with Client(mcp) as client:
            return {t.name for t in await client.list_tools()}

    names = run(go())
    assert REQUIRED_SUPERVISION <= names
    assert REQUIRED_TRAFFIC <= names
    assert len(names) >= 8


def test_every_tool_is_declared_read_only():
    async def go():
        async with Client(mcp) as client:
            return await client.list_tools()

    for tool in run(go()):
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name


def test_no_secret_or_mode_parameter_is_exposed_to_the_model():
    forbidden = {"mode", "password", "username", "community", "auth_key", "priv_key"}

    async def go():
        async with Client(mcp) as client:
            return await client.list_tools()

    for tool in run(go()):
        params = set(tool.inputSchema.get("properties", {}))
        assert not (params & forbidden), f"{tool.name} expose {params & forbidden}"


def test_tool_output_keeps_untrusted_markers():
    result = run(_call("get_bgp_peers", {"device_ip": "R1"}))
    data = result.structured_content
    assert data["status"] == "ok"
    assert data["untrusted"] is True
    assert "data.raw" in data["untrusted_fields"]


def test_ping_simulated_reachable():
    data = run(_call("ping_host", {"host": "10.0.1.1"})).structured_content
    assert data["status"] == "ok"
    assert data["data"]["reachable"] is True


def test_ping_injection_is_rejected_by_the_collector():
    try:
        data = run(_call("ping_host", {"host": "1.1.1.1; rm -rf /"})).structured_content
    except ToolError:
        return  # refus propagé comme erreur d'outil : acceptable
    assert data["status"] == "error"


def test_detect_anomalies_flags_dominant_flow_on_r1():
    data = run(_call("detect_anomalies", {"device_ip": "R1"})).structured_content
    assert data["status"] == "ok"
    assert data["data"]["anomaly_count"] >= 1


def test_get_device_status_found_and_not_found():
    found = run(_call("get_device_status", {"name": "r1"})).structured_content
    assert found["status"] == "found" and found["device"]["name"] == "R1"
    missing = run(_call("get_device_status", {"name": "ZZ9"})).structured_content
    assert missing["status"] == "not_found"


def test_resources_and_template_are_listed():
    async def go():
        async with Client(mcp) as client:
            resources = {str(r.uri) for r in await client.list_resources()}
            templates = {t.uriTemplate for t in await client.list_resource_templates()}
            return resources, templates

    resources, templates = run(go())
    assert {"noc://topology", "noc://inventory", "noc://ipam", "noc://runbooks"} <= resources
    assert "noc://runbook/{name}" in templates


def test_read_resources_and_runbooks():
    async def go():
        async with Client(mcp) as client:
            topo = await client.read_resource("noc://topology")
            bgp = await client.read_resource("noc://runbook/bgp_flap")
            index = await client.read_resource("noc://runbooks")
            return topo[0].text, bgp[0].text, index[0].text

    topo, bgp, index = run(go())
    assert '"nodes"' in topo
    assert "get_bgp_peers" in bgp and "opérateur" in bgp
    assert "bgp_flap" in index and "interface_down" in index


def test_runbook_path_traversal_is_rejected():
    async def go(uri):
        async with Client(mcp) as client:
            return await client.read_resource(uri)

    for bad in ("noc://runbook/..%2Fserver", "noc://runbook/../server", "noc://runbook/inconnu"):
        with pytest.raises(Exception):
            run(go(bad))


def test_prompts_are_available_and_enforce_rules():
    async def go():
        async with Client(mcp) as client:
            names = {p.name for p in await client.list_prompts()}
            diag = await client.get_prompt("network_diagnosis", {"device": "R1"})
            return names, diag.messages[0].content.text

    names, text = run(go())
    assert {"network_diagnosis", "incident_report"} <= names
    assert "R1" in text and "non fiable" in text and "noc://runbook" in text


def test_roots_declared_by_the_client_are_accepted():
    async def go():
        async with Client(mcp, roots=[Path(__file__).resolve().parent.as_uri()]) as client:
            return len(await client.list_tools())

    assert run(go()) == len(EXPECTED_TOOLS)


def test_capture_pcap_requires_user_consent():
    async def decline(message, response_type, params, context):
        return ElicitResult(action="decline")

    async def accept(message, response_type, params, context):
        return ElicitResult(action="accept", content={})

    refused = run(_call("capture_pcap", {"device_ip": "R1"}, elicitation_handler=decline)).structured_content
    assert refused["status"] == "error" and "refusée" in refused["error"]

    allowed = run(_call("capture_pcap", {"device_ip": "R1"}, elicitation_handler=accept)).structured_content
    assert allowed["status"] == "ok"


def test_capture_pcap_is_refused_when_client_cannot_ask_consent():
    data = run(_call("capture_pcap", {"device_ip": "R1"})).structured_content
    assert data["status"] == "error"


def test_interpret_anomalies_uses_sampling_when_available():
    async def sampler(messages, params, context):
        return "Flux dominant : probable transfert massif ou déni de service, à confirmer."

    data = run(_call("interpret_anomalies", {"device_ip": "R1"}, sampling_handler=sampler)).structured_content
    assert data["detection"]["status"] == "ok"
    assert data["qualification"] and "Flux dominant" in data["qualification"]


def test_interpret_anomalies_degrades_without_sampling():
    data = run(_call("interpret_anomalies", {"device_ip": "R1"})).structured_content
    assert data["detection"]["status"] == "ok"
    assert data["qualification"] is None


def test_tool_calls_are_written_to_the_log_file():
    from mcp_server.server import LOG_FILE, logger

    run(_call("ping_host", {"host": "10.0.1.1"}))
    for handler in logger.handlers:
        handler.flush()
    content = Path(LOG_FILE).read_text(encoding="utf-8")
    assert "Outil ping_host appelé" in content


def test_diagnosis_chain_through_the_mcp_server():
    """correlate_alarms -> analyze_root_cause -> generate_incident_report, via le serveur."""
    corr = run(_call("correlate_alarms", {})).structured_content
    assert corr["status"] == "ok" and corr["untrusted"] is True
    assert corr["data"]["incident_count"] >= 1
    first = corr["data"]["incidents"][0]["incident_id"]
    rca = run(_call("analyze_root_cause", {"incident_id": first})).structured_content
    assert rca["data"]["candidate_causes"][0]["runbook"] == "interface_down"
    report = run(_call("generate_incident_report", {"incident_id": first})).structured_content
    assert report["data"]["validation"]["status"] == "EN_ATTENTE_DE_VALIDATION_HUMAINE"
    assert report["data"]["validation"]["applied_by_ai"] is False
