"""Pont Syslog du laboratoire : écrit dans SYSLOG_FILE_PATH les changements d'état des routeurs.

Pourquoi : les conteneurs FRR du labo n'exportent pas leurs logs (voir lab/README.md,
« Limites connues ») et le collecteur Syslog attend des lignes au format
    <PRI>Mon DD HH:MM:SS HOSTNAME %FACILITY-SEV-MNEMONIC: message
Ce script interroge régulièrement chaque routeur (docker exec) et écrit une ligne à chaque
CHANGEMENT d'état réel : interface (ip link), voisin OSPF et session BGP (vtysh). Ce sont de
vrais changements observés sur les routeurs, traduits au format attendu. Ce n'est pas un
export Syslog natif de FRR : à dire tel quel en présentation.

Usage (sur la machine qui exécute le labo, avec accès à docker) :
    python lab/syslog_bridge.py --clear
    # laisser tourner ; dans un autre terminal : lab/fault-injection/inject_fault.sh link_down
Lancer le pont AVANT la panne : le premier relevé sert de référence, il n'émet rien.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

ROUTERS = {"R1": "clab-mcp-noc-lab-r1", "R2": "clab-mcp-noc-lab-r2", "R3": "clab-mcp-noc-lab-r3"}
WATCHED_INTERFACES = ("eth1", "eth2", "eth3")
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_LINK_RE = re.compile(r"^\d+:\s+(?P<name>[\w.-]+?)(?:@\S+)?:\s+<[^>]*>.*?\sstate\s+(?P<state>\w+)")


def parse_links(text: str) -> dict[str, str]:
    """`ip -o link show` -> {interface: "up"|"down"} pour les interfaces surveillées."""
    states = {}
    for line in text.splitlines():
        match = _LINK_RE.match(line.strip())
        if match and match["name"] in WATCHED_INTERFACES:
            states[match["name"]] = "up" if match["state"].upper() == "UP" else "down"
    return states


def parse_ospf(text: str) -> dict[str, dict[str, str]]:
    """`show ip ospf neighbor json` -> {router_id: {"state": "up"|"down", "iface": "ethX"}}."""
    data = json.loads(text) if text.strip() else {}
    neighbors = {}
    for router_id, entries in (data.get("neighbors") or {}).items():
        for entry in entries if isinstance(entries, list) else [entries]:
            state = str(entry.get("nbrState") or entry.get("state") or entry.get("converged") or "")
            iface = str(entry.get("ifaceName", "")).split(":")[0]
            neighbors[router_id] = {"state": "up" if state.startswith("Full") else "down", "iface": iface}
    return neighbors


def parse_bgp(text: str) -> dict[str, str]:
    """`show bgp summary json` -> {voisin: "up"|"down"}."""
    data = json.loads(text) if text.strip() else {}
    peers = {}
    for family in data.values():
        if isinstance(family, dict):
            for peer, info in (family.get("peers") or {}).items():
                peers[peer] = "up" if "Established" in str(info.get("state", "")) else "down"
    return peers


def _stamp(now: datetime) -> str:
    return f"{_MONTHS[now.month - 1]} {now.day:2d} {now:%H:%M:%S}"


def _line(sev: int, now: datetime, host: str, facility: str, mnemonic: str, message: str) -> str:
    return f"<{184 + sev}>{_stamp(now)} {host} %{facility}-{sev}-{mnemonic}: {message}"


def diff_state(host: str, prev: dict, cur: dict, now: datetime) -> list[str]:
    """Lignes Syslog pour chaque transition entre deux relevés d'un même routeur."""
    lines = []
    for iface, state in cur.get("links", {}).items():
        before = prev.get("links", {}).get(iface)
        if before and before != state:
            lines.append(_line(3, now, host, "LINK", "UPDOWN", f"Interface {iface}, changed state to {state}"))

    if "ospf" in cur and "ospf" in prev:
        for rid in sorted(set(prev["ospf"]) | set(cur["ospf"])):
            before = prev["ospf"].get(rid, {"state": "down", "iface": ""})
            after = cur["ospf"].get(rid, {"state": "down", "iface": before["iface"]})
            if before["state"] != after["state"]:
                iface = after["iface"] or before["iface"] or "?"
                move = "from FULL to DOWN" if after["state"] == "down" else "from LOADING to FULL"
                lines.append(_line(5, now, host, "OSPF", "ADJCHG", f"Process 1, Nbr {rid} on {iface} {move}"))

    if "bgp" in cur and "bgp" in prev:
        for peer in sorted(set(prev["bgp"]) | set(cur["bgp"])):
            before, after = prev["bgp"].get(peer, "down"), cur["bgp"].get(peer, "down")
            if before != after:
                lines.append(_line(5, now, host, "BGP", "ADJCHANGE", f"neighbor {peer} {after.capitalize()}"))
    return lines


def _exec(container: str, *command: str) -> str | None:
    try:
        result = subprocess.run(["docker", "exec", container, *command], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def snapshot(container: str) -> dict:
    """État courant d'un routeur. Une catégorie injoignable est omise (aucun faux événement)."""
    state = {}
    out = _exec(container, "ip", "-o", "link", "show")
    if out is not None:
        state["links"] = parse_links(out)
    for key, command, parser in (
        ("ospf", ("vtysh", "-c", "show ip ospf neighbor json"), parse_ospf),
        ("bgp", ("vtysh", "-c", "show bgp summary json"), parse_bgp),
    ):
        out = _exec(container, *command)
        if out is not None:
            try:
                state[key] = parser(out)
            except (ValueError, AttributeError):
                pass
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file", default=os.environ.get("SYSLOG_FILE_PATH", "/var/log/network_syslog.log"))
    parser.add_argument("--interval", type=float, default=2.0, help="secondes entre deux relevés")
    parser.add_argument("--clear", action="store_true", help="vider le fichier au démarrage")
    args = parser.parse_args()

    if args.clear:
        open(args.file, "w", encoding="utf-8").close()
    previous = {host: snapshot(container) for host, container in ROUTERS.items()}
    print(f"Pont Syslog actif -> {args.file} (Ctrl+C pour arrêter). Référence prise : "
          f"{ {h: sorted(s) for h, s in previous.items()} }", flush=True)
    try:
        while True:
            time.sleep(args.interval)
            for host, container in ROUTERS.items():
                current = snapshot(container)
                merged = {**previous[host], **current}  # une catégorie manquante garde son dernier état
                lines = diff_state(host, previous[host], merged, datetime.now())
                if lines:
                    with open(args.file, "a", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
                    print("\n".join(lines), flush=True)
                previous[host] = merged
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
