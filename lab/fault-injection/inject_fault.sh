#!/bin/bash
set -e
ACTION="${1:-status}"

case "$ACTION" in
  link_down)
    echo "[FAULT] Coupure du lien primaire R1 <-> R2"
    docker exec clab-mcp-noc-lab-r1 ip link set eth1 down
    docker exec clab-mcp-noc-lab-r2 ip link set eth1 down
    ;;
  link_up)
    echo "[RECOVERY] Retablissement du lien primaire R1 <-> R2"
    docker exec clab-mcp-noc-lab-r1 ip link set eth1 up
    docker exec clab-mcp-noc-lab-r2 ip link set eth1 up
    ;;
  status)
    echo "=== OSPF sur R1 ===" 
    docker exec clab-mcp-noc-lab-r1 vtysh -c "show ip ospf neighbor"
    echo "=== BGP sur R1 ===" 
    docker exec clab-mcp-noc-lab-r1 vtysh -c "show ip bgp summary"
    echo "=== Route vers 192.168.3.0/24 ===" 
    docker exec clab-mcp-noc-lab-r1 vtysh -c "show ip route 192.168.3.0/24"
    ;;
  *)
    echo "Usage: $0 [link_down|link_up|status]"
    exit 1
    ;;
esac
