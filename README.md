# MCP NOC Supervision - PPP Groupe 3 (EC2LT)

Assistant de diagnostic NOC basé sur un serveur MCP (FastMCP), déployé sur un
réseau émulé (Containerlab + FRRouting).

## Structure

```
.
├── lab/                 # Bloc 1 : Containerlab, injection de pannes
├── collector/           # Bloc 2 : backend de collecte Python (terminé, mode simulé)
├── mcp_server/          # Bloc 3 : serveur FastMCP, outils, resources (topologie, inventaire, IPAM, runbooks)
├── analysis/            # Bloc 4 : corrélation, RCA, rapports d'incident
├── security/            # Bloc 5 : Keycloak (RBAC/JWT), validation humaine, audit
├── docs/                # architecture.md, collector.md
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Démarrage

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m pytest collector/tests -q
```

Documentation du collecteur (fonctions, mode simulé/réel, sécurité) : [docs/collector.md](docs/collector.md).
