FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nfdump tshark iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ collector/
COPY analysis/ analysis/
COPY security/ security/
COPY mcp_server/ mcp_server/

# Mode simulé par défaut ; en réel, injecter les secrets via l'environnement.
ENV COLLECTOR_MODE=simulated
RUN useradd -m noc
USER noc

# TODO (bloc 3) : remplacer par le lancement du serveur MCP, ex. ["python", "-m", "mcp_server.server"]
CMD ["python", "-m", "pytest", "collector/tests", "-q"]
