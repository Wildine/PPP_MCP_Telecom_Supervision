"""
Collecteur NETCONF - outil MCP cible : netconf_get.

Lecture seule stricte : seules les opérations <get> et
<get-config> (running/candidate en lecture) sont utilisées.
Aucune opération <edit-config> n'est implémentée ici, comme
l'exige le cahier des charges (confinement en lecture seule).

Pré-requis pour le mode réel :
    pip install ncclient
"""

from typing import Any

from collector import config
from collector.common.schema import make_error_response, make_response
from collector.common.utils import fixtures_dir, load_text_fixture, logger

FIXTURES = fixtures_dir(__file__)

# Filtres YANG disponibles en mode simulé (mappage nom logique -> fixture)
_SIMULATED_FILTERS = {
    "interfaces": "interfaces_config.xml",
}


def _real_netconf_get(device_ip: str, filter_xml: str | None = None) -> str:
    """Exécute un <get-config> réel via ncclient (datastore running)."""
    from ncclient import manager

    with manager.connect(
        host=device_ip,
        port=config.NETCONF_PORT,
        username=config.NETCONF_USERNAME,
        password=config.NETCONF_PASSWORD,
        hostkey_verify=False,
        timeout=config.NETCONF_TIMEOUT,
    ) as m:
        reply = m.get_config(source="running", filter=("subtree", filter_xml) if filter_xml else None)
        return reply.data_xml


def netconf_get(
    device_ip: str,
    yang_filter: str = "interfaces",
    filter_xml: str | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Récupère une portion de configuration YANG en lecture seule.

    `yang_filter` sert de clé logique en mode simulé (ex:
    "interfaces"). En mode réel, `filter_xml` est le filtre
    subtree XML brut à envoyer via ncclient ; à défaut,
    récupère la configuration complète (déconseillé en prod,
    à limiter dans le labo).
    """
    simulated = config.is_simulated(mode)
    try:
        if simulated:
            fixture_name = _SIMULATED_FILTERS.get(yang_filter)
            if fixture_name is None:
                return make_error_response(
                    "netconf", device_ip, f"Filtre YANG simulé inconnu: {yang_filter}", simulated=True
                )
            xml_content = load_text_fixture(FIXTURES / fixture_name)
            return make_response("netconf", device_ip, {"filter": yang_filter, "xml": xml_content}, simulated=True)

        xml_content = _real_netconf_get(device_ip, filter_xml)
        return make_response("netconf", device_ip, {"filter": yang_filter, "xml": xml_content}, simulated=False)

    except Exception as exc:  # noqa: BLE001
        logger.error("netconf_get failed for %s: %s", device_ip, exc)
        return make_error_response("netconf", device_ip, str(exc), simulated=simulated)
