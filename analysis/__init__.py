"""Analyse et corrélation IA (bloc 4) : corrélation multi-sources, RCA, rapport d'incident.

Tout le calcul est déterministe et s'appuie sur le collecteur (`collector/`).
Le modèle de langage n'intervient qu'en aval, pour interpréter les constats.
"""

from analysis.correlation import correlate_alarms
from analysis.incident_report import generate_incident_report
from analysis.rca import analyze_root_cause

__all__ = ["correlate_alarms", "analyze_root_cause", "generate_incident_report"]
