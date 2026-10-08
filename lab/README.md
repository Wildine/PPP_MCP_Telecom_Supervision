# Laboratoire réseau émulé (Containerlab + FRRouting)

Topologie : 3 routeurs FRR (R1, R2, R3), un client (192.168.1.10) et un serveur (192.168.3.10).
iBGP AS 65000 entre les loopbacks, OSPF zone 0, lien de secours R1-R3 avec coût 100.

## Adressage

| Lien | Réseau | R1 | R2 | R3 |
|---|---|---|---|---|
| R1-R2 | 10.0.12.0/30 | .1 | .2 | |
| R2-R3 | 10.0.23.0/30 | | .1 | .2 |
| R1-R3 (secours) | 10.0.13.0/30 | .1 | | .2 |
| Loopback | /32 | 10.255.0.1 | 10.255.0.2 | 10.255.0.3 |
| LAN client | 192.168.1.0/24 | .1 | | |
| LAN serveur | 192.168.3.0/24 | | | .1 |

## Déploiement

```bash
cd lab
set -a; source ../.env; set +a   # SNMPV3_USER, SNMPV3_AUTH_KEY, SNMPV3_PRIV_KEY, CLI_USERNAME, CLI_PASSWORD
sudo -E clab deploy -t containerlab/topology.clab.yml
```

Attendre 10 à 15 secondes avant de vérifier.

## Accès pour le collecteur

- SNMPv3 authPriv (SHA/AES), lecture seule, vue limitée : system, interfaces, IP, OSPF, BGP.
  Cible : adresse de gestion du routeur (`containerlab inspect`), port 161.
- SSH (port 22) avec le compte CLI_USERNAME ; le shell est vtysh. La lecture seule est
  garantie par la liste blanche du collecteur, pas par le routeur.
- Secrets lus depuis le `.env` de la racine (les mêmes variables que le collecteur), aucun mot de passe dans le dépôt.
- Si le `.env` vient de Windows : `dos2unix ../.env` avant `source`.

## Scénario de panne

```bash
./fault-injection/inject_fault.sh status
./fault-injection/inject_fault.sh link_down   # coupe R1-R2, bascule sur le lien de secours
./fault-injection/inject_fault.sh status
./fault-injection/inject_fault.sh link_up
```

## Limites connues

- Pas encore de NETCONF, de Syslog distant ni d'export NetFlow.
- La MIB QoS n'existe pas sur FRRouting.
- Voisins BGP du lab (10.255.0.x, AS 65000) différents des fixtures du collecteur
  (10.0.0.2 AS 65002, 10.0.0.6 AS 65003).
- Déploiement non testé dans cet environnement : à valider sur la machine qui exécute Containerlab.

Note : les mots de passe ne doivent pas contenir `|` ni `&` (utilisés par la commande sed du déploiement).
