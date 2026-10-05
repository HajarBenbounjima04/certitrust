# CertiTrust — MVP PKI (scripts + CLI + Web)

Projet Python implémentant une Root CA minimale, avec **trois façons de
l'utiliser** au-dessus de la même logique cryptographique (aucune duplication) :
- des **scripts numérotés autonomes** (`01_...py` à `06_...py`), un par étape,
- une **CLI** avec menu interactif (`cli.py`),
- un **dashboard Web** (`web_app.py`, Flask).

## Fonctionnalités (communes aux trois interfaces)

1. **Create CA** : génère une clé privée RSA 4096 bits + un certificat X.509
   auto-signé (Root CA).
2. **Issue certificate** : génère une clé + CSR pour un client, signé par la Root CA
   (Subject = client, Issuer = Root CA).
3. **List certificates** : liste tous les certificats émis (registre JSON), avec leur statut.
4. **Revoke certificate** : marque un certificat comme révoqué (avec une raison).
5. **Generate CRL** : construit et signe la CRL à partir des certificats marqués révoqués.
6. **Verify certificate** : vérifie la signature, la validité temporelle, et l'absence
   dans la CRL / le registre de révocation (avec notre propre code Python).
7. **Verify with OpenSSL (bonus)** : relance une vérification **indépendante**, avec
   le vrai binaire `openssl` (pas notre code), pour prouver que l'implémentation
   est conforme à un outil de référence de l'industrie.

## Structure du projet

```
certitrust/
├── pki/                        # TOUTE la logique cryptographique, un module par etape
│   ├── __init__.py             #   ré-exporte tout (import pki -> pki.create_root_ca(), etc.)
│   ├── registry.py             #   chemins de fichiers + registre JSON + list/revoke
│   ├── root_ca.py               #   Etape 1 : creation de la Root CA
│   ├── client_cert.py           #   Etape 2 : emission d'un certificat client
│   ├── crl.py                   #   Etape 3 : emission de la CRL
│   ├── verify.py                #   Etape 4 (bonus) : verification (code Python)
│   └── openssl_check.py         #   Etape 4bis (bonus) : verification via le vrai openssl
│
├── 01_create_root_ca.py        # Script autonome : python3 01_create_root_ca.py
├── 02_issue_client_cert.py      # Script autonome : python3 02_issue_client_cert.py <nom>
├── 03_list_certificates.py      # Script autonome : python3 03_list_certificates.py
├── 04_revoke_certificate.py     # Script autonome : python3 04_revoke_certificate.py <nom> [raison]
├── 05_generate_crl.py           # Script autonome : python3 05_generate_crl.py
├── 06_verify_certificate.py     # Script autonome : python3 06_verify_certificate.py <nom>
├── 07_verify_openssl.py         # Script autonome (bonus) : python3 07_verify_openssl.py <nom>
│
├── cli.py                       # Interface CLI avec menu (Option A)
├── web_app.py                    # Application Flask (Option B)
├── templates/
│   └── dashboard.html           # Template du dashboard Web
├── requirements.txt
├── ca/                          # Généré à l'exécution : clé/cert CA, CRL, registry.json
└── clients/<nom>/               # Généré à l'exécution : clé/CSR/cert par client
```

Le package `pki/` est le **seul** endroit où la cryptographie est implémentée,
maintenant séparée en modules (comme dans la toute première version du projet),
au lieu d'un seul fichier `pki_core.py`. Les scripts numérotés, la CLI et l'app
Web ne font qu'appeler ces fonctions — pas de duplication de logique.

Les trois interfaces partagent le **même état** (mêmes dossiers `ca/` et
`clients/`) : tu peux créer la CA avec `01_create_root_ca.py`, émettre un
certificat avec le menu CLI, puis le révoquer depuis le dashboard Web — tout
reste cohérent.

## Utilisation des scripts autonomes (dans l'ordre)

```bash
python3 01_create_root_ca.py
python3 02_issue_client_cert.py client1
python3 02_issue_client_cert.py client2
python3 03_list_certificates.py
python3 04_revoke_certificate.py client2 key_compromise
python3 05_generate_crl.py
python3 06_verify_certificate.py client1   # -> VALIDE
python3 06_verify_certificate.py client2   # -> REVOQUE
python3 07_verify_openssl.py client1       # -> OK (openssl)
python3 07_verify_openssl.py client2       # -> certificate revoked (openssl)
```

## Installation

```bash
pip install -r requirements.txt --break-system-packages
```

## Option A — Utiliser la CLI

```bash
python3 cli.py
```

```
===== CertiTrust =====

1. Create CA
2. Issue certificate
3. List certificates
4. Revoke certificate
5. Generate CRL
6. Verify certificate
7. Exit
```

Navigue simplement en tapant le numéro de l'action, puis suis les instructions
(nom du certificat, raison de révocation, etc.).

## Option B — Utiliser le dashboard Web

```bash
python3 web_app.py
```

Puis ouvre **http://127.0.0.1:5000** dans ton navigateur. Le dashboard affiche :
- l'état de la Root CA (ou un bouton "Create CA" si elle n'existe pas encore),
- le nombre de certificats émis / valides / révoqués,
- un tableau de tous les certificats avec leur statut,
- des formulaires pour émettre, révoquer, générer la CRL, et vérifier un certificat.

Les deux interfaces partagent le **même état** (même dossier `ca/` et `clients/`) :
tu peux commencer avec la CLI et continuer avec le Web, ou inversement.

## Vérification externe avec OpenSSL (bonus)

```bash
# Inspecter le certificat de la Root CA
openssl x509 -in ca/root_ca.cert.pem -text -noout

# Vérifier la chaîne de confiance d'un certificat client
openssl verify -CAfile ca/root_ca.cert.pem clients/client1/client.cert.pem

# Inspecter la CRL
openssl crl -in ca/root_ca.crl.pem -text -noout

# Vérifier en tenant compte de la révocation
cat ca/root_ca.cert.pem ca/root_ca.crl.pem > ca/ca_chain_with_crl.pem
openssl verify -crl_check -CAfile ca/ca_chain_with_crl.pem clients/client1/client.cert.pem
```

## Points clés pour le rapport

- **Registre JSON** (`ca/registry.json`) : ajouté par rapport à la version scripts pure,
  pour pouvoir *lister* et *retrouver* facilement les certificats émis (nécessaire pour
  les fonctionnalités "List" et "Revoke" des deux interfaces). C'est un choix d'implémentation
  du MVP, pas une norme PKI — en production, cette information vivrait dans une vraie base
  de données ou serait déduite directement de la CRL/des logs de la CA.
- **Architecture en couches** : `pki_core.py` (logique) / `cli.py` + `web_app.py`
  (présentation) — permet de réutiliser exactement le même code cryptographique
  sous deux interfaces différentes, et facilite les tests.
- **Limites** (à discuter en analyse critique) :
  - Un seul niveau de CA (pas de CA intermédiaire).
  - Clé privée de la CA non protégée par mot de passe / HSM.
  - Pas de RA séparée.
  - CRL uniquement (pas d'OCSP).
  - Le serveur Flask de développement (`debug=True`) n'est pas destiné à la production.
