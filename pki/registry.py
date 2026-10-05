"""

Etat partage par tout le package : chemins des fichiers, et le "registre"
(ca/registry.json) qui garde la trace de tous les certificats emis.

C'est le seul module que les autres (root_ca, client_cert, crl, verify)
importent tous, pour ne jamais dupliquer la lecture/ecriture du registre
ni les chemins de fichiers.
"""

import datetime
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_DIR = os.path.join(BASE_DIR, "ca")
CLIENTS_DIR = os.path.join(BASE_DIR, "clients")

CA_KEY_PATH = os.path.join(CA_DIR, "root_ca.key.pem")
CA_CERT_PATH = os.path.join(CA_DIR, "root_ca.cert.pem")
CRL_PATH = os.path.join(CA_DIR, "root_ca.crl.pem")
REGISTRY_PATH = os.path.join(CA_DIR, "registry.json")


def load_registry():
    if not os.path.exists(REGISTRY_PATH):
        return {"certificates": []}
    with open(REGISTRY_PATH, "r") as f:
        return json.load(f)


def save_registry(registry):
    os.makedirs(CA_DIR, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2, default=str)


def list_certificates():
    return load_registry()["certificates"]


def revoke_certificate(common_name: str, reason: str = "unspecified"):
    registry = load_registry()
    found = None
    for c in registry["certificates"]:
        if c["common_name"] == common_name and c["status"] == "valid":
            found = c
            break
    if not found:
        raise RuntimeError(f"Aucun certificat VALIDE trouve pour '{common_name}'.")

    found["status"] = "revoked"
    found["revocation_date"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    found["revocation_reason"] = reason
    save_registry(registry)
    return found
