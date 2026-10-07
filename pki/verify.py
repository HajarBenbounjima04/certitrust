"""

Etape 4 : verification d'un certificat.
  a) Signature : verifiee avec la cle publique de la Root CA.
  b) Validite temporelle.
  c) Revocation : consultee dans le registre (source de verite,
     equivalente a ce qui finit dans la CRL).

Correspond au script 04_verify.py de la premiere version du projet.
"""

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

from . import registry
from .root_ca import ca_exists


def verify_certificate(common_name: str):
    if not ca_exists():
        raise RuntimeError("Aucune Root CA trouvee.")

    reg = registry.load_registry()
    entry = next((c for c in reg["certificates"] if c["common_name"] == common_name), None)
    if not entry:
        raise RuntimeError(f"Aucun certificat trouve pour '{common_name}'.")

    with open(registry.CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(entry["cert_path"], "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())

    # a) Signature
    try:
        ca_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
        signature_ok = True
    except InvalidSignature:
        signature_ok = False

    # b) Validite temporelle
    now = datetime.datetime.now(datetime.timezone.utc)
    time_ok = client_cert.not_valid_before_utc <= now <= client_cert.not_valid_after_utc

    # c) Revocation
    revoked = entry["status"] == "revoked"

    overall_valid = signature_ok and time_ok and not revoked

    return {
        "common_name": common_name,
        "serial_number": str(client_cert.serial_number),
        "signature_ok": signature_ok,
        "time_ok": time_ok,
        "revoked": revoked,
        "revocation_reason": entry.get("revocation_reason"),
        "overall_valid": overall_valid,
    }
