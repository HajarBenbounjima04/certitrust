"""

Etape 3 : construction et signature de la CRL, a partir des certificats
marques "revoked" dans le registre.

"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import registry
from .root_ca import ca_exists

REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
}


def generate_crl():
    if not ca_exists():
        raise RuntimeError("Aucune Root CA trouvee.")

    with open(registry.CA_KEY_PATH, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(registry.CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    reg = registry.load_registry()
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=30))
    )

    revoked_list = [c for c in reg["certificates"] if c["status"] == "revoked"]
    for c in revoked_list:
        revocation_date = datetime.datetime.fromisoformat(c["revocation_date"])
        reason_flag = REASON_MAP.get(c["revocation_reason"], x509.ReasonFlags.unspecified)
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(c["serial_number"]))
            .revocation_date(revocation_date)
            .add_extension(x509.CRLReason(reason_flag), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    # SIGNATURE de la CRL par la cle privee de la CA
    crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    with open(registry.CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    return {
        "crl_path": registry.CRL_PATH,
        "last_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat(),
        "revoked_count": len(revoked_list),
    }
