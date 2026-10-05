"""

Etape 1 : creation de la Root CA (cle privee RSA + certificat auto-signe).

"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import registry


def ca_exists():
    return os.path.exists(registry.CA_KEY_PATH) and os.path.exists(registry.CA_CERT_PATH)


def get_ca_info():
    if not ca_exists():
        return None
    with open(registry.CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return {
        "subject": ca_cert.subject.rfc4514_string(),
        "serial": str(ca_cert.serial_number),
        "not_valid_before": ca_cert.not_valid_before_utc.isoformat(),
        "not_valid_after": ca_cert.not_valid_after_utc.isoformat(),
    }


def create_root_ca(common_name="MVP Root CA", force=False):
    if ca_exists() and not force:
        raise RuntimeError("Une Root CA existe deja. Passe force=True pour en recreer une.")

    os.makedirs(registry.CA_DIR, exist_ok=True)

    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ENSET-MVP-PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    root_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)                       # Issuer == Subject => auto-signe
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()), critical=False)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())   # auto-signature
    )

    with open(registry.CA_KEY_PATH, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(registry.CA_CERT_PATH, "wb") as f:
        f.write(root_ca_cert.public_bytes(serialization.Encoding.PEM))

    # Le registre est remis a zero a chaque (re)creation de CA
    registry.save_registry({"certificates": []})

    return get_ca_info()
