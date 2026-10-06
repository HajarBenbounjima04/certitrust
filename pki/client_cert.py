"""

Etape 2 : generation d'une cle client + CSR + signature par la Root CA.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import registry
from .root_ca import ca_exists


def issue_certificate(common_name: str, validity_days: int = 365):
    if not ca_exists():
        raise RuntimeError("Aucune Root CA trouvee. Cree-la d'abord (root_ca.create_root_ca).")

    reg = registry.load_registry()
    if any(c["common_name"] == common_name and c["status"] == "valid" for c in reg["certificates"]):
        raise RuntimeError(f"Un certificat valide existe deja pour '{common_name}'.")

    with open(registry.CA_KEY_PATH, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(registry.CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    client_dir = os.path.join(registry.CLIENTS_DIR, common_name)
    os.makedirs(client_dir, exist_ok=True)

    # a) Le client genere SA PROPRE paire de cles
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # b) Construction de la CSR (signee par le client, preuve de possession de la cle)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ENSET-MVP-PKI-Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .sign(client_private_key, hashes.SHA256())
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    # c) La CA signe le certificat avec SA PROPRE cle privee (pas celle du client)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    key_path = os.path.join(client_dir, "client.key.pem")
    csr_path = os.path.join(client_dir, "client.csr.pem")
    cert_path = os.path.join(client_dir, "client.cert.pem")

    with open(key_path, "wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    with open(cert_path, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    entry = {
        "common_name": common_name,
        "serial_number": str(client_cert.serial_number),
        "not_valid_before": client_cert.not_valid_before_utc.isoformat(),
        "not_valid_after": client_cert.not_valid_after_utc.isoformat(),
        "status": "valid",
        "revocation_date": None,
        "revocation_reason": None,
        "cert_path": cert_path,
        "key_path": key_path,
    }
    reg["certificates"] = [c for c in reg["certificates"] if c["common_name"] != common_name]
    reg["certificates"].append(entry)
    registry.save_registry(reg)

    return entry
