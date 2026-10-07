"""

Script autonome :

    python3 06_verify_certificate.py client1

Appelle pki.verify_certificate() -- la logique vit dans pki/verify.py.
Affiche aussi les commandes OpenSSL equivalentes, a lancer en ligne de
commande pour une verification independante de notre propre code Python.
"""

import sys

import pki
from pki import registry


def print_openssl_commands(common_name: str):
    client_dir = f"{registry.CLIENTS_DIR}/{common_name}"
    print("\n=== Commandes OpenSSL equivalentes ===\n")
    print(f"openssl x509 -in {registry.CA_CERT_PATH} -text -noout")
    print(f"openssl x509 -in {client_dir}/client.cert.pem -text -noout")
    print(f"openssl verify -CAfile {registry.CA_CERT_PATH} {client_dir}/client.cert.pem")
    print(f"openssl crl -in {registry.CRL_PATH} -text -noout")
    print(f"cat {registry.CA_CERT_PATH} {registry.CRL_PATH} > {registry.CA_DIR}/ca_chain_with_crl.pem")
    print(f"openssl verify -crl_check -CAfile {registry.CA_DIR}/ca_chain_with_crl.pem {client_dir}/client.cert.pem")


def main():
    if len(sys.argv) < 2:
        print("Usage : python3 06_verify_certificate.py <common_name>")
        sys.exit(1)

    name = sys.argv[1]
    try:
        result = pki.verify_certificate(name)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        sys.exit(1)

    print(f"=== Verification de '{name}' ===")
    print(f"  Signature valide (emis par la CA) : {'OUI' if result['signature_ok'] else 'NON'}")
    print(f"  Dans la periode de validite        : {'OUI' if result['time_ok'] else 'NON'}")
    print(f"  Revoque                            : {'OUI' if result['revoked'] else 'NON'}"
          + (f" (raison: {result['revocation_reason']})" if result["revoked"] else ""))
    print(f"\n  ==> Certificat {'VALIDE' if result['overall_valid'] else 'INVALIDE / REVOQUE'}")

    print_openssl_commands(name)


if __name__ == "__main__":
    main()
