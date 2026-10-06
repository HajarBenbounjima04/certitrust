"""

Script autonome :

    python3 04_revoke_certificate.py client2 key_compromise

Appelle pki.revoke_certificate() -- la logique vit dans pki/registry.py.
La raison est optionnelle (defaut : "unspecified"). Raisons valides :
unspecified, key_compromise, ca_compromise, affiliation_changed,
superseded, cessation_of_operation.
"""

import sys

import pki


def main():
    if len(sys.argv) < 2:
        print("Usage : python3 04_revoke_certificate.py <common_name> [reason]")
        sys.exit(1)

    name = sys.argv[1]
    reason = sys.argv[2] if len(sys.argv) > 2 else "unspecified"
    if reason not in pki.REASON_MAP:
        print(f"Raison invalide '{reason}'. Raisons valides : {', '.join(pki.REASON_MAP.keys())}")
        sys.exit(1)

    try:
        pki.revoke_certificate(name, reason=reason)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        sys.exit(1)

    print(f"Certificat '{name}' revoque (raison : {reason}).")
    print("N'oublie pas de regenerer la CRL : python3 05_generate_crl.py")


if __name__ == "__main__":
    main()
