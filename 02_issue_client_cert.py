"""

Script autonome :

    python3 02_issue_client_cert.py client1

Appelle pki.issue_certificate() -- la logique vit dans pki/client_cert.py.
"""

import sys

import pki


def main():
    if len(sys.argv) < 2:
        print("Usage : python3 02_issue_client_cert.py <common_name>")
        sys.exit(1)

    name = sys.argv[1]
    try:
        entry = pki.issue_certificate(name)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        sys.exit(1)

    print(f"Certificat emis pour '{name}'.")
    print(f"  Serial        : {entry['serial_number']}")
    print(f"  Valide de     : {entry['not_valid_before']}")
    print(f"  Valide jusqu' : {entry['not_valid_after']}")
    print(f"  Certificat    : {entry['cert_path']}")
    print(f"  Cle privee    : {entry['key_path']}")


if __name__ == "__main__":
    main()
