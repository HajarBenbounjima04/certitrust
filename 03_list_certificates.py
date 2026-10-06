"""

Script autonome :

    python3 03_list_certificates.py

Appelle pki.list_certificates() -- la logique vit dans pki/registry.py.
"""

import pki


def main():
    certs = pki.list_certificates()
    if not certs:
        print("Aucun certificat emis pour l'instant.")
        return

    print(f"{'Common Name':<20} {'Serial':<25} {'Statut':<10} {'Expire le'}")
    print("-" * 80)
    for c in certs:
        serial_short = c["serial_number"][:20] + "..."
        expire = c["not_valid_after"][:10]
        print(f"{c['common_name']:<20} {serial_short:<25} {c['status']:<10} {expire}")

    valid_count = sum(1 for c in certs if c["status"] == "valid")
    revoked_count = sum(1 for c in certs if c["status"] == "revoked")
    print(f"\nTotal : {len(certs)} certificats  ({valid_count} valides, {revoked_count} revoques)")


if __name__ == "__main__":
    main()
