"""

Interface CLI en mode menu pour le MVP PKI "CertiTrust".

Lance simplement :
    python3 cli.py

et navigue avec le menu affiche.
"""

import pki


def pause():
    input("\n(Appuie sur Entree pour continuer...)")


def print_header():
    print("\n===== CertiTrust =====\n")


def menu_create_ca():
    print_header()
    if pki.ca_exists():
        info = pki.get_ca_info()
        print("Une Root CA existe deja :")
        print(f"  Subject : {info['subject']}")
        print(f"  Serial  : {info['serial']}")
        confirm = input("\nRecreer une nouvelle Root CA (efface tout) ? [o/N] : ").strip().lower()
        if confirm != "o":
            print("Annule.")
            pause()
            return
        pki.create_root_ca(force=True)
        print("Nouvelle Root CA creee (registre reinitialise).")
    else:
        info = pki.create_root_ca()
        print("Root CA creee avec succes :")
        print(f"  Subject : {info['subject']}")
        print(f"  Serial  : {info['serial']}")
        print(f"  Validite: {info['not_valid_before']} -> {info['not_valid_after']}")
    pause()


def menu_issue_certificate():
    print_header()
    if not pki.ca_exists():
        print("Erreur : aucune Root CA. Cree-la d'abord (option 1).")
        pause()
        return
    name = input("Nom du client (Common Name) : ").strip()
    if not name:
        print("Nom vide, annule.")
        pause()
        return
    try:
        entry = pki.issue_certificate(name)
        print(f"\nCertificat emis pour '{name}' :")
        print(f"  Serial       : {entry['serial_number']}")
        print(f"  Valide de    : {entry['not_valid_before']}")
        print(f"  Valide jusqu': {entry['not_valid_after']}")
        print(f"  Fichiers     : {entry['cert_path']}")
    except RuntimeError as e:
        print(f"Erreur : {e}")
    pause()


def menu_list_certificates():
    print_header()
    certs = pki.list_certificates()
    if not certs:
        print("Aucun certificat emis pour l'instant.")
        pause()
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
    pause()


def menu_revoke_certificate():
    print_header()
    certs = [c for c in pki.list_certificates() if c["status"] == "valid"]
    if not certs:
        print("Aucun certificat valide a revoquer.")
        pause()
        return
    print("Certificats valides :")
    for c in certs:
        print(f"  - {c['common_name']}")
    name = input("\nNom du certificat a revoquer : ").strip()
    reasons = list(pki.REASON_MAP.keys())
    print(f"\nRaisons possibles : {', '.join(reasons)}")
    reason = input("Raison (Entree = 'unspecified') : ").strip() or "unspecified"
    if reason not in pki.REASON_MAP:
        print("Raison invalide, utilisation de 'unspecified'.")
        reason = "unspecified"
    try:
        pki.revoke_certificate(name, reason=reason)
        print(f"\nCertificat '{name}' revoque (raison : {reason}).")
        print("N'oublie pas de regenerer la CRL (option 5) pour publier cette revocation.")
    except RuntimeError as e:
        print(f"Erreur : {e}")
    pause()


def menu_generate_crl():
    print_header()
    try:
        result = pki.generate_crl()
        print("CRL generee avec succes :")
        print(f"  Fichier       : {result['crl_path']}")
        print(f"  Last update   : {result['last_update']}")
        print(f"  Next update   : {result['next_update']}")
        print(f"  Nb revoques   : {result['revoked_count']}")
    except RuntimeError as e:
        print(f"Erreur : {e}")
    pause()


def menu_verify_certificate():
    print_header()
    certs = pki.list_certificates()
    if not certs:
        print("Aucun certificat emis pour l'instant.")
        pause()
        return
    name = input("Nom du certificat a verifier : ").strip()
    try:
        result = pki.verify_certificate(name)
        print(f"\n=== Verification de '{name}' ===")
        print(f"  Signature valide (emis par la CA) : {'OUI' if result['signature_ok'] else 'NON'}")
        print(f"  Dans la periode de validite        : {'OUI' if result['time_ok'] else 'NON'}")
        print(f"  Revoque                            : {'OUI' if result['revoked'] else 'NON'}"
              + (f" (raison: {result['revocation_reason']})" if result["revoked"] else ""))
        print(f"\n  ==> Certificat {'VALIDE' if result['overall_valid'] else 'INVALIDE / REVOQUE'}")
    except RuntimeError as e:
        print(f"Erreur : {e}")
    pause()


def menu_verify_openssl():
    print_header()
    certs = pki.list_certificates()
    if not certs:
        print("Aucun certificat emis pour l'instant.")
        pause()
        return
    name = input("Nom du certificat a verifier avec openssl : ").strip()
    try:
        result = pki.verify_with_openssl(name)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        pause()
        return

    print(f"\n=== Verification OpenSSL de '{name}' ===")

    chain = result["chain_check"]
    print(f"\n$ {chain['command']}")
    print(chain["stdout"] or chain["stderr"])
    print(f"  ==> {'OK (chaine de confiance valide)' if chain['ok'] else 'ECHEC'}")

    crl = result["crl_check"]
    if crl:
        print(f"\n$ {crl['command']}")
        print(crl["stdout"] or crl["stderr"])
        print(f"  ==> {'OK (non revoque)' if crl['ok'] else 'ECHEC (revoque ou invalide)'}")
    else:
        print("\n(Aucune CRL generee pour l'instant, verification CRL ignoree.)")

    pause()


MENU_ACTIONS = {
    "1": menu_create_ca,
    "2": menu_issue_certificate,
    "3": menu_list_certificates,
    "4": menu_revoke_certificate,
    "5": menu_generate_crl,
    "6": menu_verify_certificate,
    "7": menu_verify_openssl,
}


def main():
    while True:
        print_header()
        print("1. Create CA")
        print("2. Issue certificate")
        print("3. List certificates")
        print("4. Revoke certificate")
        print("5. Generate CRL")
        print("6. Verify certificate")
        print("7. Verify with OpenSSL")
        print("8. Exit")
        choice = input("\nChoix : ").strip()

        if choice == "8":
            print("\nAu revoir.")
            break
        action = MENU_ACTIONS.get(choice)
        if action:
            action()
        else:
            print("Choix invalide.")
            pause()


if __name__ == "__main__":
    main()
