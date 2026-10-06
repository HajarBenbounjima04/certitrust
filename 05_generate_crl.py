"""

Script autonome :

    python3 05_generate_crl.py

Appelle pki.generate_crl() -- la logique vit dans pki/crl.py.
Construit la CRL a partir de TOUS les certificats actuellement marques
"revoked" dans le registre (voir 04_revoke_certificate.py).
"""

import pki


def main():
    try:
        result = pki.generate_crl()
    except RuntimeError as e:
        print(f"Erreur : {e}")
        return

    print("CRL generee et signee avec succes.")
    print(f"  Fichier      : {result['crl_path']}")
    print(f"  Last update  : {result['last_update']}")
    print(f"  Next update  : {result['next_update']}")
    print(f"  Nb revoques  : {result['revoked_count']}")


if __name__ == "__main__":
    main()
