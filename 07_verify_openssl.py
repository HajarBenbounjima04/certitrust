"""

Script autonome  :

    python3 07_verify_openssl.py client1

Appelle pki.verify_with_openssl() -- la logique vit dans pki/openssl_check.py.
Contrairement a 06_verify_certificate.py (qui verifie avec NOTRE code Python),
ce script demande au vrai binaire `openssl` de refaire la verification de
son cote, de maniere totalement independante.
"""

import sys

import pki


def main():
    if len(sys.argv) < 2:
        print("Usage : python3 07_verify_openssl.py <common_name>")
        sys.exit(1)

    name = sys.argv[1]
    try:
        result = pki.verify_with_openssl(name)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        sys.exit(1)

    print(f"=== Verification OpenSSL de '{name}' ===\n")

    chain = result["chain_check"]
    print(f"$ {chain['command']}")
    print(chain["stdout"] or chain["stderr"])
    print(f"==> {'OK (chaine de confiance valide)' if chain['ok'] else 'ECHEC'}\n")

    crl = result["crl_check"]
    if crl:
        print(f"$ {crl['command']}")
        print(crl["stdout"] or crl["stderr"])
        print(f"==> {'OK (non revoque)' if crl['ok'] else 'ECHEC (revoque ou invalide)'}")
    else:
        print("(Aucune CRL generee pour l'instant, verification CRL ignoree.)")


if __name__ == "__main__":
    main()
