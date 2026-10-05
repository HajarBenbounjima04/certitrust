"""

Script autonome, executable directement en ligne de commande :

    python3 01_create_root_ca.py

Ne fait qu'appeler pki.create_root_ca() -- toute la logique cryptographique
vit dans pki/root_ca.py, pas ici. Ce script est juste une "porte d'entree"
en ligne de commande, pour ceux qui veulent creer la CA sans passer par
le menu (cli.py) ou le dashboard (web_app.py).
"""

import sys

import pki


def main():
    force = "--force" in sys.argv
    try:
        info = pki.create_root_ca(force=force)
    except RuntimeError as e:
        print(f"Erreur : {e}")
        print("Astuce : relance avec --force pour recreer la CA (efface tout).")
        sys.exit(1)

    print("Root CA generee avec succes.")
    print(f"  Subject   : {info['subject']}")
    print(f"  Serial    : {info['serial']}")
    print(f"  Validite  : {info['not_valid_before']} -> {info['not_valid_after']}")


if __name__ == "__main__":
    main()
