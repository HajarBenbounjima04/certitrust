"""
Ce package regroupe TOUTE la logique cryptographique du MVP, separee
en modules par responsabilite (au lieu d'un seul gros fichier) :

    pki/registry.py     -> chemins de fichiers + registre JSON + list/revoke
    pki/root_ca.py       -> Etape 1 : creation de la Root CA
    pki/client_cert.py   -> Etape 2 : emission d'un certificat client
    pki/crl.py           -> Etape 3 : emission de la CRL
    pki/verify.py        -> Etape 4 (bonus) : verification
 
"""

from .root_ca import ca_exists, get_ca_info, create_root_ca
from .client_cert import issue_certificate
from .registry import list_certificates, revoke_certificate
from .crl import generate_crl, REASON_MAP
from .verify import verify_certificate
from .openssl_check import verify_with_openssl

__all__ = [
    "ca_exists",
    "get_ca_info",
    "create_root_ca",
    "issue_certificate",
    "list_certificates",
    "revoke_certificate",
    "generate_crl",
    "REASON_MAP",
    "verify_certificate",
    "verify_with_openssl",
]
