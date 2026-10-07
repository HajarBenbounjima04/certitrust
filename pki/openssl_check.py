"""
mecanisme de validation EXTERNE, via le vrai binaire `openssl`


"""

import os
import subprocess

from . import registry


def _find_cert_path(common_name: str) -> str:
    entry = next(
        (c for c in registry.list_certificates() if c["common_name"] == common_name),
        None,
    )
    if not entry:
        raise RuntimeError(f"Aucun certificat trouve pour '{common_name}'.")
    return entry["cert_path"]


def _run(cmd):
    """Execute une commande et retourne un dict pret a afficher."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "ok": proc.returncode == 0,
    }


def verify_with_openssl(common_name: str):
    """
    Lance deux verifications avec le binaire openssl :
      1) `openssl verify -CAfile root_ca.cert.pem <cert>`
         -> valide uniquement la chaine de confiance (signature + dates).
      2) `openssl verify -crl_check -CAfile <ca+crl> <cert>`
         -> valide EN PLUS que le certificat n'est pas dans la CRL.
         (seulement si une CRL a deja ete generee)
    """
    if not os.path.exists(registry.CA_CERT_PATH):
        raise RuntimeError("Aucune Root CA trouvee.")

    cert_path = _find_cert_path(common_name)

    chain_result = _run(["openssl", "verify", "-CAfile", registry.CA_CERT_PATH, cert_path])

    crl_result = None
    if os.path.exists(registry.CRL_PATH):
        chain_with_crl_path = os.path.join(registry.CA_DIR, "ca_chain_with_crl.pem")
        with open(chain_with_crl_path, "wb") as out:
            with open(registry.CA_CERT_PATH, "rb") as f:
                out.write(f.read())
            with open(registry.CRL_PATH, "rb") as f:
                out.write(f.read())
        crl_result = _run([
            "openssl", "verify", "-crl_check",
            "-CAfile", chain_with_crl_path,
            cert_path,
        ])

    return {
        "common_name": common_name,
        "chain_check": chain_result,
        "crl_check": crl_result,
    }
