"""

Interface Web (dashboard) pour le MVP PKI "CertiTrust", basee sur Flask.

Lancement :
    python3 web_app.py
puis ouvrir http://127.0.0.1:5000 dans un navigateur.

Toute la logique cryptographique vient du package pki/ (aucune duplication) :
cette app ne fait que l'affichage + le traitement des formulaires.
"""

from flask import Flask, redirect, render_template, request, url_for, flash, session

import pki

app = Flask(__name__)
app.secret_key = "mvp-pki-demo-secret"  # suffisant pour un MVP pedagogique local


@app.route("/")
def dashboard():
    ca_info = pki.get_ca_info()
    certs = pki.list_certificates()
    valid_count = sum(1 for c in certs if c["status"] == "valid")
    revoked_count = sum(1 for c in certs if c["status"] == "revoked")
    # Resultat de la derniere verification OpenSSL (affiche une fois, puis efface)
    openssl_result = session.pop("openssl_result", None)
    return render_template(
        "dashboard.html",
        ca_info=ca_info,
        certs=certs,
        valid_count=valid_count,
        revoked_count=revoked_count,
        reasons=list(pki.REASON_MAP.keys()),
        openssl_result=openssl_result,
    )


@app.route("/ca/create", methods=["POST"])
def create_ca():
    force = pki.ca_exists()
    try:
        pki.create_root_ca(force=force)
        flash("Root CA creee avec succes." + (" (ancienne CA remplacee)" if force else ""), "success")
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/certificates/issue", methods=["POST"])
def issue_certificate():
    name = request.form.get("common_name", "").strip()
    if not name:
        flash("Le nom du certificat ne peut pas etre vide.", "error")
        return redirect(url_for("dashboard"))
    try:
        pki.issue_certificate(name)
        flash(f"Certificat emis pour '{name}'.", "success")
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/certificates/revoke", methods=["POST"])
def revoke_certificate():
    name = request.form.get("common_name", "").strip()
    reason = request.form.get("reason", "unspecified")
    try:
        pki.revoke_certificate(name, reason=reason)
        flash(f"Certificat '{name}' revoque (raison : {reason}). Pense a regenerer la CRL.", "success")
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/crl/generate", methods=["POST"])
def generate_crl():
    try:
        result = pki.generate_crl()
        flash(f"CRL generee ({result['revoked_count']} certificat(s) revoque(s)).", "success")
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/certificates/verify", methods=["POST"])
def verify_certificate():
    name = request.form.get("common_name", "").strip()
    try:
        result = pki.verify_certificate(name)
        if result["overall_valid"]:
            flash(f"'{name}' est VALIDE (signature OK, non expire, non revoque).", "success")
        else:
            reasons = []
            if not result["signature_ok"]:
                reasons.append("signature invalide")
            if not result["time_ok"]:
                reasons.append("hors periode de validite")
            if result["revoked"]:
                reasons.append(f"revoque ({result['revocation_reason']})")
            flash(f"'{name}' est INVALIDE : {', '.join(reasons)}.", "error")
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/certificates/verify-openssl", methods=["POST"])
def verify_openssl():
    """: relance une verification independante avec le vrai binaire openssl
    (pas notre propre code Python), et affiche sa sortie brute sur le dashboard."""
    name = request.form.get("common_name", "").strip()
    try:
        result = pki.verify_with_openssl(name)
        session["openssl_result"] = result
    except RuntimeError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
