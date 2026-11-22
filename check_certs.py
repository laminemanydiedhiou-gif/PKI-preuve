#!/usr/bin/env python3
"""Supervision des certificats TLS - version corrigée.

Corrections par rapport à la version initiale :
  1. La date d'expiration est lue SANS vérification de chaîne (CERT_NONE), donc
     un certificat expiré, auto-signé ou inconnu est quand même analysé.
  2. La confiance (chaîne, nom, validité) est évaluée dans un second temps.
  3. Toute anomalie produit une ALERTE écrite dans un puits SOC (fichier JSON
     lines et/ou webhook), et non un simple print. Code retour : 0 / 1 / 2.
  4. Seuils adaptés à une durée de vie de 30 jours avec renouvellement à 10 jours.

Usage : check_certs.py hote:port[:sni] [...] [--ca ca.pem] [--sink alerts.jsonl] [--webhook URL]
"""
import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.request

from cryptography import x509

# Jours restants avant expiration -> niveau d'alerte (durée de vie 30 j, renouvellement à 10 j)
SEUILS = {"INFORMATION": 10, "AVERTISSEMENT": 7, "CRITIQUE": 3}
GRAVITE = {"OK": 0, "INFORMATION": 1, "AVERTISSEMENT": 1, "CRITIQUE": 2}


def maintenant():
    return dt.datetime.now(dt.timezone.utc)


def lire_certificat(hote, port, sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lecture seule : on veut la date même si la chaîne est invalide
    with socket.create_connection((hote, port), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as ss:
            return x509.load_der_x509_certificate(ss.getpeercert(binary_form=True))


def date_fin(cert):
    d = getattr(cert, "not_valid_after_utc", None)
    return d if d is not None else cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def confiance(hote, port, sni, cafile):
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection((hote, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=sni):
                return "FIABLE", ""
    except ssl.SSLCertVerificationError as e:
        return "NON_FIABLE", e.verify_message
    except Exception as e:  # noqa: BLE001
        return "ERREUR", str(e)


def niveau(jours, trust):
    if jours < 0:
        return "CRITIQUE", "certificat expiré"
    if trust == "NON_FIABLE":
        return "CRITIQUE", "certificat non reconnu (auto-signé, chaîne inconnue ou nom invalide)"
    if jours <= SEUILS["CRITIQUE"]:
        return "CRITIQUE", "expiration imminente"
    if jours <= SEUILS["AVERTISSEMENT"]:
        return "AVERTISSEMENT", "renouvellement en échec probable"
    if jours <= SEUILS["INFORMATION"]:
        return "INFORMATION", "fenêtre de renouvellement ouverte"
    return "OK", "certificat conforme"


def emettre(alerte, sink, webhook):
    ligne = json.dumps(alerte, ensure_ascii=False)
    print(ligne)
    if sink:
        with open(sink, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    if webhook:
        req = urllib.request.Request(webhook, data=ligne.encode(), headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:  # noqa: BLE001
            print(json.dumps({"erreur_webhook": str(e)}), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cibles", nargs="+")
    ap.add_argument("--ca")
    ap.add_argument("--sink")
    ap.add_argument("--webhook")
    a = ap.parse_args()
    pire = 0
    for c in a.cibles:
        p = c.split(":")
        hote, port, sni = p[0], int(p[1]), (p[2] if len(p) > 2 else p[0])
        base = {"horodatage": maintenant().isoformat(timespec="seconds"), "cible": f"{hote}:{port}"}
        try:
            cert = lire_certificat(hote, port, sni)
        except Exception as e:  # noqa: BLE001 - un service injoignable DOIT alerter
            emettre({**base, "niveau": "CRITIQUE", "motif": "service injoignable ou TLS impossible", "detail": str(e)},
                    a.sink, a.webhook)
            pire = max(pire, 2)
            continue
        fin = date_fin(cert)
        jours = (fin - maintenant()).total_seconds() / 86400
        trust, detail = confiance(hote, port, sni, a.ca)
        lvl, motif = niveau(jours, trust)
        rec = {**base, "niveau": lvl, "motif": motif, "sujet": cert.subject.rfc4514_string(),
               "emetteur": cert.issuer.rfc4514_string(), "expire_le": fin.isoformat(timespec="seconds"),
               "jours_restants": round(jours, 2), "confiance": trust, "detail_confiance": detail}
        emettre(rec, a.sink, a.webhook)
        pire = max(pire, GRAVITE[lvl])
    sys.exit(pire)


if __name__ == "__main__":
    main()
