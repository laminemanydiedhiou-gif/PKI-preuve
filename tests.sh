#!/usr/bin/env bash
# Banc de preuves reproductible - Mémoire PKI (OpenSSL, Vault, ACME/Certbot, supervision, OCSP, MITM)
# Complet  : docker run --rm -v "$PWD/out:/out" pki-lab
# Hors ligne (OpenSSL + Python seulement) : MODE=offline OUT=./out LAB=./lab bash tests.sh
set -u
echo "tests.sh : $(wc -l < "$0") lignes, empreinte sha256 = $(sha256sum "$0" | cut -c1-12)"
if bash -n "$0"; then echo "controle de syntaxe de tests.sh : OK"; else echo "ERREUR DE SYNTAXE dans tests.sh (voir la ligne indiquee ci-dessus) : le fichier a ete mal copie"; fi
MODE=${MODE:-full}
OUT=${OUT:-/out}
LAB=${LAB:-/lab}
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT" "$LAB"
OUT=$(cd "$OUT" && pwd); LAB=$(cd "$LAB" && pwd)
cd "$LAB" || exit 1
RES="$OUT/RESULTATS.md"
printf '| Test | Résultat | Détail |\n|---|---|---|\n' > "$RES"
PIDS=()
export SAN="DNS:placeholder.lab.local"   # variable requise par la config openssl (surchargée à chaque émission)
trap 'for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done' EXIT

# ---------------------------------------------------------------- utilitaires
CUR=/dev/null
log(){ printf '%s\n' "$*" | tee -a "$CUR"; }
begin(){ CUR="$OUT/$1.log"; : > "$CUR"; log "=================================================="; log "$1 - $2"; log "Objectif : $3"; log "Date (UTC) : $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
cmd(){ log ""; log "\$ $*"; local o rc; o=$(bash -c "$*" 2>&1); rc=$?; [ -n "$o" ] && printf '%s\n' "$o" | tee -a "$CUR"; log "[code retour : $rc]"; LAST_OUT="$o"; return $rc; }
verdict(){ local s="CONFORME"; [ "$2" -ne 0 ] && s="NON CONFORME"; log ">>> $1 : $s - $3"; printf '| %s | %s | %s |\n' "$1" "$s" "$3" >> "$RES"; }
attendre_port(){ for _ in $(seq 1 40); do (echo > "/dev/tcp/$1/$2") 2>/dev/null && return 0; sleep 0.5; done; return 1; }
serveur_tls(){ # port cert key  -> serveur de test openssl s_server
  openssl s_server -accept "$1" -cert "$2" -key "$3" -www -quiet >/dev/null 2>&1 &
  PIDS+=($!); attendre_port 127.0.0.1 "$1"; }
dans(){ date -u -d "$1" +%Y%m%d%H%M%SZ; }

export REQUESTS_CA_BUNDLE="$LAB/root/root.pem" VAULT_CACERT="$LAB/root/root.pem"
export VAULT_ADDR="https://vault.lab.local:8200"
if [ "$MODE" = full ]; then
  grep -q vault.lab.local /etc/hosts || echo "127.0.0.1 vault.lab.local web.lab.local crl.lab.local ocsp.lab.local" >> /etc/hosts
fi

# ---------------------------------------------------------------- 0. versions
{ echo "mode: $MODE"; date -u; openssl version; python3 --version; curl --version | head -1
  command -v vault >/dev/null && vault version; command -v certbot >/dev/null && certbot --version 2>&1
  command -v nginx >/dev/null && nginx -v 2>&1; command -v promtool >/dev/null && promtool --version | head -1; } > "$OUT/versions.txt" 2>&1
cp "$SRC_DIR/check_certs.py" "$OUT/check_certs.py" 2>/dev/null

# ---------------------------------------------------------------- configuration OpenSSL (racine et intermédiaire)
mk_ca(){ # nom  (crée /lab/<nom>/ avec sa config openssl)
  local d="$LAB/$1"
  mkdir -p "$d"/{newcerts,private}; : > "$d/index.txt"; echo 1000 > "$d/serial"; echo 1000 > "$d/crlnumber"
  cat > "$d/openssl.cnf" <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = @DIR@
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
crlnumber = $dir/crlnumber
private_key = $dir/private/ca.key
certificate = $dir/ca.pem
default_md = sha256
default_days = 30
default_crl_days = 30
policy = policy_lab
unique_subject = no
copy_extensions = none
[ policy_lab ]
commonName = supplied
organizationName = optional
countryName = optional
[ req ]
distinguished_name = req_dn
prompt = no
[ req_dn ]
CN = placeholder
[ v3_ca ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_intermediate ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
crlDistributionPoints = URI:http://crl.lab.local:8081/root.crl
[ v3_server ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = $ENV::SAN
crlDistributionPoints = URI:http://crl.lab.local:8081/int.crl
authorityInfoAccess = OCSP;URI:http://ocsp.lab.local:2560
[ v3_ocsp ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
EOF
  sed -i "s#@DIR@#$d#" "$d/openssl.cnf"
}
CAROOT="$LAB/root/openssl.cnf"
nouvelle_cle_csr(){ openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null; }
emettre_depuis(){ # ca nom cn san options...
  local ca=$1 n=$2 cn=$3 san=$4; shift 4
  nouvelle_cle_csr "$LAB/$n" "$cn"
  SAN="$san" openssl ca -batch -config "$LAB/$ca/openssl.cnf" -extensions v3_server -notext -in "$LAB/$n.csr" -out "$LAB/$n.pem" "$@" 2>/dev/null
}

# ================================================================ T01 - racine
begin T01 "Génération de la clé racine et du certificat auto-signé" "Obtenir une racine valide avec les extensions v3_ca (CA:TRUE, keyCertSign, cRLSign)"
mk_ca root
cmd "openssl ecparam -genkey -name secp384r1 -noout -out $LAB/root/private/ca.key && chmod 400 $LAB/root/private/ca.key"
cmd "openssl req -x509 -new -key $LAB/root/private/ca.key -sha256 -days 3650 -subj '/CN=Lab Root CA/O=Lab PKI' -config $CAROOT -extensions v3_ca -out $LAB/root/ca.pem"
cp "$LAB/root/ca.pem" "$LAB/root/root.pem"
cmd "openssl x509 -in $LAB/root/root.pem -noout -subject -issuer -dates -ext basicConstraints,keyUsage"
if echo "$LAST_OUT" | grep -q 'CA:TRUE' && echo "$LAST_OUT" | grep -q 'Certificate Sign'; then rc=0; else rc=1; fi
verdict T01 $rc "racine auto-signée, CA:TRUE, keyCertSign/cRLSign (ECDSA P-384)"

# ================================================================ T02 - intermédiaire signée par la racine (OpenSSL)
begin T02 "Signature de la CSR intermédiaire par la racine" "Intermédiaire signée par la racine et chaîne vérifiable avec openssl verify"
mk_ca intb
cmd "openssl ecparam -genkey -name secp384r1 -noout -out $LAB/intb/private/ca.key"
cmd "openssl req -new -key $LAB/intb/private/ca.key -subj '/CN=Lab Intermediate CA/O=Lab PKI' -out $LAB/intb/ca.csr"
cmd "openssl ca -batch -config $CAROOT -extensions v3_intermediate -days 1825 -notext -in $LAB/intb/ca.csr -out $LAB/intb/ca.pem"
cmd "openssl verify -CAfile $LAB/root/root.pem $LAB/intb/ca.pem"
rc=$?
cmd "openssl x509 -in $LAB/intb/ca.pem -noout -subject -issuer -ext basicConstraints,keyUsage,crlDistributionPoints"
cat "$LAB/intb/ca.pem" "$LAB/root/root.pem" > "$LAB/intb/chain.pem"
verdict T02 $rc "intermédiaire pathlen:0 signée par la racine, openssl verify = OK"

# ================================================================ Vault + ACME (mode complet uniquement)
if [ "$MODE" = full ]; then
  SAN="DNS:vault.lab.local,IP:127.0.0.1" emettre_depuis root vault-tls vault.lab.local "DNS:vault.lab.local,IP:127.0.0.1" -days 30
  cat > "$LAB/vault.hcl" <<EOF
storage "file" { path = "$LAB/vault-data" }
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "$LAB/vault-tls.pem"
  tls_key_file  = "$LAB/vault-tls.key"
}
api_addr     = "https://vault.lab.local:8200"
disable_mlock = true
ui = false
EOF
  nohup vault server -config="$LAB/vault.hcl" > "$OUT/vault-server.log" 2>&1 &
  PIDS+=($!)
  attendre_port 127.0.0.1 8200

  begin T02b "Initialisation de Vault (Shamir 5/3) et import de l'intermédiaire Vault signée par la racine OpenSSL" "Montrer l'état de Vault et la chaîne racine OpenSSL -> intermédiaire Vault"
  cmd "vault operator init -key-shares=5 -key-threshold=3 -format=json > $LAB/vault-init.json; echo 'parts de descellement :' \$(jq '.unseal_keys_b64|length' $LAB/vault-init.json) ' / seuil : 3'"
  for i in 0 1 2; do vault operator unseal "$(jq -r ".unseal_keys_b64[$i]" "$LAB/vault-init.json")" >/dev/null 2>&1; done
  export VAULT_TOKEN=$(jq -r .root_token "$LAB/vault-init.json")
  cmd "vault status"
  log "LIMITE : dans ce banc, les 5 parts et le jeton racine sont dans un seul fichier ($LAB/vault-init.json) : le seuil 3/5 ne sépare pas les responsabilités (simplification de laboratoire)."
  cmd "vault secrets enable -path=pki_int pki && vault secrets tune -max-lease-ttl=43800h -passthrough-request-headers=If-Modified-Since -allowed-response-headers=Last-Modified -allowed-response-headers=Location -allowed-response-headers=Replay-Nonce -allowed-response-headers=Link pki_int"
  cmd "vault write -format=json pki_int/intermediate/generate/internal common_name='Lab Vault Intermediate CA' key_type=ec key_bits=384 | jq -r .data.csr > $LAB/vault-int.csr; head -2 $LAB/vault-int.csr"
  cmd "openssl ca -batch -config $CAROOT -extensions v3_intermediate -days 1825 -notext -in $LAB/vault-int.csr -out $LAB/vault-int.pem"
  cat "$LAB/vault-int.pem" "$LAB/root/root.pem" > "$LAB/vault-chain.pem"
  cmd "vault write pki_int/intermediate/set-signed certificate=@$LAB/vault-chain.pem"
  cmd "openssl verify -CAfile $LAB/root/root.pem $LAB/vault-int.pem"
  verdict T02b $? "intermédiaire Vault signée par la racine OpenSSL et importée (set-signed)"

  cmd "vault write pki_int/config/urls issuing_certificates=https://vault.lab.local:8200/v1/pki_int/ca crl_distribution_points=https://vault.lab.local:8200/v1/pki_int/crl ocsp_servers=https://vault.lab.local:8200/v1/pki_int/ocsp"
  cmd "vault write pki_int/config/cluster path=https://vault.lab.local:8200/v1/pki_int aia_path=https://vault.lab.local:8200/v1/pki_int"
  cmd "vault write pki_int/roles/lab-acme allowed_domains=lab.local allow_subdomains=true key_type=any ttl=720h max_ttl=720h require_cn=false"
  cmd "vault write pki_int/roles/lab-issue allowed_domains=lab.local allow_subdomains=true key_type=ec key_bits=256 ttl=720h max_ttl=720h"
  cmd "vault write pki_int/config/acme enabled=true default_directory_policy=role:lab-acme"
  cmd "vault read pki_int/config/acme"

  # ---------------------------------------------------------------- T03 / T04
  begin T03 "Émission d'un certificat via l'API Vault (CLI)" "Certificat, clé et chaîne retournés en moins d'une seconde"
  t0=$(date +%s.%N)
  cmd "vault write -format=json pki_int/issue/lab-issue common_name=app.lab.local ttl=24h > $LAB/issue.json && jq -r '.data.serial_number, .data.expiration' $LAB/issue.json"
  rc=$?; t1=$(date +%s.%N)
  dur=$(python3 -c "print(round(($t1-$t0)*1000))")
  jq -r .data.certificate "$LAB/issue.json" > "$LAB/vault-leaf.pem"
  log "Durée mesurée de la commande vault write : ${dur} ms (une seule mesure)"
  verdict T03 $rc "émission réussie en ${dur} ms (une mesure ; le mémoire annonce une moyenne, à refaire sur plusieurs essais)"

  begin T04 "Respect du rôle Vault (domaine hors périmètre)" "Refus de l'émission pour un domaine hors lab.local"
  log "Témoin positif : T03 vient d'émettre app.lab.local avec le même rôle (lab-issue) : le refus ci-dessous vient donc bien du nom de domaine."
  cmd "vault write pki_int/issue/lab-issue common_name=app.example.com ttl=24h"
  if [ $? -ne 0 ] && echo "$LAST_OUT" | grep -qi 'not allowed by this role'; then rc=0; else rc=1; fi
  verdict T04 $rc "émission refusée par le rôle pour un domaine hors lab.local (message : not allowed by this role)"

  # ---------------------------------------------------------------- T05 ACME + Certbot + nginx
  begin T05 "Émission ACME via Certbot contre Vault" "Certificat obtenu via le protocole ACME (défi HTTP-01) et configuré automatiquement sur nginx"
  log "Topologie : un seul conteneur ; vault.lab.local et web.lab.local résolus par /etc/hosts vers 127.0.0.1."
  log "Défi ACME : HTTP-01 (Vault joint http://web.lab.local:80/.well-known/acme-challenge/...)."
  log "Confiance : Certbot fait confiance au certificat TLS de Vault via REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE (racine OpenSSL)."
  log "Authentification : compte ACME (requêtes signées par la clé du compte), pas de jeton Vault. EAB non exigé dans ce banc (eab_policy par défaut)."
  rm -f /etc/nginx/sites-enabled/default
  mkdir -p /var/www/html; echo "web.lab.local OK" > /var/www/html/index.html
  printf 'server {\n  listen 80;\n  server_name web.lab.local;\n  root /var/www/html;\n  index index.html;\n}\n' > /etc/nginx/conf.d/web.conf
  cmd "nginx -t && (nginx || true)"
  cmd "getent hosts vault.lab.local web.lab.local"
  cmd "curl -s --cacert $LAB/root/root.pem https://vault.lab.local:8200/v1/pki_int/acme/directory"
  cmd "certbot --nginx --non-interactive --agree-tos --register-unsafely-without-email --server https://vault.lab.local:8200/v1/pki_int/acme/directory -d web.lab.local"
  rc=$?
  cmd "openssl x509 -in /etc/letsencrypt/live/web.lab.local/cert.pem -noout -serial -subject -issuer -dates -ext subjectAltName"
  cmd "echo | openssl s_client -connect 127.0.0.1:443 -servername web.lab.local -CAfile $LAB/root/root.pem 2>&1 | grep -E 'Verification|Verify return|subject=|issuer=|depth'"
  cmd "curl -sS --cacert $LAB/root/root.pem https://web.lab.local/"
  if [ $rc -eq 0 ] && echo "$LAST_OUT" | grep -q 'web.lab.local OK'; then rc=0; else rc=1; fi
  verdict T05 $rc "certificat ACME (HTTP-01) émis par Vault, nginx configuré, chaîne vérifiée par la racine OpenSSL"

  # seuil de renouvellement : 10 jours pour des certificats de 30 jours
  RC=/etc/letsencrypt/renewal/web.lab.local.conf
  [ -f "$RC" ] && sed -i '1i renew_before_expiry = 10 days' "$RC"
  begin T06 "Renouvellement automatique (dry-run) et fenêtre de renouvellement" "Simulation sans erreur ; pas de renouvellement tant que >10 jours restent (certificat de 30 jours)"
  log "NOTE : sans --server, 'certbot renew --dry-run' vise le serveur staging de Let's Encrypt (échec constaté au premier essai) ; on force donc le serveur Vault."
  cmd "certbot renew --dry-run --server https://vault.lab.local:8200/v1/pki_int/acme/directory"
  rc=$?
  cmd "certbot renew"
  if echo "$LAST_OUT" | grep -qi 'not yet due'; then nd=0; log "Constat : certbot renew ne renouvelle pas (échéance > 10 jours) -> plus de renouvellement à chaque exécution."; else nd=1; fi
  [ $rc -eq 0 ] && [ $nd -eq 0 ]; verdict T06 $? "dry-run réussi contre Vault ; fenêtre de renouvellement de 10 jours : pas de renouvellement tant que >10 j restent"

  begin T07 "Renouvellement automatique réel (cycles accélérés)" "7 renouvellements successifs avec changement de numéro de série"
  log "LIMITE : cycles forcés (--force-renewal) en quelques secondes ; ce test ne prouve PAS un fonctionnement sur 7 jours."
  ok=0; prev=$(openssl x509 -in /etc/letsencrypt/live/web.lab.local/cert.pem -noout -serial)
  for i in 1 2 3 4 5 6 7; do
    cmd "certbot renew --force-renewal --cert-name web.lab.local --no-random-sleep-on-renew"
    cur=$(openssl x509 -in /etc/letsencrypt/live/web.lab.local/cert.pem -noout -serial)
    log "cycle $i : $cur (précédent : $prev)"
    [ "$cur" != "$prev" ] && ok=$((ok+1)); prev=$cur
  done
  [ $ok -eq 7 ]; verdict T07 $? "$ok/7 cycles accélérés avec nouveau numéro de série (pas une observation sur 7 jours)"

  begin T08 "Rechargement nginx après renouvellement" "Aucune requête en échec pendant un renouvellement (charge faible)"
  ( for _ in $(seq 1 200); do curl -s -o /dev/null -w '%{http_code}\n' --cacert "$LAB/root/root.pem" https://web.lab.local/; sleep 0.1; done > "$LAB/codes.txt" ) &
  bgp=$!
  cmd "certbot renew --force-renewal --cert-name web.lab.local --no-random-sleep-on-renew --deploy-hook 'nginx -s reload'"
  wait $bgp
  total=$(wc -l < "$LAB/codes.txt"); ko=$(grep -vc '^200$' "$LAB/codes.txt")
  log "Requêtes envoyées : $total ; réponses différentes de 200 : $ko ; répartition :"; sort "$LAB/codes.txt" | uniq -c | tee -a "$CUR"
  [ "$ko" -eq 0 ]; verdict T08 $? "$total requêtes (~10/s), $ko en échec pendant le renouvellement+rechargement (charge faible, pas un test de charge)"
fi

# ================================================================ Supervision (T09 / T10) + démonstration du défaut de l'ancien script
begin T09 "Script de supervision - seuil INFORMATION" "Alerte INFORMATION générée et écrite dans le puits SOC pour un certificat à ~9 jours"
log "Topologie : 6 serveurs de test openssl s_server sur 127.0.0.1 (ports 9601 à 9605 et 9607), certificats signés par la racine du banc."
D="$LAB/sup"; mkdir -p "$D"; cd "$D" || exit 1
emettre_depuis root c30 web.lab.local "DNS:web.lab.local" -days 30
emettre_depuis root c9 c9.lab.local "DNS:c9.lab.local" -days 9
emettre_depuis root c6 c6.lab.local "DNS:c6.lab.local" -days 6
emettre_depuis root c2 c2.lab.local "DNS:c2.lab.local" -days 2
emettre_depuis root cexp cexp.lab.local "DNS:cexp.lab.local" -startdate "$(dans '-40 days')" -enddate "$(dans '-1 day')"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$D/auto.key" -out "$D/auto.pem" -days 30 -subj "/CN=auto.lab.local" 2>/dev/null
mv "$LAB"/c30.* "$LAB"/c9.* "$LAB"/c6.* "$LAB"/c2.* "$LAB"/cexp.* "$D"/ 2>/dev/null
serveur_tls 9601 "$D/c30.pem" "$D/c30.key"
serveur_tls 9602 "$D/c9.pem" "$D/c9.key"
serveur_tls 9603 "$D/c2.pem" "$D/c2.key"
serveur_tls 9604 "$D/cexp.pem" "$D/cexp.key"
serveur_tls 9605 "$D/auto.pem" "$D/auto.key"
serveur_tls 9607 "$D/c6.pem" "$D/c6.key"
log ""
log "--- Démonstration du défaut de l'ANCIEN script (ssl.create_default_context + print) sur le certificat expiré (port 9604) ---"
cat > "$D/ancien.py" <<'EOF'
import socket, ssl
try:
    ctx = ssl.create_default_context(cafile="@ROOT@")   # la racine du labo est connue : seul l'expiration pose problème
    with socket.create_connection(("127.0.0.1", 9604), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname="cexp.lab.local") as ss:
            print(ss.getpeercert()["notAfter"])
except Exception as e:
    print("Erreur :", e)   # <- seul effet : un print, aucune alerte, la date n'est jamais lue
EOF
sed -i "s#@ROOT@#$LAB/root/root.pem#" "$D/ancien.py"
cmd "python3 $D/ancien.py; echo '(aucune alerte émise par l ancien script)'"
log "--- Nouveau script (lecture sans vérification, puis évaluation de la confiance, alerte SOC) ---"
: > "$D/alertes.jsonl"
CHK="$SRC_DIR/check_certs.py"
cmd "python3 $CHK 127.0.0.1:9602:c9.lab.local --ca $LAB/root/root.pem --sink $D/alertes.jsonl"
rc=$?
if [ $rc -eq 1 ] && echo "$LAST_OUT" | grep -q '"niveau": "INFORMATION"'; then v=0; else v=1; fi
verdict T09 $v "certificat à ~9 j -> alerte INFORMATION (seuil 10 j), code retour $rc"

begin T10 "Script de supervision - seuil CRITIQUE et cas d'échec de vérification" "CRITIQUE pour 2 j, certificat expiré, auto-signé et service injoignable ; AVERTISSEMENT à 6 j ; OK à 30 j"
cmd "python3 $CHK 127.0.0.1:9601:web.lab.local 127.0.0.1:9607:c6.lab.local 127.0.0.1:9603:c2.lab.local 127.0.0.1:9604:cexp.lab.local 127.0.0.1:9605:auto.lab.local 127.0.0.1:9699 --ca $LAB/root/root.pem --sink $D/alertes.jsonl"
rc=$?
n_crit=$(grep -c '"niveau": "CRITIQUE"' "$D/alertes.jsonl"); n_av=$(grep -c '"niveau": "AVERTISSEMENT"' "$D/alertes.jsonl"); n_ok=$(grep -c '"niveau": "OK"' "$D/alertes.jsonl")
log "Puits SOC ($D/alertes.jsonl) : CRITIQUE=$n_crit AVERTISSEMENT=$n_av OK=$n_ok INFORMATION=$(grep -c '"niveau": "INFORMATION"' "$D/alertes.jsonl")"
if [ "$n_crit" -eq 4 ] && [ "$n_av" -eq 1 ] && [ "$n_ok" -eq 1 ] && [ $rc -eq 2 ]; then v=0; else v=1; fi
verdict T10 $v "2 j, expiré, auto-signé, injoignable -> 4 CRITIQUE ; 6 j -> AVERTISSEMENT ; 30 j -> OK ; code retour $rc"
cp "$D/alertes.jsonl" "$OUT/alertes-soc.jsonl"
cd "$LAB" || exit 1

# ================================================================ T11 - règle Prometheus (test unitaire promtool)
begin T11 "Règle Prometheus - expiration < 7 jours" "Alerte warning déclenchée dans un test unitaire promtool (pas dans Grafana)"
mkdir -p "$LAB/prom"
cat > "$LAB/prom/alerts.yml" <<'EOF'
groups:
- name: certificats
  rules:
  - alert: CertificatExpireBientot
    expr: (ssl_probe_cert_not_after - time()) / 86400 < 7
    labels:
      severity: warning
EOF
cat > "$LAB/prom/test.yml" <<'EOF'
rule_files: [alerts.yml]
evaluation_interval: 1m
tests:
  - interval: 1m
    input_series:
      - series: 'ssl_probe_cert_not_after{instance="web.lab.local:443"}'
        values: '518400+0x30'
    alert_rule_test:
      - eval_time: 5m
        alertname: CertificatExpireBientot
        exp_alerts:
          - exp_labels: {severity: warning, instance: "web.lab.local:443"}
  - interval: 1m
    input_series:
      - series: 'ssl_probe_cert_not_after{instance="web.lab.local:443"}'
        values: '1728000+0x30'
    alert_rule_test:
      - eval_time: 5m
        alertname: CertificatExpireBientot
        exp_alerts: []
EOF
if command -v promtool >/dev/null; then
  cmd "cat $LAB/prom/alerts.yml"
  cmd "promtool check rules $LAB/prom/alerts.yml"
  cmd "cd $LAB/prom && promtool test rules test.yml"
  verdict T11 $? "règle <7 j testée : 6 j -> alerte warning ; 20 j -> aucune alerte (test unitaire promtool ; Grafana/Alertmanager non rejoués)"
else
  log "promtool absent de cet environnement : test non exécuté."; printf '| T11 | NON EXÉCUTÉ | promtool absent |\n' >> "$RES"
fi

# ================================================================ T12 / T13 - interception (simulation de redirection)
begin T12 "Interception MITM - certificat auto-signé" "Montrer qu'un utilisateur qui contourne l'avertissement est vulnérable"
log "Topologie (3 rôles distincts) : SERVEUR légitime = openssl s_server :9703 (certificat signé par la racine) ;"
log "ATTAQUANT = openssl s_server :9701 (certificat auto-signé) et :9702 (certificat d'une fausse AC) ; VICTIME = curl."
log "La redirection du trafic est SIMULÉE par curl --connect-to (équivalent d'un détournement DNS/ARP) ; aucun ARP spoofing n'est réalisé."
M="$LAB/mitm"; mkdir -p "$M"
emettre_depuis root legit web.lab.local "DNS:web.lab.local" -days 30; mv "$LAB"/legit.* "$M"/
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$M/att-auto.key" -out "$M/att-auto.pem" -days 30 -subj "/CN=web.lab.local" -addext "subjectAltName=DNS:web.lab.local" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$M/rogue-ca.key" -out "$M/rogue-ca.pem" -days 30 -subj "/CN=Fausse AC" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$M/att-rogue.key" -out "$M/att-rogue.csr" -subj "/CN=web.lab.local" 2>/dev/null
printf 'subjectAltName=DNS:web.lab.local\nbasicConstraints=CA:FALSE\n' > "$M/ext.cnf"
openssl x509 -req -in "$M/att-rogue.csr" -CA "$M/rogue-ca.pem" -CAkey "$M/rogue-ca.key" -CAcreateserial -days 30 -extfile "$M/ext.cnf" -out "$M/att-rogue.pem" 2>/dev/null
serveur_tls 9703 "$M/legit.pem" "$M/legit.key"
serveur_tls 9701 "$M/att-auto.pem" "$M/att-auto.key"
serveur_tls 9702 "$M/att-rogue.pem" "$M/att-rogue.key"
cmd "curl -sS --cacert $LAB/root/root.pem --connect-to web.lab.local:9703:127.0.0.1:9703 https://web.lab.local:9703/ -o /dev/null -w 'HTTP %{http_code}\n'"
log "(témoin : sans attaquant, la connexion légitime aboutit)"
cmd "curl -sS -k --connect-to web.lab.local:9703:127.0.0.1:9701 https://web.lab.local:9703/ -o /dev/null -w 'HTTP %{http_code} (verification TLS désactivée par la victime : -k)\n'"
verdict T12 $? "avec la vérification contournée (-k), la victime se connecte à l'attaquant : vulnérabilité confirmée"

begin T13 "Interception MITM - PKI correctement déployée" "Refus automatique du certificat de l'attaquant par un client qui fait confiance à la racine du labo"
cmd "curl -sS --cacert $LAB/root/root.pem --connect-to web.lab.local:9703:127.0.0.1:9701 https://web.lab.local:9703/ -o /dev/null"
r1=$?
cmd "curl -sS --cacert $LAB/root/root.pem --connect-to web.lab.local:9703:127.0.0.1:9702 https://web.lab.local:9703/ -o /dev/null"
r2=$?
if [ $r1 -ne 0 ] && [ $r2 -ne 0 ]; then rc=0; else rc=1; fi
log "Cas limite (hors protection) : si la FAUSSE AC est installée dans le magasin de confiance du client, l'interception réussit :"
cmd "curl -sS --cacert $M/rogue-ca.pem --connect-to web.lab.local:9703:127.0.0.1:9702 https://web.lab.local:9703/ -o /dev/null -w 'HTTP %{http_code}\n'"
verdict T13 $rc "certificat auto-signé et certificat d'une fausse AC refusés (curl code 60) ; la protection vaut seulement tant que le magasin de confiance n'est pas altéré"

# ================================================================ T15 - OCSP avec openssl ocsp (répondeur de l'intermédiaire OpenSSL)
begin T15b "Révocation et OCSP (répondeur openssl ocsp)" "Statut good avant révocation puis revoked après, avec commandes et sorties brutes"
emettre_depuis intb ocsp-leaf web.lab.local "DNS:web.lab.local" -days 30; mv "$LAB"/ocsp-leaf.* "$LAB/intb/" 2>/dev/null
cmd "openssl x509 -in $LAB/intb/ocsp-leaf.pem -noout -serial -ext authorityInfoAccess,crlDistributionPoints"
cmd "openssl verify -CAfile $LAB/root/root.pem -untrusted $LAB/intb/ca.pem $LAB/intb/ocsp-leaf.pem"
# certificat de signature OCSP dédié
nouvelle_cle_csr "$LAB/intb/ocsp-signer" "OCSP Responder Lab"
openssl ca -batch -config "$LAB/intb/openssl.cnf" -extensions v3_ocsp -notext -in "$LAB/intb/ocsp-signer.csr" -out "$LAB/intb/ocsp-signer.pem" -days 30 2>/dev/null
# l'intermédiaire doit pouvoir émettre : son DB/clé sont dans intb ; copier le certificat à la place attendue
demarrer_ocsp(){
  openssl ocsp -index "$LAB/intb/index.txt" -port 2560 -rsigner "$LAB/intb/ocsp-signer.pem" -rkey "$LAB/intb/ocsp-signer.key" -CA "$LAB/intb/ca.pem" >> "$OUT/ocsp-responder.log" 2>&1 &
  OCSP_PID=$!; PIDS+=($!); sleep 1.5   # pas de sonde TCP : le répondeur openssl s'arrête sur une requête mal formée
}
demarrer_ocsp
cmd "openssl ocsp -issuer $LAB/intb/ca.pem -cert $LAB/intb/ocsp-leaf.pem -url http://127.0.0.1:2560 -CAfile $LAB/intb/chain.pem -resp_text -noverify | grep -E 'OCSP Response Status|Cert Status|Responder|This Update|ocsp-leaf'"
cmd "openssl ocsp -issuer $LAB/intb/ca.pem -cert $LAB/intb/ocsp-leaf.pem -url http://127.0.0.1:2560 -CAfile $LAB/intb/chain.pem -VAfile $LAB/intb/ocsp-signer.pem 2>&1 | tail -4"
avant="$LAST_OUT"
cmd "openssl ca -config $LAB/intb/openssl.cnf -revoke $LAB/intb/ocsp-leaf.pem -crl_reason keyCompromise"
cmd "openssl ca -config $LAB/intb/openssl.cnf -gencrl -out $LAB/intb/int.crl"
log "(le répondeur openssl ocsp est relancé pour relire sa base d'index après la révocation)"
kill $OCSP_PID 2>/dev/null; sleep 0.5; demarrer_ocsp
cmd "openssl ocsp -issuer $LAB/intb/ca.pem -cert $LAB/intb/ocsp-leaf.pem -url http://127.0.0.1:2560 -CAfile $LAB/intb/chain.pem -VAfile $LAB/intb/ocsp-signer.pem 2>&1 | tail -4"
apres="$LAST_OUT"
if echo "$avant" | grep -q ': good' && echo "$apres" | grep -q ': revoked'; then rc=0; else rc=1; fi
verdict T15b $rc "même certificat : good avant révocation, revoked après (réponse signée vérifiée avec -VAfile)"

# ================================================================ T15 - OCSP du moteur PKI de Vault (mode complet)
if [ "$MODE" = full ]; then
  begin T15 "Révocation via Vault et vérification OCSP (endpoint Vault)" "Statut good puis revoked retourné par le répondeur OCSP intégré de Vault"
  cmd "openssl x509 -in $LAB/vault-leaf.pem -noout -serial -ext authorityInfoAccess"
  SER=$(openssl x509 -in "$LAB/vault-leaf.pem" -noout -serial | cut -d= -f2)
  ocsp_vault(){ openssl ocsp -issuer "$LAB/vault-int.pem" -cert "$LAB/vault-leaf.pem" -reqout "$LAB/req.der" -no_nonce >/dev/null 2>&1
    curl -s --cacert "$LAB/root/root.pem" -H 'Content-Type: application/ocsp-request' --data-binary @"$LAB/req.der" "$VAULT_ADDR/v1/pki_int/ocsp" -o "$LAB/resp.der"
    openssl ocsp -respin "$LAB/resp.der" -issuer "$LAB/vault-int.pem" -cert "$LAB/vault-leaf.pem" -CAfile "$LAB/vault-chain.pem" 2>&1 | tail -6; }
  log "--- avant révocation ---"; avant=$(ocsp_vault); log "$avant"
  SERH=$(echo "$SER" | sed 's/../&:/g; s/:$//' | tr 'A-F' 'a-f')
  cmd "vault write pki_int/revoke serial_number=$SERH"
  log "--- après révocation ---"; apres=$(ocsp_vault); log "$apres"
  if echo "$avant" | grep -q ': good' && echo "$apres" | grep -q ': revoked'; then rc=0; else rc=1; fi
  verdict T15 $rc "OCSP Vault : good avant, revoked après (voir requête/réponse brutes ci-dessus)"
fi

# ================================================================ R01 - révocation de l'AC intermédiaire (par la racine OpenSSL)
begin R01 "Révocation de l'autorité intermédiaire par la racine" "Seule la racine peut révoquer l'intermédiaire : révocation openssl, nouvelle CRL, publication et vérification"
log "NOTE : 'vault write pki_int/root/rotate' ne révoque pas le certificat de l'intermédiaire signé par la racine OpenSSL."
cmd "openssl ca -config $CAROOT -gencrl -out $LAB/root/root.crl"
cmd "openssl ca -config $LAB/intb/openssl.cnf -gencrl -out $LAB/intb/int.crl"
cat "$LAB/root/root.crl" "$LAB/intb/int.crl" > "$LAB/crls.pem"
emettre_depuis intb r01-leaf app.lab.local "DNS:app.lab.local" -days 30; mv "$LAB"/r01-leaf.* "$LAB/intb/" 2>/dev/null
cmd "openssl ca -config $LAB/intb/openssl.cnf -gencrl -out $LAB/intb/int.crl"
cat "$LAB/root/root.crl" "$LAB/intb/int.crl" > "$LAB/crls.pem"
log "--- AVANT révocation de l'intermédiaire (certificat feuille r01-leaf, non révoqué) ---"
cmd "openssl verify -crl_check_all -CAfile $LAB/root/root.pem -CRLfile $LAB/crls.pem -untrusted $LAB/intb/ca.pem $LAB/intb/r01-leaf.pem"
avant_rc=$?
cmd "openssl ca -config $CAROOT -revoke $LAB/intb/ca.pem -crl_reason CACompromise"
cmd "openssl ca -config $CAROOT -gencrl -out $LAB/root/root.crl"
cat "$LAB/root/root.crl" "$LAB/intb/int.crl" > "$LAB/crls.pem"
cmd "openssl crl -in $LAB/root/root.crl -noout -text | grep -E 'Issuer|Last Update|Next Update|Serial Number|Reason|CA Compromise|Revocation Date'"
mkdir -p "$LAB/pub"; cp "$LAB/root/root.crl" "$LAB/pub/root.crl"; cp "$LAB/intb/int.crl" "$LAB/pub/int.crl"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$LAB/pub" > "$OUT/crl-http.log" 2>&1 &
PIDS+=($!); attendre_port 127.0.0.1 8081
log "--- Accès des clients au point de distribution de la CRL (extension CDP du certificat intermédiaire) ---"
cmd "openssl x509 -in $LAB/intb/ca.pem -noout -ext crlDistributionPoints"
cmd "curl -s --resolve crl.lab.local:8081:127.0.0.1 http://crl.lab.local:8081/root.crl | openssl crl -noout -issuer -lastupdate -nextupdate"
log "--- APRÈS révocation de l'intermédiaire ---"
cmd "openssl verify -crl_check_all -CAfile $LAB/root/root.pem -CRLfile $LAB/crls.pem -untrusted $LAB/intb/ca.pem $LAB/intb/r01-leaf.pem"
if [ $avant_rc -eq 0 ] && echo "$LAST_OUT" | grep -q 'error 23 at 1 depth lookup: certificate revoked'; then rc=0; else rc=1; fi
verdict R01 $rc "avant : chaîne OK ; après révocation de l'intermédiaire par la racine et nouvelle CRL : 'certificate revoked' (error 23, profondeur 1)"
LIM="isolation de la racine : dans ce banc la racine est dans le même conteneur que le reste (pas de vrai air-gap) ; Shamir : parts et jeton racine dans un seul fichier ; MITM simulé par redirection (pas d'ARP spoofing) ; cycles de renouvellement accélérés ; charge de test faible ; Grafana/Alertmanager et Terraform (T14) non rejoués."
log "LIMITES DU BANC : $LIM"

# ---------------------------------------------------------------- artefacts (certificats publics et configurations, jamais de clés privées)
mkdir -p "$OUT/artefacts"
cp "$LAB"/root/root.pem "$LAB"/intb/ca.pem "$OUT/artefacts/" 2>/dev/null
cp "$LAB"/root/openssl.cnf "$OUT/artefacts/openssl-root.cnf" 2>/dev/null
cp "$LAB"/vault.hcl "$OUT/artefacts/" 2>/dev/null
cp /etc/letsencrypt/renewal/web.lab.local.conf "$OUT/artefacts/certbot-renewal.conf" 2>/dev/null
cp /etc/nginx/conf.d/web.conf "$OUT/artefacts/nginx-web.conf" 2>/dev/null
cp "$LAB"/prom/*.yml "$OUT/artefacts/" 2>/dev/null
printf '\nLimites du banc : %s\n' "$LIM" >> "$RES"
echo; echo "===== RÉSUMÉ ====="; cat "$RES"
exit 0
