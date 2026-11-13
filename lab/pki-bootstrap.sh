#!/bin/sh
# Creates the lab PKI on first start (idempotent). Keys are generated inside the `pki`
# volume and only reach each container as a read-only per-component bundle.
set -eu

DIR="${PKI_DIR:-/pki}"
OUT="$DIR/members"
DEVICES="ih-alice ih-bob ih-bench-1 ih-bench-2 ih-bench-3 ih-bench-4 ih-bench-5"

if [ -f "$DIR/.done" ]; then
    echo "[pki] PKI already initialized in $DIR"
    exit 0
fi

sdp-pki ca --dir "$DIR/ca"

issue() { # id role dns out
    sdp-pki issue --ca "$DIR/ca" --id "$1" --role "$2" --dns "$3" --out "$OUT/$4"
}

issue controller  controller controller,controller-mgmt controller
issue sdp-gateway gateway    sdp-gateway                gateway   # shared by every gateway replica
issue ids         ids        ids                        ids
issue keycloak    server     keycloak                   keycloak
for d in $DEVICES; do
    issue "$d" device "" "$d"
done

# The controller knows the static SPA key of every device (to open its own port).
mkdir -p "$OUT/controller/devices"
for d in $DEVICES; do
    cp "$OUT/$d/spa.keys" "$OUT/controller/devices/$d.keys"
done
chmod 600 "$OUT"/controller/devices/*.keys

# Clients and the IDS run as uid 10001, Keycloak as uid 1000; controller and gateway as root.
for d in $DEVICES ids; do
    chown -R 10001:10001 "$OUT/$d"
done
chown -R 1000:0 "$OUT/keycloak"
chmod -R go-rwx "$DIR/ca"
touch "$DIR/.done"
echo "[pki] done"
