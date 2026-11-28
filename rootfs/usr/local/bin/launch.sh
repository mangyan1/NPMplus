#!/usr/bin/env sh

echo "
-------------------------------------
PUID:     $PUID
User ID:  $(id -u)
PGID:     $PGID
Group ID: $(id -g)
-------------------------------------
"

if [ -z "$(find -L /data/tls/certbot/accounts/"$(echo "$ACME_SERVER" | sed "s|^https\?://||g")" -type f 2> /dev/null)" ]; then
    if [ "$(echo "$ACME_SERVER" | sed "s|^https\?://\([^/]\+\).*$|\1|g")" = "acme.zerossl.com" ] && [ -z "$ACME_EAB_KID$ACME_EAB_KID_FILE" ] && [ -z "$ACME_EAB_HMAC_KEY$ACME_EAB_HMAC_KEY_FILE" ]; then
        if [ -z "$ACME_EMAIL$ACME_EMAIL_FILE" ]; then
            echo "ACME_EMAIL is required to use zerossl. Either set it or use a different acme server like letsencrypt (ACME_SERVER: https://acme-v02.api.letsencrypt.org/directory)"
            sleep inf
        fi

        ZS_EAB="$(curl -sSL https://api.zerossl.com/acme/eab-credentials-email --data-urlencode "email=${ACME_EMAIL:-$(cat "$ACME_EMAIL_FILE")}")"
        export ZS_EAB
        ACME_EAB_KID="$(echo "$ZS_EAB" | jq -r .eab_kid)"
        export ACME_EAB_KID
        ACME_EAB_HMAC_KEY="$(echo "$ZS_EAB" | jq -r .eab_hmac_key)"
        export ACME_EAB_HMAC_KEY
    fi
    if [ -z "$ACME_EMAIL$ACME_EMAIL_FILE" ]; then
        if ! certbot --config /etc/certbot.ini register --server "$ACME_SERVER" --register-unsafely-without-email; then
            sleep inf
        fi
    elif [ -n "$ACME_EMAIL$ACME_EMAIL_FILE" ] && [ -z "$ACME_EAB_KID$ACME_EAB_KID_FILE" ] && [ -z "$ACME_EAB_HMAC_KEY$ACME_EAB_HMAC_KEY_FILE" ]; then
        if ! certbot --config /etc/certbot.ini register --server "$ACME_SERVER" --email "${ACME_EMAIL:-$(cat "$ACME_EMAIL_FILE")}"; then
            sleep inf
        fi
    elif [ -n "$ACME_EMAIL$ACME_EMAIL_FILE" ] && [ -n "$ACME_EAB_KID$ACME_EAB_KID_FILE" ] && [ -n "$ACME_EAB_HMAC_KEY$ACME_EAB_HMAC_KEY_FILE" ]; then
        if ! certbot --config /etc/certbot.ini register --server "$ACME_SERVER" --eab-kid "${ACME_EAB_KID:-$(cat "$ACME_EAB_KID_FILE")}" --eab-hmac-key "${ACME_EAB_HMAC_KEY:-$(cat "$ACME_EAB_HMAC_KEY_FILE")}" --email "${ACME_EMAIL:-$(cat "$ACME_EMAIL_FILE")}"; then
            sleep inf
        fi
    fi
    echo
elif [ -n "$ACME_EMAIL$ACME_EMAIL_FILE$ACME_EAB_KID$ACME_EAB_KID_FILE$ACME_EAB_HMAC_KEY$ACME_EAB_HMAC_KEY_FILE" ]; then
    echo "ACME_EMAIL, ACME_EAB_KID and ACME_EAB_HMAC_KEY (and their _FILE variants) are only used once to register an acme account, since one already exists for $ACME_SERVER you can safely remove them."
fi

if [ "$ACME_OCSP_STAPLING" = "true" ]; then
    ocsp.js /data/tls/certbot/live
    echo
fi
if [ "$CUSTOM_OCSP_STAPLING" = "true" ]; then
    ocsp.js /data/tls/custom
    echo
fi

if [ ! -s /data/tls/ech/config-ids.json ]; then
    jq -n '{current: [], previous: []}' > /data/tls/ech/config-ids.json
fi

if [ -s /data/tls/ech/cron.sh ]; then
    rm -f /data/tls/ech/*-previous.ech
    jq '{current: [], previous: .current}' /data/tls/ech/config-ids.json > /data/tls/ech/config-ids.json.tmp && mv /data/tls/ech/config-ids.json.tmp /data/tls/ech/config-ids.json

    chmod +x /data/tls/ech/cron.sh
    /data/tls/ech/cron.sh

    : > /data/tls/ech/nginx.conf
    for file in /data/tls/ech/*.ech; do
        [ -s "$file" ] && echo "ssl_ech_file $file;" >> /data/tls/ech/nginx.conf
    done
elif [ -s /data/tls/ech/nginx.conf ]; then
    rm -f /data/tls/ech/*.ech
    jq -n '{current: [], previous: []}' > /data/tls/ech/config-ids.json

    : > /data/tls/ech/nginx.conf
fi


# a boot can start the container before the host's dns answers ("no name
# servers defined" or resolvers unreachable) - that heals once dns is up,
# a genuinely broken config does not. retry for a while, then keep the
# sleep-forever debug path
i=0
while ! nginx -tq; do
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        sleep inf
    fi
    sleep 1
done

echo "0 */$ECH_ROTATION_INTERVAL * * * cron-ech.sh" | tee "/tmp/crontabs/$(id -un)"
if [ "$LOGROTATE" = "true" ]; then
    logrotate --state /data/nginx/logs/logrotate.state /etc/logrotate
    echo "0 * * * * logrotate --state /data/nginx/logs/logrotate.state /etc/logrotate" | tee -a "/tmp/crontabs/$(id -un)"
fi

set -- backend nginx crond
[ "$GOA" = "true" ] && set -- "$@" goaccess

echo "Starting services..."
exec dinit -s "$@"
