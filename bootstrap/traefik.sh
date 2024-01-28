#!/bin/sh
DOMAIN='177cpt.com'
#LOCAL_DOMAIN=us.177cpt.com
CF_API_EMAIL=cseelhoff@gmail.com
CF_API_KEY=fZ-U4Q3zgxHq6_Cn_a-_Ps0-SwL1FRg3Vd-cMp-S
TIMEZONE=America/Chicago
DNS_SERVER='10.0.1.44'
DHCP_ROUTER='10.0.1.2'
DHCP_START='10.0.1.10'
DHCP_END='10.0.1.50'

PIHOLE_BASE_URL=http://localhost/admin
PIHOLE_LOGIN_URL=$PIHOLE_BASE_URL/login.php
PIHOLE_INDEX_URL=$PIHOLE_BASE_URL/index.php
PIHOLE_CUSTOM_DNS_URL=$PIHOLE_BASE_URL/scripts/pi-hole/php/customdns.php
PIHOLE_PASSWORD=$(openssl rand -base64 32)
TRAEFIK_PASSWORD=$(openssl rand -base64 32)
PIHOLE_FQDN=pihole.$DOMAIN
NEXUS_FQDN=nexus.$DOMAIN
TRAEFIK_FQDN=traefik.$DOMAIN
#TRAEFIK_FQDN=traefik-dashboard.us.177cpt.com

# Run the pihole container
docker run -d \
    --name=pihole \
    -h pihole \
    -p 53:53/tcp -p 53:53/udp -p 67:67/udp -p 80:80/tcp \
    -e DNSMASQ_LISTENING=all \
    -e TZ=$TIMEZONE \
    -e PIHOLE_DNS_=$DNS_SERVER \
    -e DHCP_ROUTER=$DHCP_ROUTER \
    -e DHCP_START=$DHCP_START \
    -e DHCP_END=$DHCP_END \
    -e PIHOLE_DOMAIN=$LOCAL_DOMAIN \
    -e VIRTUAL_HOST=pihole \
    -e WEBPASSWORD=$PIHOLE_PASSWORD \
    -v $(pwd)/etc-pihole/:/etc/pihole/ \
    -v $(pwd)/etc-dnsmasq.d/:/etc/dnsmasq.d/ \
    --cap-add NET_ADMIN \
    --restart=unless-stopped \
    pihole/pihole:2024.01.0

# Make the POST request and extract the token
PIHOLE_TOKEN=$(curl -s -d "pw=$PIHOLE_PASSWORD" -c cookies.txt -X POST $PIHOLE_INDEX_URL | grep -oP '(?<=<div id="token" hidden>)(\S+)(?=<\/div>)' -m 1 | tr '\n' '\0' | jq -sRr @uri)
# Add DNS A record for pihole, nexus, traefik
curl -d "action=add&ip=$DNS_SERVER&domain=$PIHOLE_FQDN&token=$PIHOLE_TOKEN" -b cookies.txt -X POST $PIHOLE_CUSTOM_DNS_URL
curl -d "action=add&ip=$DNS_SERVER&domain=$NEXUS_FQDN&token=$PIHOLE_TOKEN" -b cookies.txt -X POST $PIHOLE_CUSTOM_DNS_URL
curl -d "action=add&ip=$DNS_SERVER&domain=$TRAEFIK_FQDN&token=$PIHOLE_TOKEN" -b cookies.txt -X POST $PIHOLE_CUSTOM_DNS_URL

# create proxy network for traefik
docker network create proxy

TRAEFIK_CREDS=$(htpasswd -nb "admin" "$TRAEFIK_PASSWORD" | sed -e s/\\$/\\$\\$/g)
sed -i "s/traefik.http.middlewares.traefik-auth.basicauth.users=USER:BASIC_AUTH_PASSWORD/traefik.http.middlewares.traefik-auth.basicauth.users=$TRAEFIK_CREDS/g" traefik/docker-compose.yml

# download and install docker-compose
curl -L "https://github.com/docker/compose/releases/download/v2.24.2/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
chmod 755 /usr/local/bin/docker-compose

docker-compose -f traefik/docker-compose.yml -p traefik up -d
#docker-compose -f traefik/docker-compose.yml -p traefik up -d --force-recreate
