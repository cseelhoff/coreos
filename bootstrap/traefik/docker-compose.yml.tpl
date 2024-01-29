version: '3'

services:
  traefik:
    image: ${TRAEFIK_DOCKER_IMAGE}
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    networks:
      - proxy
    ports:
      - 80:80
      - 443:443
    environment:
      - CF_DNS_API_TOKEN=${CF_DNS_API_TOKEN}
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /home/localadmin/coreos/bootstrap/traefik/data/traefik.yml:/traefik.yml:ro
      - /home/localadmin/coreos/bootstrap/traefik/data/acme.json:/acme.json
      - /home/localadmin/coreos/bootstrap/traefik/data/config.yml:/config.yml:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik.entrypoints=http"
      - "traefik.http.routers.traefik.rule=Host(`${TRAEFIK_FQDN}`,`traefik`)"
      - "traefik.http.middlewares.traefik-auth.basicauth.users=${TRAEFIK_AUTH}"
      - "traefik.http.middlewares.traefik-https-redirect.redirectscheme.scheme=https"
      - "traefik.http.middlewares.sslheader.headers.customrequestheaders.X-Forwarded-Proto=https"
      - "traefik.http.routers.traefik.middlewares=traefik-https-redirect"
      - "traefik.http.routers.traefik-secure.entrypoints=https"
      - "traefik.http.routers.traefik-secure.rule=Host(`${TRAEFIK_FQDN}`,`traefik`)"
      - "traefik.http.routers.traefik-secure.middlewares=traefik-auth"
      - "traefik.http.routers.traefik-secure.tls=true"
      - "traefik.http.routers.traefik-secure.tls.certresolver=cloudflare"
      - "traefik.http.routers.traefik-secure.tls.domains[0].main=${DOMAIN_NAME}"
      - "traefik.http.routers.traefik-secure.tls.domains[0].sans=*.${DOMAIN_NAME}"
      - "traefik.http.routers.traefik-secure.service=api@internal"

networks:
  proxy:
    external: true
