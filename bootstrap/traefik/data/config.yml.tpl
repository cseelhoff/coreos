http:
 #region routers 
  routers:
    pihole:
      entryPoints:
        - "https"
      rule: "Host(`${PIHOLE_FRONTEND_FQDN}`)"
      middlewares:
        - redirectregex-pihole
        - default-headers
        - addprefix-pihole
        - https-redirectscheme
      tls: {}
      service: pihole
    nexus:
      entryPoints:
        - "https"
      rule: "Host(`${NEXUS_FRONTEND_FQDN}`)"
      middlewares:
        - default-headers
        - https-redirectscheme
      tls: {}
      service: nexus
    docker_registry:
      entryPoints:
        - "https"
      rule: "Host(`${DOCKER_REGISTRY_FRONTEND_FQDN}`)"
      middlewares:
        - default-headers
        - https-redirectscheme
      tls: {}
      service: docker_registry
    portainer:
      entryPoints:
        - "https"
      rule: "Host(`${PORTAINER_FRONTEND_FQDN}`)"
      middlewares:
        - default-headers
        - https-redirectscheme
      tls: {}
      service: portainer
    openldap:
      entryPoints:
        - "https"
      rule: "Host(`${OPENLDAP_FRONTEND_FQDN}`)"
      middlewares:
        - default-headers
        - https-redirectscheme
      tls: {}
      service: openldap
#endregion
#region services
  services:
    pihole:
      loadBalancer:
        servers:
          - url: "${PIHOLE_BACKEND_URL}"
        passHostHeader: true
    nexus:
      loadBalancer:
        servers:
          - url: "${NEXUS_BACKEND_URL}"
        passHostHeader: true
    docker_registry:
      loadBalancer:
        servers:
          - url: "${DOCKER_REGISTRY_BACKEND_URL}"
        passHostHeader: true
    portainer:
      loadBalancer:
        servers:
          - url: "${PORTAINER_BACKEND_URL}"
        passHostHeader: true
    openldap:
      loadBalancer:
        servers:
          - url: "${OPENLDAP_BACKEND_URL}"
        passHostHeader: true
#endregion
  middlewares:
    addprefix-pihole:
      addPrefix:
        prefix: "/admin"
    https-redirectscheme:
      redirectScheme:
        scheme: https
        permanent: true
    redirectregex-pihole:
      redirectRegex:
        regex: /admin/$
        replacement: /

    default-headers:
      headers:
        frameDeny: true
        browserXssFilter: true
        contentTypeNosniff: true
        forceSTSHeader: true
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 15552000
        customFrameOptionsValue: SAMEORIGIN
        customRequestHeaders:
          X-Forwarded-Proto: https

    default-whitelist:
      ipWhiteList:
        sourceRange:
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "172.16.0.0/12"

    secured:
      chain:
        middlewares:
        - default-whitelist
        - default-headers
