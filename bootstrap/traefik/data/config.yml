http:
 #region routers 
  routers:
    pihole:
      entryPoints:
        - "https"
      rule: "Host(`pihole.177cpt.com`)"
      middlewares:
        - redirectregex-pihole
        - default-headers
        - addprefix-pihole
        - https-redirectscheme
      tls: {}
      service: pihole
    
#endregion
#region services
  services:
    pihole:
      loadBalancer:
        servers:
          - url: "http://10.0.1.44:8080"
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
