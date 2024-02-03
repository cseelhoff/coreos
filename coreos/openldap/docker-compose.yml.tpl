version: "2"
services:
  openldap:
    image: ${OPENLDAP_DOCKER_IMAGE}
    container_name: openldap
    environment:
      LDAP_LOG_LEVEL: "256"
      LDAP_ORGANISATION: "${ORGANISATION_NAME}"
      LDAP_DOMAIN: "${DOMAIN_NAME}"
      LDAP_ADMIN_PASSWORD: "${LDAP_ADMIN_PASSWORD}"
      LDAP_CONFIG_PASSWORD: "${LDAP_CONFIG_PASSWORD}"
      LDAP_READONLY_USER: "false"
      LDAP_RFC2307BIS_SCHEMA: "false"
      LDAP_BACKEND: "mdb"
      LDAP_TLS: "true"
      LDAP_TLS_CRT_FILENAME: "ldap.crt"
      LDAP_TLS_KEY_FILENAME: "ldap.key"
      LDAP_TLS_DH_PARAM_FILENAME: "dhparam.pem"
      LDAP_TLS_CA_CRT_FILENAME: "ca.crt"
      LDAP_TLS_ENFORCE: "false"
      LDAP_TLS_CIPHER_SUITE: "SECURE256:-VERS-SSL3.0"
      LDAP_TLS_VERIFY_CLIENT: "demand"
      LDAP_REPLICATION: "false"
      KEEP_EXISTING_CONFIG: "false"
      LDAP_REMOVE_CONFIG_AFTER_SETUP: "true"
      LDAP_SSL_HELPER_PREFIX: "ldap"
    tty: true
    stdin_open: true
    volumes:
      - database:/var/lib/ldap
      - config:/etc/ldap/slapd.d
      - certs:/container/service/slapd/assets/certs/
    ports:
      - "389:389"
      - "636:636"
    domainname: "${DOMAIN_NAME}"
    hostname: "ldap"
  phpldapadmin:
    image: ${PHPLDAPADMIN_DOCKER_IMAGE}
    container_name: phpldapadmin
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: "ldap"
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "${OPENLDAP_PORT}:80"
    depends_on:
      - openldap
volumes:
  database:
  config:
  certs:
