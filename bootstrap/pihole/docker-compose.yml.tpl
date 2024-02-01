version: '2'
#this is not being used right now
services:
  pihole:
    container_name: pihole
    image: pihole/pihole:latest
    hostname: virtual-pihole
    domainname: 177cpt.com             # <-- Update
    mac_address: d0:ca:ab:cd:ef:01
    cap_add:
      - NET_ADMIN
    networks:
      pihole_network:
        ipv4_address: 10.0.1.10   # <-- Update
    dns:
      - 127.0.0.1
      - 8.8.8.8
    ports:
      - 443/tcp
      - 53/tcp
      - 53/udp
      - 67/udp
      - 80/tcp
    environment:
      ServerIP: 10.0.1.10         # <-- Update (match ipv4_address)
      VIRTUAL_HOST: virtual-pihole.177cpt.com  # <-- Update (match hostname + domainname)
      WEBPASSWORD: "asdf"                   # <-- Add password (if required)
    restart: unless-stopped

networks:
  pihole_network:
    driver: macvlan
    driver_opts:
      parent: ovs_eth0
    ipam:
      config:
        - subnet: 10.0.1.0/26            # <-- Update
          gateway: 10.0.1.2/26              # <-- Update
          ip_range: 10.0.1.32/28        # <-- Update