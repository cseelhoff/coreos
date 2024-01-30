#!/bin/bash

### --- SECRETS --- ###
# Store and retrieve secrets from .env file
[ -f .env ] && source .env
keys=("CF_DNS_API_TOKEN" "GOVC_PASSWORD" "COREOS_ADMIN_PASSWORD")
for key in "${keys[@]}"; do
  # Check if the key exists in the environment
  if [ -z "${!key}" ]; then
    read -p "Enter a value for $key: " value
    echo "export $key='$value'" >> .env
  fi
done
source .env

### --- VARIABLES --- ###
# NOTE: it is required to "export" any variables that are used in templates; also GOVC seems to require this
export ORGANIZATION_NAME='177th Cyber Protection Team'
export DOMAIN_NAME='177cpt.com'
export CLOUDFLARE_EMAIL=cseelhoff@gmail.com
export TIMEZONE=America/Chicago
DNS_SERVER_IP='10.0.1.10'
# get all IP addresses of current machine
ALL_IPS=$(hostname -I)

#BOOTSTRAP_IP=$DNS_SERVER_IP
DHCP_ROUTER_IP='10.0.1.2'
DHCP_START_IP='10.0.1.11'
DHCP_END_IP='10.0.1.30'
export GOVC_URL="vsphere2.us.177cpt.com"
GOVC_IP='10.0.1.41'
export GOVC_USERNAME="Administrator@VSPHERE.LOCAL"
export GOVC_HOST="10.0.1.31"
export GOVC_DATASTORE="esxi4_datastore"
export GOVC_VM="coreos"
export GOVC_NETWORK="Internal Management"
export GOVC_INSECURE=true
export GOVC_TLS_KNOWN_HOSTS=~/.govc_known_hosts

### --- OPTIONAL VARIABLES --- ###
COREOS_OVA_URL="https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240104.3.0/x86_64/fedora-coreos-39.20240104.3.0-vmware.x86_64.ova",
COREOS_OVA_NAME="fedora-coreos-39.20240104.3.0-vmware.x86_64"
PIHOLE_DOCKER_IMAGE=pihole/pihole:2024.01.0
export PORTAINER_DOCKER_IMAGE=portainer/portainer-ce:2.19.4
export OPENLDAP_DOCKER_IMAGE=osixia/openldap:1.5.0
NEXUS_DOCKER_IMAGE=sonatype/nexus3:3.64.0
GITEA_DOCKER_IMAGE=gitea/gitea:1.21.4
export TRAEFIK_DOCKER_IMAGE=traefik:v2.11
export PHPLDAPADMIN_DOCKER_IMAGE=osixia/phpldapadmin:0.9.0
#export AWX_GHCR_IMAGE=ghcr.io/ansible/awx_devel:devel
export AWX_GHCR_IMAGE=ansible/awx_devel:devel
#PIHOLE_ETC_PIHOLE_DIR=$(pwd)/bootstrap/etc-pihole/
#PIHOLE_ETC_DNSMASQ_DIR=$(pwd)/bootstrap/etc-dnsmasq.d/
# replace symbols that would need to be web encoded
PIHOLE_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
TRAEFIK_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
NEXUS_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
export LDAP_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
export LDAP_CONFIG_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
export PORTAINER_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
export DJANGO_SUPERUSER_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
export AWX_POSTGRES_PASSWORD="rzabMdUaDNuyQGmnYUQN" #$(openssl rand -base64 32)
export BROADCAST_WEBSOCKET_SECRET="QnJ1V0FzUG5Eb2pIRURCRnFKQ0Y=" #$(openssl rand -base64 32)
export AWX_SECRET_KEY="JDqxKuQemHEajsZVZFQs" #$(openssl rand -base64 32)
export PIHOLE_SHORTNAME=pihole
export NEXUS_SHORTNAME=nexus
export TRAEFIK_SHORTNAME=traefik
export DOCKER_SHORTNAME=docker

export PORTAINER_PORT=9000
PIHOLE_PORT=8001
NEXUS_PORT=8081
DOCKER_REGISTRY_PORT=8002
VCENTER_LIBRARY_NAME=library

### --- AUTO-GENERATED VARIABLES --- ###
export PIHOLE_FRONTEND_FQDN=$PIHOLE_SHORTNAME.$DOMAIN_NAME
export NEXUS_FRONTEND_FQDN=$NEXUS_SHORTNAME.$DOMAIN_NAME
export DOCKER_REGISTRY_FRONTEND_FQDN=$DOCKER_SHORTNAME.$DOMAIN_NAME
export TRAEFIK_FQDN=$TRAEFIK_SHORTNAME.$DOMAIN_NAME
export PIHOLE_BACKEND_FQDN=$PIHOLE_SHORTNAME-backend01.$DOMAIN_NAME
export NEXUS_BACKEND_FQDN=$NEXUS_SHORTNAME-backend01.$DOMAIN_NAME
export DOCKER_REGISTRY_BACKEND_FQDN=$DOCKER_SHORTNAME-backend01.$DOMAIN_NAME
TRAEFIK_IP=$BOOTSTRAP_IP
PIHOLE_IP=$BOOTSTRAP_IP
NEXUS_IP=$BOOTSTRAP_IP
DOCKER_REGISTRY_IP=$BOOTSTRAP_IP
export PIHOLE_BACKEND_URL=http://$PIHOLE_BACKEND_FQDN:$PIHOLE_PORT
export NEXUS_BACKEND_URL=http://$NEXUS_BACKEND_FQDN:$NEXUS_PORT
export DOCKER_REGISTRY_BACKEND_URL=http://$DOCKER_REGISTRY_BACKEND_FQDN:$DOCKER_REGISTRY_PORT
PIHOLE_LOCALHOST_BASE_URL=http://localhost:$PIHOLE_PORT
PIHOLE_LOGIN_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/login.php
PIHOLE_INDEX_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/index.php
PIHOLE_SETTINGS_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/settings.php?tab=dns
PIHOLE_CUSTOM_DNS_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/scripts/pi-hole/php/customdns.php
NEXUS_SERIVICE_REST_URL=https://$NEXUS_FRONTEND_FQDN/service/rest/v1
GOVC_CONNECTION_STRING=$GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
export TRAEFIK_AUTH=$(htpasswd -nb "admin" "$TRAEFIK_PASSWORD" | sed -e s/\\$/\\$\\$/g) 
export PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2 | sed -e s/\\$/\\$\\$/g)
export COREOS_ADMIN_PASSWORD_HASH=$(mkpasswd --method=yescrypt $COREOS_ADMIN_PASSWORD)
echo "Creating ssh keypair if it does not exist..."
[ -f ~/.ssh/id_rsa ] || ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N '' >/dev/null
export COREOS_SSH_PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)

### --- TEMPLATES --- ###
echo "Generating templates"
envsubst < bootstrap/traefik/docker-compose.yml.tpl > bootstrap/traefik/docker-compose.yml
envsubst < bootstrap/traefik/data/config.yml.tpl > bootstrap/traefik/data/config.yml
envsubst < bootstrap/traefik/data/traefik.yml.tpl > bootstrap/traefik/data/traefik.yml
envsubst < coreos/awx/docker-compose.yml.tpl > coreos/awx/docker-compose.yml
envsubst < coreos/awx/etc/tower/conf.d/database.py.tpl > coreos/awx/etc/tower/conf.d/database.py
envsubst < coreos/awx/etc/tower/conf.d/websocket_secret.py.tpl > coreos/awx/etc/tower/conf.d/websocket_secret.py
envsubst < coreos/guacamole/docker-compose.yml.tpl > coreos/guacamole/docker-compose.yml
envsubst < coreos/openldap/docker-compose.yml.tpl > coreos/openldap/docker-compose.yml
envsubst < coreos/portainer/deploy-stack.sh.tpl > coreos/portainer/deploy-stack.sh
envsubst < coreos/coreos.bu.tpl > coreos/coreos.bu
echo $AWX_SECRET_KEY > coreos/awx/etc/tower/SECRET_KEY
butane --files-dir coreos --pretty --strict coreos/coreos.bu --output coreos/coreos.ign

### --- MAIN --- ###
echo "Deploying Pi-hole for DNS and DHCP on bootstrap server. Password is $PIHOLE_PASSWORD"
#mkdir -p $PIHOLE_ETC_PIHOLE_DIR
#mkdir -p $PIHOLE_ETC_DNSMASQ_DIR
sudo docker run -d \
  --name=pihole \
  -h pihole \
  -p 53:53/tcp -p 53:53/udp -p 67:67/udp -p $PIHOLE_PORT:80/tcp \
  -e DNSMASQ_LISTENING=all \
  -e TZ=$TIMEZONE \
  -e PIHOLE_DNS_=$DNS_SERVER_IP \
  -e DHCP_ROUTER_IP=$DHCP_ROUTER_IP \
  -e DHCP_START_IP=$DHCP_START_IP \
  -e DHCP_END_IP=$DHCP_END_IP \
  -e PIHOLE_DOMAIN=$DOMAIN_NAME \
  -e VIRTUAL_HOST=pihole \
  -e WEBPASSWORD=$PIHOLE_PASSWORD \
  -v /etc/pihole/ \
  -v /etc/dnsmasq.d/ \
  --cap-add NET_ADMIN \
  --restart=unless-stopped \
  $PIHOLE_DOCKER_IMAGE

# Wait for pihole to start
printf 'Waiting for Pi-hole to start'
until $(curl --output /dev/null --silent --head --fail $PIHOLE_LOGIN_URL); do
  printf '.'
  sleep 1
done
echo "Logging into Pi-hole"
PIHOLE_TOKEN=$(curl -s -d "pw=$PIHOLE_PASSWORD" -c cookies.txt -X POST $PIHOLE_INDEX_URL | grep -oP '(?<=<div id="token" hidden>)(\S+)(?=<\/div>)' -m 1 | tr '\n' '\0' | jq -sRr @uri)
echo "Obtained Pi-hole token: $PIHOLE_TOKEN"
# Add DNS A record for pihole, nexus, traefik, and docker registry
function add_dns_a_record() {
  local fqdn=$1
  local ip=$2
  echo "Adding DNS A record for $fqdn with IP $ip"
  curl -s -d "action=add&ip=$ip&domain=$fqdn&token=$PIHOLE_TOKEN" -b cookies.txt -X POST $PIHOLE_CUSTOM_DNS_URL
}
add_dns_a_record $PIHOLE_BACKEND_FQDN $PIHOLE_IP
add_dns_a_record $NEXUS_BACKEND_FQDN $NEXUS_IP
add_dns_a_record $DOCKER_REGISTRY_BACKEND_FQDN $DOCKER_REGISTRY_IP
add_dns_a_record $TRAEFIK_FQDN $TRAEFIK_IP
add_dns_a_record $PIHOLE_FRONTEND_FQDN $TRAEFIK_IP
add_dns_a_record $NEXUS_FRONTEND_FQDN $TRAEFIK_IP
add_dns_a_record $DOCKER_REGISTRY_FRONTEND_FQDN $TRAEFIK_IP
add_dns_a_record $GOVC_URL $GOVC_IP

echo "Setting default DNS servers on Pi-hole to cloudflare 1.1.1.1 and 1.0.0.1"
curl -s -b cookies.txt -X POST $PIHOLE_SETTINGS_URL --data-raw "DNSserver1.1.1.1=true&DNSserver1.0.0.1=true&custom1val=&custom2val=&custom3val=&custom4val=&DNSinterface=all&rate_limit_count=1000&rate_limit_interval=60&field=DNS&token=$PIHOLE_TOKEN" > /dev/null

echo "Setting DNS to use 127.0.0.1 (Pi-hole) and setting search domain to $DOMAIN_NAME"
echo -e "nameserver 127.0.0.1\nsearch $DOMAIN_NAME" | sudo tee /etc/resolv.conf > /dev/null
echo -e "[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n" | sudo tee /etc/systemd/resolved.conf > /dev/null
echo "Creating proxy network for Traefik"
sudo docker network create proxy
echo "Setting permissions to 600 on Traefik acme.json"
chmod 600 bootstrap/traefik/data/acme.json
echo "Starting Traefik"
sudo docker-compose -f bootstrap/traefik/docker-compose.yml -p traefik up -d
sudo docker volume create --name nexus-data
if [ -f backup/nexus-backup.tar.gz ]; then
  printf "Restoring Nexus from backup"
  sudo docker run --rm -v nexus-data:/nexus-data -v $(pwd)/backup:/backup alpine tar -xzf /backup/nexus-backup.tar.gz -C /nexus-data
fi
printf "Starting Nexus"
sudo docker run -d -p $NEXUS_PORT:$NEXUS_PORT -p $DOCKER_REGISTRY_PORT:$DOCKER_REGISTRY_PORT --name nexus -v nexus-data:/nexus-data $NEXUS_DOCKER_IMAGE
printf "Waiting for Nexus to start on: $NEXUS_SERIVICE_REST_URL/security/users"
until $(curl -u admin:$NEXUS_TEMP_PASSWORD -X GET --output /dev/null --silent --head --fail $NEXUS_SERIVICE_REST_URL/security/users); do
  printf '.'
  sleep 1
  NEXUS_TEMP_PASSWORD=$(sudo docker exec nexus cat /nexus-data/admin.password 2>/dev/null)
done
# change the default admin password
echo "Changing Nexus password from: $NEXUS_TEMP_PASSWORD to: $NEXUS_PASSWORD"
curl -u admin:$NEXUS_TEMP_PASSWORD -X PUT -d $NEXUS_PASSWORD -H "Content-Type: text/plain" $NEXUS_SERIVICE_REST_URL/security/users/admin/change-password
echo "Setting active realms to LdapRealm, DockerToken, and NexusAuthenticatingRealm"
curl -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '[
    "LdapRealm",
    "DockerToken",
    "NexusAuthenticatingRealm"
  ]' -X PUT $NEXUS_SERIVICE_REST_URL/security/realms/active
echo "Creating docker-hosted repository"
curl -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-hosted",
  "online": true,
  "storage": {
    "blobStoreName": "default",
    "strictContentTypeValidation": true,
    "writePolicy": "ALLOW"
  },
  "docker": {
    "v1Enabled": false,
    "forceBasicAuth": false
  }
}' -X POST $NEXUS_SERIVICE_REST_URL/repositories/docker/hosted
echo "Creating docker-proxy repository"
curl -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-proxy",
  "online": true,
  "storage": {
    "blobStoreName": "default",
    "strictContentTypeValidation": true
  },
  "proxy": {
    "remoteUrl": "https://registry-1.docker.io",
    "contentMaxAge": 1440,
    "metadataMaxAge": 1440
  },
  "negativeCache": {
    "enabled": true,
    "timeToLive": 1440
  },
  "httpClient": {
    "blocked": false,
    "autoBlock": false
  },
  "docker": {
    "v1Enabled": false,
    "forceBasicAuth": false
  },
  "dockerProxy": {
    "indexType": "HUB"
  }
}' -X POST $NEXUS_SERIVICE_REST_URL/repositories/docker/proxy
echo "Creating ghcr-proxy repository"
curl -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "ghcr-proxy",
  "online": true,
  "storage": {
    "blobStoreName": "default",
    "strictContentTypeValidation": true
  },
  "proxy": {
    "remoteUrl": "https://ghcr.io",
    "contentMaxAge": 1440,
    "metadataMaxAge": 1440
  },
  "negativeCache": {
    "enabled": true,
    "timeToLive": 1440
  },
  "httpClient": {
    "blocked": false,
    "autoBlock": false
  },
  "docker": {
    "v1Enabled": false,
    "forceBasicAuth": false
  },
  "dockerProxy": {
    "indexType": "REGISTRY"
  }
}' -X POST $NEXUS_SERIVICE_REST_URL/repositories/docker/proxy
echo "Creating docker-group repository for docker-hosted, docker-proxy, and ghcr-proxy"
curl -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d "{
  \"name\": \"docker-group\",
  \"online\": true,
  \"storage\": {
    \"blobStoreName\": \"default\",
    \"strictContentTypeValidation\": true
  },
  \"group\": {
    \"memberNames\": [
      \"docker-hosted\",
      \"docker-proxy\",
      \"ghcr-proxy\"
    ]
  },
  \"docker\": {
    \"v1Enabled\": false,
    \"forceBasicAuth\": false,
    \"httpPort\": $DOCKER_REGISTRY_PORT
  }
}" -X POST $NEXUS_SERIVICE_REST_URL/repositories/docker/group

printf 'Removing local docker images cache'
sudo docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
sudo docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$PORTAINER_DOCKER_IMAGE
#sudo docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$OPENLDAP_DOCKER_IMAGE
sudo docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$TRAEFIK_DOCKER_IMAGE
#sudo docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$AWX_GHCR_IMAGE
printf 'Caching docker images in Nexus'
sudo docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
sudo docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$PORTAINER_DOCKER_IMAGE
#sudo docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$OPENLDAP_DOCKER_IMAGE
sudo docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$TRAEFIK_DOCKER_IMAGE
#sudo docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$AWX_GHCR_IMAGE

#When stopping, be sure to allow sufficient time for the databases to fully shut down.
printf 'Stopping Nexus to create backup'
sudo docker stop --time=120 nexus
printf 'Creating Nexus backup'
mkdir backup
sudo docker run --rm -v nexus-data:/nexus-data -v $(pwd)/backup:/backup alpine tar -C /nexus-data -cf /backup/nexus-backup.tar.gz .
printf 'Starting Nexus'
sudo docker start nexus
printf 'Bootstrap complete!'

printf 'Logging into vCenter'
govc about.cert -u $GOVC_URL -k -thumbprint | tee -a $GOVC_TLS_KNOWN_HOSTS
govc about -u $GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
govc session.login -u $GOVC_CONNECTION_STRING
# why this fixes things, we don't know...
govc library.ls -u $GOVC_CONNECTION_STRING > /dev/null

printf 'Creating library and importing OVA'
if govc library.ls -u $GOVC_CONNECTION_STRING -json | jq -r '.[].name' | grep -q $VCENTER_LIBRARY_NAME; then
  echo "Library name: $VCENTER_LIBRARY_NAME already exists"
else
  echo "Creating library $VCENTER_LIBRARY_NAME"
  govc library.create -u $GOVC_CONNECTION_STRING -ds=$GOVC_DATASTORE $VCENTER_LIBRARY_NAME
fi

printf 'Checking if OVA already exists in library'
if govc library.ls -u $GOVC_CONNECTION_STRING $VCENTER_LIBRARY_NAME/* | grep -q $COREOS_OVA_NAME; then
  echo "OVA $COREOS_OVA_NAME already exists in library $VCENTER_LIBRARY_NAME"
else
  echo "Importing OVA $COREOS_OVA_NAME into library $VCENTER_LIBRARY_NAME"
  govc library.import -u $GOVC_CONNECTION_STRING -n=$COREOS_OVA_NAME $VCENTER_LIBRARY_NAME $COREOS_OVA_URL
fi

printf 'Deploying VM from OVA'
govc library.deploy -u $GOVC_CONNECTION_STRING -host=$GOVC_HOST /$VCENTER_LIBRARY_NAME/$COREOS_OVA_NAME $GOVC_VM
govc vm.change -u $GOVC_CONNECTION_STRING -vm $GOVC_VM -e="guestinfo.ignition.config.data=$(cat coreos/coreos.ign | base64 -w0)"
govc vm.change -u $GOVC_CONNECTION_STRING -vm $GOVC_VM -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.change -u $GOVC_CONNECTION_STRING -vm $GOVC_VM -m=32000 -c=8
govc vm.power -u $GOVC_CONNECTION_STRING -on $GOVC_VM

echo "Waiting for VM to be ready..."
VM_IP=$(govc vm.ip -u $GOVC_CONNECTION_STRING $GOVC_VM )
echo "YOUR PORTAINER PASSWORD IS: $PORTAINER_PASSWORD"
echo "$GOVC_VM's IP: $VM_IP"
echo "`date +"%Y-%m-%d %T"` -- deployment complete!"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# prompt user to press y to delete the VM
read -p "Press y to delete the VM: " -n 1 -r
if [[  $REPLY =~ ^[Yy]$ ]]
then
# delete the VM
  govc vm.power -u $GOVC_CONNECTION_STRING -off $GOVC_VM
  govc vm.destroy -u $GOVC_CONNECTION_STRING $GOVC_VM
fi
