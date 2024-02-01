#!/bin/bash

# if user is not in docker group, add them
if ! groups | grep -q docker; then
  sudo usermod -aG docker $USER
  newgrp docker
  echo "You may need to log out and back in for the changes to take effect"
  #exit 1
fi

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

# making this a function so it can easily be collapsed in the editor
get_network_info() {
  HOST_IP=$(hostname -I | cut -d' ' -f1)
  HOST_GATEWAY_IP=$(ip route | grep default | cut -d' ' -f3)
  # get primary network interface from ip route
  PRIMARY_NETWORK_INTERFACE=$(ip route | grep default | cut -d' ' -f5)
  HOST_SUBNET_MASK=$(ip -o -f inet addr show | grep $PRIMARY_NETWORK_INTERFACE | awk '/scope global/ {print $4}')
  CIDR=$(echo $HOST_SUBNET_MASK | cut -d'/' -f2)

  # Calculate the network address
  HOST_IP_INT=$(echo $HOST_IP | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
  HOST_GATEWAY_IP_INT=$(echo $HOST_GATEWAY_IP | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
  NUM_IPS=$((2**(32-$CIDR)))
  CIDR_INT=$(( (0xFFFFFFFF << (32 - $CIDR)) & 0xFFFFFFFF ))
  NETWORK_ADDRESS_INT=$(($HOST_IP_INT & $CIDR_INT))
  NETWORK_ADDRESS_IP=$(printf "%d.%d.%d.%d" $(($NETWORK_ADDRESS_INT>>24&255)) $(($NETWORK_ADDRESS_INT>>16&255)) $(($NETWORK_ADDRESS_INT>>8&255)) $(($NETWORK_ADDRESS_INT&255)))
  #echo "NETWORK_ADDRESS_IP: $NETWORK_ADDRESS_IP"
  BROADCAST_INT=$(($NETWORK_ADDRESS_INT + NUM_IPS - 1))

  if [ $HOST_IP_INT -lt $HOST_GATEWAY_IP_INT ]; then
    INT2=$HOST_IP_INT
    INT3=$HOST_GATEWAY_IP_INT
  else
    INT2=$HOST_GATEWAY_IP_INT
    INT3=$HOST_IP_INT
  fi
  RANGE1=$(($INT2 - $NETWORK_ADDRESS_INT))
  RANGE2=$(($INT3 - $INT2))
  RANGE3=$(($BROADCAST_INT - $INT3))
  # Find the greatest range
  if [ $RANGE1 -gt $RANGE2 ] && [ $RANGE1 -gt $RANGE3 ]; then
    STARTING_IP_INT=$(($NETWORK_ADDRESS_INT+1))
    ENDING_IP_INT=$(($INT2-1))
  elif [ $RANGE2 -gt $RANGE1 ] && [ $RANGE2 -gt $RANGE3 ]; then
    STARTING_IP_INT=$(($INT2+1))
    ENDING_IP_INT=$(($INT3-1))
  else
    STARTING_IP_INT=$(($INT3+1))
    ENDING_IP_INT=$(($BROADCAST_INT-1))
  fi

  # convert the network address back to a dotted decimal
  STARTING_IP=$(printf "%d.%d.%d.%d" $(($STARTING_IP_INT>>24&255)) $(($STARTING_IP_INT>>16&255)) $(($STARTING_IP_INT>>8&255)) $(($STARTING_IP_INT&255)))
  ENDING_IP=$(printf "%d.%d.%d.%d" $(($ENDING_IP_INT>>24&255)) $(($ENDING_IP_INT>>16&255)) $(($ENDING_IP_INT>>8&255)) $(($ENDING_IP_INT&255)))
}
get_network_info
echo "HOST_IP: $HOST_IP"
echo "HOST_GATEWAY_IP: $HOST_GATEWAY_IP"
echo "STARTING_IP: $STARTING_IP"
echo "ENDING_IP: $ENDING_IP"

### --- VARIABLES --- ###
# NOTE: it is required to "export" any variables that are used in templates; also GOVC seems to require this
export ORGANIZATION_NAME='177th Cyber Protection Team'
export DOMAIN_NAME='177cpt.com'
export CLOUDFLARE_EMAIL=cseelhoff@gmail.com
export TIMEZONE=America/Chicago
export GOVC_URL="vsphere2.us.177cpt.com"
export GOVC_USERNAME="Administrator@VSPHERE.LOCAL"
export GOVC_HOST="10.0.1.31"
export GOVC_DATASTORE="esxi4_datastore"
export GOVC_VM="infravm"
export GOVC_NETWORK="Internal Management"
#GOVC_IP=$(dig +short $GOVC_URL)
GOVC_IP="10.0.1.41"
DNS_SERVER_IP=$HOST_IP
BOOTSTRAP_IP=$DNS_SERVER_IP
DHCP_ROUTER_IP=$HOST_GATEWAY_IP
DHCP_START_IP=$STARTING_IP
DHCP_END_IP=$ENDING_IP

### --- OPTIONAL VARIABLES --- ###
export GOVC_INSECURE=true
export GOVC_TLS_KNOWN_HOSTS=~/.govc_known_hosts
COREOS_OVA_URL="https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240104.3.0/x86_64/fedora-coreos-39.20240104.3.0-vmware.x86_64.ova"
COREOS_OVA_NAME="fedora-coreos-39.20240104.3.0-vmware.x86_64"
PIHOLE_DOCKER_IMAGE=pihole/pihole:2024.01.0
export PORTAINER_DOCKER_IMAGE=portainer/portainer-ce:2.19.4
export OPENLDAP_DOCKER_IMAGE=osixia/openldap:1.5.0
NEXUS_DOCKER_IMAGE=sonatype/nexus3:3.64.0
GITEA_DOCKER_IMAGE=gitea/gitea:1.21.4
export TRAEFIK_DOCKER_IMAGE=traefik:v2.10.4
export PHPLDAPADMIN_DOCKER_IMAGE=osixia/phpldapadmin:0.9.0
#export AWX_GHCR_IMAGE=ghcr.io/ansible/awx_devel:devel
export AWX_GHCR_IMAGE=ansible/awx_devel:devel
#PIHOLE_ETC_PIHOLE_DIR=$(pwd)/bootstrap/etc-pihole/
#PIHOLE_ETC_DNSMASQ_DIR=$(pwd)/bootstrap/etc-dnsmasq.d/
# replace symbols that would need to be web encoded
PIHOLE_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
TRAEFIK_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
NEXUS_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
LDAP_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
LDAP_CONFIG_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
PORTAINER_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
DJANGO_SUPERUSER_PASSWORD=$(openssl rand -base64 32 | tr '+' '0')
AWX_POSTGRES_PASSWORD="rzabMdUaDNuyQGmnYUQN" #$(openssl rand -base64 32)
BROADCAST_WEBSOCKET_SECRET="QnJ1V0FzUG5Eb2pIRURCRnFKQ0Y=" #$(openssl rand -base64 32)
AWX_SECRET_KEY="JDqxKuQemHEajsZVZFQs" #$(openssl rand -base64 32)
PIHOLE_SHORTNAME=pihole
NEXUS_SHORTNAME=nexus
TRAEFIK_SHORTNAME=traefik
DOCKER_SHORTNAME=docker
UPSTREAM_DNS_IPS="1.1.1.1;1.0.0.1"
PORTAINER_PORT=9000
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
export PORTAINER_LOCALHOST_URL=http://localhost:$PORTAINER_PORT
#PIHOLE_LOCALHOST_BASE_URL=http://localhost:$PIHOLE_PORT
#PIHOLE_LOGIN_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/login.php
#PIHOLE_INDEX_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/index.php
#PIHOLE_SETTINGS_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/settings.php?tab=dns
#PIHOLE_CUSTOM_DNS_URL=$PIHOLE_LOCALHOST_BASE_URL/admin/scripts/pi-hole/php/customdns.php
NEXUS_SERIVICE_REST_URL=https://$NEXUS_FRONTEND_FQDN/service/rest/v1
GOVC_CONNECTION_STRING=$GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
export TRAEFIK_DATA_DIR=$(pwd)/bootstrap/traefik/data
#change to container for passowrds
export TRAEFIK_AUTH=$(htpasswd -nb "admin" "$TRAEFIK_PASSWORD" | sed -e s/\\$/\\$\\$/g)
export PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2 | sed -e s/\\$/\\$\\$/g)
export COREOS_ADMIN_PASSWORD_HASH=$(mkpasswd --method=yescrypt $COREOS_ADMIN_PASSWORD | sed -e s/\\$/\\$\\$/g)
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
envsubst < coreos/coreos.bu.tpl > coreos/coreos.bu
echo $AWX_SECRET_KEY > coreos/awx/etc/tower/SECRET_KEY
butane --files-dir coreos --pretty --strict coreos/coreos.bu --output coreos/coreos.ign

### --- MAIN --- ###
remove_docker_container() {
    containerName=$1
    echo "Checking if the container named $containerName exists"
    if docker ps -a --format '{{.Names}}' | grep -q "$containerName"; then
        echo "Container '$containerName' exists. Checking if it is running"
        if docker ps --format '{{.Names}}' | grep -q "$containerName"; then
            echo "Container '$containerName' is running. Stopping container..."
            docker stop $containerName > /dev/null
        else
            echo "Container '$containerName' is not running"
        fi
        echo "Removing container '$containerName'..."
        docker rm $containerName > /dev/null
    else
        echo "Container '$containerName' does not exist"
    fi
}

# Usage
remove_docker_container "pihole"
echo "Deploying Pi-hole for DNS and DHCP on bootstrap server. Password is $PIHOLE_PASSWORD"
docker run -d \
  --name=pihole \
  -h virtual-pihole \
  -e DNSMASQ_LISTENING=all \
  -e TZ=$TIMEZONE \
  -e PIHOLE_DNS_=$UPSTREAM_DNS_IPS \
  -e DHCP_ACTIVE=true \
  -e DHCP_START=$DHCP_START_IP \
  -e DHCP_END=$DHCP_END_IP \
  -e DHCP_ROUTER=$DHCP_ROUTER_IP \
  -e PIHOLE_DOMAIN=$DOMAIN_NAME \
  -e VIRTUAL_HOST=virtual-pihole.$DOMAIN_NAME \
  -e WEBPASSWORD=$PIHOLE_PASSWORD \
  -e WEB_PORT=$PIHOLE_PORT \
  -v /etc/pihole/ \
  -v /etc/dnsmasq.d/ \
  --cap-add NET_ADMIN \
  --restart=unless-stopped \
  --network=host \
  $PIHOLE_DOCKER_IMAGE

echo "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig before changing local DNS settings"
dig +short $NEXUS_FRONTEND_FQDN

# Define the custom DNS list
CUSTOM_DNS_LIST="
$PIHOLE_IP $PIHOLE_BACKEND_FQDN
$NEXUS_IP $NEXUS_BACKEND_FQDN
$DOCKER_REGISTRY_IP $DOCKER_REGISTRY_BACKEND_FQDN
$TRAEFIK_IP $TRAEFIK_FQDN
$TRAEFIK_IP $PIHOLE_FRONTEND_FQDN
$TRAEFIK_IP $NEXUS_FRONTEND_FQDN
$TRAEFIK_IP $DOCKER_REGISTRY_FRONTEND_FQDN
$GOVC_IP vsphere2.177cpt.com
$GOVC_IP $GOVC_URL
"
# Append the custom DNS list to the pihole custom list file and restart the DNS service
echo "Append the custom DNS list to the pihole custom list file and restart the DNS service"

dockerSHCommand="echo \"$CUSTOM_DNS_LIST\" >> /etc/pihole/custom.list && pihole restartdns"
docker exec pihole sh -c "$dockerSHCommand"

#docker exec -it pihole sh -c "echo -e \"$CUSTOM_DNS_LIST\" >> /etc/pihole/custom.list && pihole restartdns"
#echo "Setting default DNS servers on Pi-hole to cloudflare 1.1.1.1 and 1.0.0.1"
#curl -s -b cookies.txt -X POST $PIHOLE_SETTINGS_URL --data-raw "DNSserver1.1.1.1=true&DNSserver1.0.0.1=true&custom1val=&custom2val=&custom3val=&custom4val=&DNSinterface=all&rate_limit_count=1000&rate_limit_interval=60&field=DNS&token=$PIHOLE_TOKEN" > /dev/null
echo "Setting DNS to use 127.0.0.1 (Pi-hole) and setting search domain to $DOMAIN_NAME"
echo -e "nameserver 127.0.0.1\nsearch $DOMAIN_NAME" | sudo tee /etc/resolv.conf > /dev/null
echo -e "[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n" | sudo tee /etc/systemd/resolved.conf > /dev/null
echo "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig after changing local DNS settings"
dig +short $NEXUS_FRONTEND_FQDN
#echo "Stopping and removing existing Traefik container"

remove_docker_container "traefik"
echo "Checking if the volume named traefik-data exists"
if docker volume inspect traefik-data > /dev/null 2>&1; then
  echo "Volume 'traefik-data' exists. Removing volume..."
  docker volume rm traefik-data
fi
echo "Creating volume 'traefik-data'"
docker volume create --name traefik-data
echo "Creating temporary container to copy acme.json to traefik-data volume"
docker run --rm -d -v traefik-data:/data --name temp alpine tail -f /dev/null
# check if the acme.json file exists in the backup folder
if [ -f backup/acme.json ]; then
    echo "Restoring acme.json from backup"
    docker cp backup/acme.json temp:/data/
else
    echo "Creating new acme.json"
    docker exec temp touch /data/acme.json
fi

echo "Setting permissions to 600 on Traefik acme.json"
docker exec temp chmod 600 /data/acme.json
echo "Stopping and removing temporary container"
docker stop temp

echo "Checking if proxy network for Traefik exists"
if docker network inspect proxy >/dev/null 2>&1; then
  echo "Proxy network exists. Checking if any containers are using it"
  if docker network inspect proxy | grep -q '"Containers": {}'; then
    echo "No containers are using the proxy network. Removing the proxy network"
    docker network rm proxy > /dev/null
  else
    echo "Other containers are still using the proxy network. Exiting script as failed."
    exit 1
  fi
fi
echo "Creating proxy network for Traefik"
docker network create proxy > /dev/null
echo "Starting Traefik with password: $TRAEFIK_PASSWORD"
docker-compose -f bootstrap/traefik/docker-compose.yml -p traefik up -d

remove_docker_container "nexus"

echo "Checking if the volume named nexus-data exists"
if docker volume inspect nexus-data >/dev/null 2>&1; then
  echo "Volume 'nexus-data' exists. Removing volume..."
  docker volume rm nexus-data > /dev/null
fi
echo "Creating volume 'nexus-data'"
docker volume create --name nexus-data
if [ -f backup/nexus-backup.tar.gz ]; then
  echo "Restoring Nexus from backup"
  docker run --rm -v nexus-data:/nexus-data -v $(pwd)/backup:/backup alpine tar -xzf /backup/nexus-backup.tar.gz -C /nexus-data
else
  echo "No backup found, creating new Nexus"
  echo "Starting Nexus"
  docker run -d -p $NEXUS_PORT:$NEXUS_PORT -p $DOCKER_REGISTRY_PORT:$DOCKER_REGISTRY_PORT --name nexus -v nexus-data:/nexus-data $NEXUS_DOCKER_IMAGE
  printf "Waiting for Nexus to start on: $NEXUS_SERIVICE_REST_URL/security/users"
  until $(curl -u admin:$NEXUS_TEMP_PASSWORD -X GET --output /dev/null --silent --head --fail $NEXUS_SERIVICE_REST_URL/security/users); do
    printf '.'
    sleep 1
    # if the password is not set, get it from the container
    if [ -z "$NEXUS_TEMP_PASSWORD" ]; then
      NEXUS_TEMP_PASSWORD=$(docker exec nexus cat /nexus-data/admin.password 2>/dev/null)
      if [ -n "$NEXUS_TEMP_PASSWORD" ]; then
        printf "\n"
        echo "Nexus temp password is: $NEXUS_TEMP_PASSWORD"
        printf "Continuing to wait for Nexus to start"
      fi
    fi
  done
  # change the default admin password
  printf '\n'
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

  echo 'Removing local docker images cache'
  docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
  docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$PORTAINER_DOCKER_IMAGE
  #docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$OPENLDAP_DOCKER_IMAGE
  docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$TRAEFIK_DOCKER_IMAGE
  #docker image rm $DOCKER_REGISTRY_FRONTEND_FQDN/$AWX_GHCR_IMAGE
  echo 'Caching docker images in Nexus'
  docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
  docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$PORTAINER_DOCKER_IMAGE
  #docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$OPENLDAP_DOCKER_IMAGE
  docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$TRAEFIK_DOCKER_IMAGE
  #docker pull $DOCKER_REGISTRY_FRONTEND_FQDN/$AWX_GHCR_IMAGE

  #When stopping, be sure to allow sufficient time for the databases to fully shut down.
  echo 'Stopping Nexus to create backup'
  docker stop --time=120 nexus
  echo 'Creating Nexus backup'
  # create a new backup directory if it does not exist
  [ -d backup ] || mkdir backup
  docker run --rm -v nexus-data:/nexus-data -v $(pwd)/backup:/backup alpine sh -c "tar -C /nexus-data -czf /backup/nexus-backup.tar.gz ."
  echo 'Starting Nexus'
  docker start nexus
fi
printf "Waiting for Nexus to start on: $NEXUS_SERIVICE_REST_URL/security/users"
until $(curl -u admin:$NEXUS_PASSWORD -X GET --output /dev/null --silent --head --fail $NEXUS_SERIVICE_REST_URL/security/users); do
  printf '.'
  sleep 1  
done
printf '\n'

echo "Creating backup of acme.json"
if [ ! -d "backup" ]; then
    mkdir backup
fi
docker cp traefik:/data/acme.json backup/

echo 'Bootstrap complete!'

echo 'Logging into vCenter'
govc about.cert -u $GOVC_URL -k -thumbprint | tee -a $GOVC_TLS_KNOWN_HOSTS
govc about -u $GOVC_CONNECTION_STRING
govc session.login -u $GOVC_CONNECTION_STRING
# why this fixes things, we don't know...
govc library.ls -u $GOVC_CONNECTION_STRING > /dev/null

echo 'Creating library and importing OVA'
if govc library.ls -u $GOVC_CONNECTION_STRING -json | jq -r '.[].name' | grep -q $VCENTER_LIBRARY_NAME; then
  echo "Library name: $VCENTER_LIBRARY_NAME already exists"
else
  echo "Creating library $VCENTER_LIBRARY_NAME"
  govc library.create -u $GOVC_CONNECTION_STRING -ds=$GOVC_DATASTORE $VCENTER_LIBRARY_NAME
fi

echo 'Checking if OVA already exists in library'
if govc library.ls -u $GOVC_CONNECTION_STRING $VCENTER_LIBRARY_NAME/* | grep -q $COREOS_OVA_NAME; then
  echo "OVA $COREOS_OVA_NAME already exists in library $VCENTER_LIBRARY_NAME"
else
  echo "Importing OVA $COREOS_OVA_NAME into library $VCENTER_LIBRARY_NAME"
  govc library.import -u $GOVC_CONNECTION_STRING -n=$COREOS_OVA_NAME $VCENTER_LIBRARY_NAME $COREOS_OVA_URL
fi

echo 'Deploying VM from OVA'
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
