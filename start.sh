#!/bin/sh

### --- SECRETS --- ###
# Store and retrieve secrets from .env file
[ -f .env ] && source .env
keys=("CF_API_KEY" "GOVC_PASSWORD" "COREOS_ADMIN_PASSWORD")
for key in "${keys[@]}"; do
    # Check if the key exists in the environment
    if [ -z "${!key}" ]; then
        read -p "Enter a value for $key: " value
        echo "export $key='$value'" >> .env
    fi
done
source .env

### --- VARIABLES --- ###
DOMAIN_NAME='177cpt.com'
CF_API_EMAIL=cseelhoff@gmail.com
TIMEZONE=America/Chicago
DNS_SERVER='10.0.1.44'
DHCP_ROUTER='10.0.1.2'
DHCP_START='10.0.1.10'
DHCP_END='10.0.1.50'
export GOVC_URL="vsphere2.us.177cpt.com"
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
PIHOLE_BASE_URL=http://localhost/admin
PIHOLE_ETC_PIHOLE_DIR=$(pwd)/etc-pihole/
PIHOLE_ETC_DNSMASQ_DIR=$(pwd)/etc-dnsmasq.d/
PIHOLE_PASSWORD=$(openssl rand -base64 32)
TRAEFIK_PASSWORD=$(openssl rand -base64 32)
NEXUS_PASSWORD=$(openssl rand -base64 32)
export PORTAINER_PASSWORD=$(openssl rand -base64 32)
PIHOLE_FQDN=pihole.$DOMAIN_NAME
NEXUS_FQDN=nexus.$DOMAIN_NAME
TRAEFIK_FQDN=traefik.$DOMAIN_NAME
NEXUS_PORT=8081
DOCKER_REGISTRY_PORT=5000
VCENTER_LIBRARY_NAME=library

### --- AUTO-GENERATED VARIABLES --- ###
PIHOLE_LOGIN_URL=$PIHOLE_BASE_URL/login.php
PIHOLE_INDEX_URL=$PIHOLE_BASE_URL/index.php
PIHOLE_CUSTOM_DNS_URL=$PIHOLE_BASE_URL/scripts/pi-hole/php/customdns.php
NEXUS_SERIVICE_REST_URL=https://$NEXUS_FQDN/service/rest/v1
NEXUS_CREDS=admin:$NEXUS_PASSWORD
GOVC_CONNECTION_STRING=$GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
export TRAEFIK_AUTH=$(htpasswd -nb "admin" "$TRAEFIK_PASSWORD")

### --- TEMPLATES --- ###
envsubst < bootstrap/traefik/docker-compose.yml.tpl > bootstrap/traefik/docker-compose.yml
envsubst < coreos/guacamole/docker-compose.yml.tpl > coreos/guacamole/docker-compose.yml
envsubst < coreos/openldap/docker-compose.yml.tpl > coreos/openldap/docker-compose.yml

### --- MAIN --- ###
echo "`date +"%Y-%m-%d %T"` -- deployment started!"
# Run the pihole container for DNS and DHCP on bootstrap
mkdir -p $PIHOLE_ETC_PIHOLE_DIR
mkdir -p $PIHOLE_ETC_DNSMASQ_DIR
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
    -e PIHOLE_DOMAIN=$DOMAIN_NAME \
    -e VIRTUAL_HOST=pihole \
    -e WEBPASSWORD=$PIHOLE_PASSWORD \
    -v $PIHOLE_ETC_PIHOLE_DIR:/etc/pihole/ \
    -v $PIHOLE_ETC_DNSMASQ_DIR:/etc/dnsmasq.d/ \
    --cap-add NET_ADMIN \
    --restart=unless-stopped \
    $PIHOLE_DOCKER_IMAGE

# Wait for pihole to start
printf 'Waiting for pihole to start'
until $(curl --output /dev/null --silent --head --fail $PIHOLE_LOGIN_URL); do
    printf '.'
    sleep 5
done
PIHOLE_TOKEN=$(curl -s -d "pw=$PIHOLE_PASSWORD" -c cookies.txt -X POST $PIHOLE_INDEX_URL | grep -oP '(?<=<div id="token" hidden>)(\S+)(?=<\/div>)' -m 1 | tr '\n' '\0' | jq -sRr @uri)
# Add DNS A record for pihole, nexus, traefik
function add_dns_a_record() {
    local fqdn=$1
    curl -d "action=add&ip=$DNS_SERVER&domain=$fqdn&token=$PIHOLE_TOKEN" -b cookies.txt -X POST $PIHOLE_CUSTOM_DNS_URL
}
add_dns_a_record $PIHOLE_FQDN
add_dns_a_record $NEXUS_FQDN
add_dns_a_record $TRAEFIK_FQDN

# create proxy network for traefik
docker network create proxy

# download and install docker-compose
curl -L "https://github.com/docker/compose/releases/download/v2.24.2/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
chmod 755 /usr/local/bin/docker-compose

docker-compose -f traefik/docker-compose.yml -p traefik up -d
#docker-compose -f traefik/docker-compose.yml -p traefik up -d --force-recreate

# install nexus into docker container
docker run -d -p $NEXUS_PORT:$NEXUS_PORT --name nexus sonatype/nexus3:3.64.0

# change the default admin password
NEXUS_TEMP_PASSWORD=$(docker exec -it nexus cat /nexus-data/admin.password)
curl -v -u admin:$NEXUS_TEMP_PASSWORD -X PUT -d $NEXUS_PASSWORD -H "Content-Type: text/plain" $NEXUS_SERIVICE_REST_URL/security/users/admin/change-password

# use nexus api to add a docker-hosted registry
curl -v -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-hosted",
  "type": "groovy",
  "content": "repository.createDockerHosted('docker-hosted')"
}' -X POST $NEXUS_SERIVICE_REST_URL/script

# create a docker-proxy repository to pull from docker hub
curl -v -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-proxy",
  "type": "groovy",
  "content": "repository.createDockerProxy('docker-proxy', 'https://registry-1.docker.io')"
}' -X POST $NEXUS_SERIVICE_REST_URL/script

# create a docker-group repository to pull from docker-proxy and docker-hosted on port 5000 and allow anonymous access
curl -v -u admin:$NEXUS_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-group",
  "type": "groovy",
  "content": "repository.createDockerGroup('docker-group', ['docker-hosted', 'docker-proxy'], '$DOCKER_REGISTRY_PORT', true)"
}' -X POST $NEXUS_SERIVICE_REST_URL/script


govc about.cert -u $GOVC_URL -k -thumbprint | tee -a $GOVC_TLS_KNOWN_HOSTS
govc about -u $GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
# init login
govc session.login -u $GOVC_CONNECTION_STRING
# why this fixes things, we don't know...
govc library.ls -u $GOVC_CONNECTION_STRING > /dev/null

export COREOS_ADMIN_PASSWORD_HASH=$(mkpasswd --method=yescrypt $COREOS_ADMIN_PASSWORD)
# if ~/.ssh/id_rsa does not exist, create it
[ -f ~/.ssh/id_rsa ] || ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ''
export COREOS_SSH_PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)
envsubst < coreos/coreos.bu.tpl > coreos/coreos.bu

# Escape special characters in the password to use in sed
ESCAPED_PORTAINER_PASSWORD=$(echo "$PORTAINER_PASSWORD" | sed -e 's/[\/&]/\\&/g')
# Replace the existing password in portainer/deploy-portainer.sh with the new password
envsubst < coreos/portainer/deploy-stack.sh.tpl > coreos/portainer/deploy-stack.sh
PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2)
# replace all of the $ symbols in the bcrypt hash with two consecutive $$ symbols
ESCAPED_PORTAINER_BCRYPT=$(echo "$PORTAINER_BCRYPT" | sed -e 's/\$/\$\$/g')
ESCAPED_PORTAINER_BCRYPT=$(echo "$ESCAPED_PORTAINER_BCRYPT" | sed -e 's/[\/&]/\\&/g')
sed -i "s/--admin-password '[^']*/--admin-password '$ESCAPED_PORTAINER_BCRYPT/g" ./coreos.bu

butane --files-dir ./ --pretty --strict coreos.bu --output coreos.ign

# use govc library.ls -json to check if the library exists
if govc library.ls -u $GOVC_CONNECTION_STRING -json | jq -r '.[].name' | grep -q $VCENTER_LIBRARY_NAME; then
  echo "Library name: $VCENTER_LIBRARY_NAME already exists"
else
  echo "Creating library $VCENTER_LIBRARY_NAME"
  govc library.create -u $GOVC_CONNECTION_STRING -ds=$GOVC_DATASTORE $VCENTER_LIBRARY_NAME
fi

# check if the OVA already exists in the library
if govc library.ls -u $GOVC_CONNECTION_STRING $VCENTER_LIBRARY_NAME/* | grep -q $COREOS_OVA_NAME; then
  echo "OVA $COREOS_OVA_NAME already exists in library $VCENTER_LIBRARY_NAME"
else
  echo "Importing OVA $COREOS_OVA_NAME into library $VCENTER_LIBRARY_NAME"
  govc library.import -u $GOVC_CONNECTION_STRING -n=$COREOS_OVA_NAME $VCENTER_LIBRARY_NAME $COREOS_OVA_URL
fi

govc library.deploy -u $GOVC_CONNECTION_STRING -host=$GOVC_HOST /$VCENTER_LIBRARY_NAME/$COREOS_OVA_NAME $GOVC_VM
govc vm.change -u $GOVC_CONNECTION_STRING -vm $GOVC_VM -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
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
