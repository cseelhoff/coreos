#!/bin/sh
if [ -z ${GOVC_PASSWORD+x} ]; then
  echo "Enter vCenter password:"
  read -s GOVC_PASSWORD
fi

GOVC_INSECURE=true
GOVC_TLS_KNOWN_HOSTS=~/.govc_known_hosts
GOVC_USERNAME=$(jq -r '.GOVC_USERNAME' vcenter_settings.json)
GOVC_URL=$(jq -r '.GOVC_URL' vcenter_settings.json)
GOVC_DATASTORE=$(jq -r '.GOVC_DATASTORE' vcenter_settings.json)
GOVC_VM=$(jq -r '.GOVC_VM' vcenter_settings.json)
GOVC_HOST=$(jq -r '.GOVC_HOST' vcenter_settings.json)
GOVC_NETWORK=$(jq -r '.GOVC_NETWORK' vcenter_settings.json)
OVA_URL=$(jq -r '.ova_url' vcenter_settings.json)
OVA_NAME=$(jq -r '.ova_name' vcenter_settings.json)
LIBRARY_NAME=$(jq -r '.library_name' vcenter_settings.json)
CONNECTION_STRING=$(echo $GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL)
govc about.cert -u $GOVC_URL -k -thumbprint | tee -a $GOVC_TLS_KNOWN_HOSTS
govc about -u $CONNECTION
govc session.login -u $CONNECTION
# why this fixes things, we don't know...
govc library.ls -u $CONNECTION

# if ~/.ssh/id_rsa does not exist, create it
if [ ! -f ~/.ssh/id_rsa ]; then
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ''
fi
# Read the public key from ~/.ssh/id_rsa.pub
PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)
# Escape special characters in the public key to use in sed
ESCAPED_PUBLIC_KEY=$(echo "$PUBLIC_KEY" | sed -e 's/[\/&]/\\&/g')
# Replace the existing key in coreos.bu with the new public key
sed -i "s/ssh-rsa [^ ]*/$ESCAPED_PUBLIC_KEY/g" coreos.bu

# gererate a random password
PORTAINER_PASSWORD=$(openssl rand -base64 32)
# Escape special characters in the password to use in sed
ESCAPED_PORTAINER_PASSWORD=$(echo "$PORTAINER_PASSWORD" | sed -e 's/[\/&]/\\&/g')
# Replace the existing password in portainer/deploy-portainer.sh with the new password
sed -i "s/PORTAINER_PASSWORD=\"[^\"]*/PORTAINER_PASSWORD=\"$ESCAPED_PORTAINER_PASSWORD/g" ./portainer/deploy-portainer.sh
PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2)
# replace all of the $ symbols in the bcrypt hash with two consecutive $$ symbols
ESCAPED_PORTAINER_BCRYPT=$(echo "$PORTAINER_BCRYPT" | sed -e 's/\$/\$\$/g')
sed -i "s/--admin-password '[^']*/--admin-password '$ESCAPED_PORTAINER_BCRYPT/g" ./coreos.bu

butane --files-dir ./ --pretty --strict coreos.bu --output coreos.ign

# use govc library.ls -json to check if the library exists
if govc library.ls -json | jq -r '.[].name' | grep -q $LIBRARY_NAME; then
  echo "Library name: $LIBRARY_NAME already exists"
else
  echo "Creating library $LIBRARY_NAME"
  govc library.create -ds=$GOVC_DATASTORE $LIBRARY
fi

# check if the OVA already exists in the library
if govc library.ls -json $LIBRARY_NAME/* | jq -r '.[].name' | grep -q $OVA_NAME; then
  echo "OVA $OVA_NAME already exists in library $LIBRARY_NAME"
else
  echo "Importing OVA $OVA_NAME into library $LIBRARY_NAME"
  govc library.import -n=$OVA_NAME $LIBRARY_NAME $OVA_URL
fi

govc library.deploy -host=$GOVC_HOST /$LIBRARY_NAME/$OVA_NAME $VM_NAME
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.change -vm $VM_NAME -m=32000 -c=8
govc vm.power -on $VM_NAME

echo "Waiting for VM to be ready..."
VM_IP=$(govc vm.ip $VM_NAME)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

pause "Press [Enter] key to continue..."
# delete the VM
govc vm.power -off $VM_NAME
govc vm.destroy $VM_NAME
