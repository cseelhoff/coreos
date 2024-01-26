#!/bin/sh
if [ -z ${GOVC_PASSWORD+x} ]; then
  echo "Enter vCenter password:"
  read -s GOVC_PASSWORD
fi
echo "`date +"%Y-%m-%d %T"` -- deployment started!"
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
# add the vcenter certificate thumbprint to the known hosts file
export GOVC_TLS_KNOWN_HOSTS=~/.govc_known_hosts
govc about.cert -u $GOVC_URL -k -thumbprint | tee -a $GOVC_TLS_KNOWN_HOSTS
govc about -u $GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL
# init login
govc session.login -u $CONNECTION_STRING
# why this fixes things, we don't know...
govc library.ls -u   > /dev/null

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
sed -i "s/PORTAINER_PASSWORD=\"[^\"]*/PORTAINER_PASSWORD=\"$ESCAPED_PORTAINER_PASSWORD/g" ./portainer/deploy-stack.sh
PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2)
# replace all of the $ symbols in the bcrypt hash with two consecutive $$ symbols
ESCAPED_PORTAINER_BCRYPT=$(echo "$PORTAINER_BCRYPT" | sed -e 's/\$/\$\$/g')
ESCAPED_PORTAINER_BCRYPT=$(echo "$ESCAPED_PORTAINER_BCRYPT" | sed -e 's/[\/&]/\\&/g')
sed -i "s/--admin-password '[^']*/--admin-password '$ESCAPED_PORTAINER_BCRYPT/g" ./coreos.bu

butane --files-dir ./ --pretty --strict coreos.bu --output coreos.ign

# use govc library.ls -json to check if the library exists
if govc library.ls -u $CONNECTION_STRING -json | jq -r '.[].name' | grep -q $LIBRARY_NAME; then
  echo "Library name: $LIBRARY_NAME already exists"
else
  echo "Creating library $LIBRARY_NAME"
  govc library.create -u $CONNECTION_STRING -ds=$GOVC_DATASTORE $LIBRARY_NAME
fi

# check if the OVA already exists in the library
if govc library.ls -u $CONNECTION_STRING $LIBRARY_NAME/* | grep -q $OVA_NAME; then
  echo "OVA $OVA_NAME already exists in library $LIBRARY_NAME"
else
  echo "Importing OVA $OVA_NAME into library $LIBRARY_NAME"
  govc library.import -u $CONNECTION_STRING -n=$OVA_NAME $LIBRARY_NAME $OVA_URL
fi

govc library.deploy -u $CONNECTION_STRING -host=$GOVC_HOST /$LIBRARY_NAME/$OVA_NAME $GOVC_VM
govc vm.change -u $CONNECTION_STRING -vm $GOVC_VM -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
govc vm.change -u $CONNECTION_STRING -vm $GOVC_VM -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.change -u $CONNECTION_STRING -vm $GOVC_VM -m=32000 -c=8
govc vm.power -u $CONNECTION_STRING -on $GOVC_VM

echo "Waiting for VM to be ready..."
VM_IP=$(govc vm.ip -u $CONNECTION_STRING $GOVC_VM )
echo "YOUR PORTAINER PASSWORD IS: $PORTAINER_PASSWORD"
echo "$GOVC_VM's IP: $VM_IP"
echo "`date +"%Y-%m-%d %T"` -- deployment complete!"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# prompt user to press y to delete the VM
read -p "Press y to delete the VM: " -n 1 -r
if [[  $REPLY =~ ^[Yy]$ ]]
then
# delete the VM
  govc vm.power -u $CONNECTION_STRING -off $GOVC_VM
  govc vm.destroy -u $CONNECTION_STRING $GOVC_VM
fi
