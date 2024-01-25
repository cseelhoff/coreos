#!/bin/sh
if [ -z ${GOVC_PASSWORD+x} ]; then
  echo "Enter vCenter password:"
  read -s GOVC_PASSWORD
fi

export GOVC_INSECURE=true
export GOVC_USERNAME=$(jq -r '.username' vcenter_settings.json)
export GOVC_VCENTER=$(jq -r '.vcenter' vcenter_settings.json)
export CONNECTION=$(echo $GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_VCENTER)
export OVA_URL=$(jq -r '.ova_url' vcenter_settings.json)
export GOVC_URL=$(jq -r '.vcenter' vcenter_settings.json)
export LIBRARY=$(jq -r '.library' vcenter_settings.json)
export DATASTORE=$(jq -r '.datastore' vcenter_settings.json)
export VM_NAME=$(jq -r '.vm_name' vcenter_settings.json)
export OVA_NAME=$(jq -r '.ova_name' vcenter_settings.json)
export HOST=$(jq -r '.host' vcenter_settings.json)

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
# Replace the existing password in portainer/deploy-portainer.sh with the new password
sed -i "s/PORTAINER_PASSWORD=\"[^\"]*/PORTAINER_PASSWORD=\"$PORTAINER_PASSWORD/g" ./portainer/deploy-portainer.sh
PORTAINER_BCRYPT=$(htpasswd -nbB admin $PORTAINER_PASSWORD | cut -d ":" -f 2)
# replace all of the $ symbols in the bcrypt hash with two consecutive $$ symbols
ESCAPED_PORTAINER_BCRYPT=$(echo "$PORTAINER_BCRYPT" | sed -e 's/\$/\$\$/g')
sed -i "s/--admin-password '[^']*/--admin-password '$ESCAPED_PORTAINER_BCRYPT/g" ./coreos.bu

butane --files-dir ./ --pretty --strict coreos.bu --output coreos.ign
govc session.login -u $CONNECTION

# use govc library.ls -json to check if the library exists
if govc library.ls -json | jq -r '.[].name' | grep -q $LIBRARY; then
  echo "Library $LIBRARY already exists"
else
  echo "Creating library $LIBRARY"
  govc library.create -ds=$DATASTORE $LIBRARY
fi

# check if the OVA already exists in the library
if govc library.ls -json $LIBRARY/* | jq -r '.[].name' | grep -q $OVA_NAME; then
  echo "OVA $OVA_NAME already exists in library $LIBRARY"
else
  echo "Importing OVA $OVA_NAME into library $LIBRARY"
  govc library.import $LIBRARY $OVA_URL
fi

govc library.deploy -host=$HOST /$LIBRARY/$OVA_NAME $VM_NAME
#govc vm.create -m 4096 -c 2 -g coreos -net.adapter vmxnet3 -net="VM Network" -disk.controller pvscsi -disk.backing datastore1 -on=false coreos
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.power -on $VM_NAME

echo "Waiting for VM to be ready..."
VM_IP=$(govc vm.ip $VM_NAME)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# delete the VM
govc vm.power -off $VM_NAME
govc vm.destroy $VM_NAME
