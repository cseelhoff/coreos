#!/bin/sh
# login to vcenter using govc session.login and credentials from vcenter_settings.json
export GOVC_INSECURE=true
export CONNECTION=$(jq -r '.username + ":" + .password + "@" + .vcenter' vcenter_settings.json)
export OVA_URL=$(jq -r '.ova_url' vcenter_settings.json)
export GOVC_USERNAME=$(jq -r '.username' vcenter_settings.json)
export GOVC_PASSWORD=$(jq -r '.password' vcenter_settings.json)
export GOVC_URL=$(jq -r '.vcenter' vcenter_settings.json)
export LIBRARY=$(jq -r '.library' vcenter_settings.json)
export DATASTORE=$(jq -r '.datastore' vcenter_settings.json)
export VM_NAME=$(jq -r '.vm_name' vcenter_settings.json)
export OVA_NAME=$(jq -r '.ova_name' vcenter_settings.json)
export HOST=$(jq -r '.host' vcenter_settings.json)

# create a new ssh key
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ''
# Read the public key from ~/.ssh/id_rsa.pub
PUBLIC_KEY=$(cat ~/.ssh/id_rsa.pub)
# Escape special characters in the public key to use in sed
ESCAPED_PUBLIC_KEY=$(echo "$PUBLIC_KEY" | sed -e 's/[\/&]/\\&/g')
# Replace the existing key in coreos.bu with the new public key
sed -i "s/ssh-rsa [^ ]*/$ESCAPED_PUBLIC_KEY/g" coreos.bu

butane --files-dir ./ --pretty --strict coreos.bu --output coreos.ign
govc session.login -u $CONNECTION

govc library.create -ds=$DATASTORE $LIBRARY
govc library.import $LIBRARY $OVA_URL

govc library.deploy -host=$HOST /$LIBRARY/$OVA_NAME $VM_NAME
#govc vm.create -m 4096 -c 2 -g coreos -net.adapter vmxnet3 -net="VM Network" -disk.controller pvscsi -disk.backing datastore1 -on=false coreos
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.power -on $VM_NAME

echo "Waiting for VM to be ready..."
VM_IP=$(govc vm.ip $VM_NAME)
#VM_IP="10.0.1.46"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# delete the VM
#govc vm.power -off $VM_NAME
#govc vm.destroy $VM_NAME

