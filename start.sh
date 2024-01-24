#!/bin/sh
butane --pretty --strict coreos.bu --output coreos.ign
# login to vcenter using govc session.login and credentials from vcenter_settings.json
export CONNECTION=$(jq -r '.username + ":" + .password + "@" + .vcenter' vcenter_settings.json)
govc session.login -u $CONNECTION

#set $OVA_URL to get ova_url from vcenter_settings.json
export OVA_URL=$(jq -r '.ova_url' vcenter_settings.json)
export GOVC_USERNAME=$(jq -r '.username' vcenter_settings.json)
export GOVC_PASSWORD=$(jq -r '.password' vcenter_settings.json)
export GOVC_URL=$(jq -r '.vcenter' vcenter_settings.json)
export LIBRARY=$(jq -r '.library' vcenter_settings.json)
export DATASTORE=$(jq -r '.datastore' vcenter_settings.json)
export VM_NAME=$(jq -r '.vm_name' vcenter_settings.json)
export OVA_NAME=$(jq -r '.ova_name' vcenter_settings.json)
export HOST=$(jq -r '.host' vcenter_settings.json)
export GOVC_INSECURE=true
govc library.create -ds=$DATASTORE $LIBRARY
govc library.import $LIBRARY $OVA_URL
govc library.deploy -host=$HOST /$LIBRARY/$OVA_NAME $VM_NAME
#govc vm.create -m 4096 -c 2 -g coreos -net.adapter vmxnet3 -net="VM Network" -disk.controller pvscsi -disk.backing datastore1 -on=false coreos
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data=$(cat coreos.ign | base64 -w0)"
govc vm.change -vm $VM_NAME -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.power -on $VM_NAME


