butane --pretty --strict coreos.bu --output coreos.ign
.\kvpctl.exe coreos add-ign .\coreos.ign
.\kvpctl.exe coreos get

export GOVC_USERNAME='username'
export GOVC_PASSWORD='password'
export GOVC_URL='vcenter_url'
export GOVC_INSECURE=true
export OVA_URL='ova_url'
govc library.create -ds=esxi4_datastore library
govc library.import library https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240104.3.0/x86_64/fedora-coreos-39.20240104.3.0-vmware.x86_64.ova

sudo tar -zcf portainer_data.tar.gz /var/portainer

python3 -m http.server 80
