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

ulimit -n 65536 

docker exec tools_awx_1 make clean-ui ui-devel
docker exec tools_awx_1 make clean-ui clean/ui-next ui-devel ui-next

docker exec -ti tools_awx_1 awx-manage createsuperuser

docker run --name=pihole -h pihole -p 53:53/tcp -p 53:53/udp -p 67:67/udp -p 80:80/tcp -e PIHOLE_DNS_=10.0.1.1 -e TZ='America/Chicago' -e DNSMASQ_LISTENING=all -e DHCP_START=10.0.1.10 -e DHCP_END=10.0.1.50 -e DHCP_ROUTER=10.0.1.2 -e PIHOLE_DOMAIN=us.177cpt.com -e VIRTUAL_HOST=pihole -e WEBPASSWORD=53nnp3rWIFI -v ./pihole:/etc/pihole -v ./dnsmasq.d:/etc/dnsmasq.d --cap-add NET_ADMIN --restart=unless-stopped pihole/pihole:2024.01.0

https://go-acme.github.io/lego/dns/cloudflare/#api-tokens
create an API token with the following permissions:
Zone / Zone / Read
Zone / DNS / Edit
#more notes