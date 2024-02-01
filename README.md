For the linux machines:
If it exists, .env should be in \ dirctory. The start.sh will create it in the proper folder if does not exist. 

acme.json should be in the ~/coreos/backup. Start.sh will create it there is if does not exist. #We need to add a check to see if it is in the /coreos and move it if it is

.env key:

export TIMEZONE=America/Chicago
export ORGANIZATION_NAME='177th Cyber Protection Team'
export DOMAIN_NAME='177cpt.com'
export CLOUDFLARE_EMAIL=cseelhoff@gmail.com
export GOVC_URL="vsphere2.us.177cpt.com" #this is the URL for the image address 
export GOVC_USERNAME="Administrator@VSPHERE.LOCAL" #login for the vsphere
export GOVC_HOST="10.0.1.31" #this is the IP address of the ESXI host that the infraVM is on 
export GOVC_DATASTORE="esxi4_datastore" #datastore that VM is stored on
export GOVC_VM="infravm" #infravm's name
export GOVC_NETWORK="Internal Management" #network that VM put on
GOVC_IP="10.0.1.41" # this is the vcenter ip address

#extra Seelhoff notes:
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