#!/bin/bash

#wget https://raw.githubusercontent.com/cseelhoff/coreos/main/ubuntuServer_setup.sh
#chmod u+x ubuntuServer_setup.sh
#bash ubuntuServer_setup.sh

#this scripts is to be run on a ubuntu server before anything else has been start.sh

#if [ "$(id -u)" != "0" ]; then
#    echo "This script must be run as root."
#    exit 1
#fi

if dpkg -l | grep -q "openssh-server"; then
    echo "OpenSSH Server is installed."
else
    echo "OpenSSH Server is not installed."
    sudo apt install openssh-server
fi

#These are some extra stuff to disable resolved, they shouldn't be needed but are still here just in case.
#echo -e "[Resolve]\nDNS=1.1.1.1\nDNSStubListener=no\n" | sudo tee /etc/systemd/resolved.conf > /dev/null

#this removes the symlink between resolved and the normal resolv.conf
#sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

#installing the repo and required packages
sudo apt install -y apache2-utils whois jq curl git docker.io && \
curl -L -o - https://github.com/vmware/govmomi/releases/download/v0.34.2/govc_Linux_x86_64.tar.gz | sudo tar -C /usr/local/bin -xvzf - govc && \
sudo curl -L https://github.com/coreos/butane/releases/download/v0.19.0/butane-x86_64-unknown-linux-gnu --output /usr/local/bin/butane && sudo chmod +x /usr/local/bin/butane && \
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.2/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose && \
sudo chmod 755 /usr/local/bin/docker-compose
git clone https://github.com/cseelhoff/coreos && cd coreos


#stops the default the DNS service so that the PIhole doesn't run into issues later on
sudo systemctl disable systemd-resolved && sudo systemctl stop systemd-resolved