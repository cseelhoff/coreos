# start a new docker container to build awx
$SH_command = "
sudo usermod -aG docker $USER
newgrp docker
sudo apt update
#consider python 3.9 to match the version in the container - also quay.io/centos/centos:stream9
DEBIAN_FRONTEND=noninteractive sudo apt install -y --no-install-recommends git build-essential python3.11 python3-pip python3.11-venv python-setuptools docker-compose docker-buildx gettext curl
curl -sL https://deb.nodesource.com/setup_20.x -o nodesource_setup.sh
sudo bash nodesource_setup.sh
sudo apt install -y nodejs
git clone -b 23.7.0 https://github.com/ansible/awx.git
cd awx
git checkout -b 23.7.0-ENV
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install ansible setuptools==69.0.3 setuptools-scm==8.0.4

sed -i '/exec \$@/i bash \/create_passwords.sh' entrypoint.sh
sed -i '/## File mappings/a ADD tools\/docker-compose\/create_passwords.sh \/create_passwords.sh\nADD .venv\/ \/awx_devel\/.venv\nADD _build\/ \/awx_devel\/_build\nADD awx\/ \/awx_devel\/awx\nADD awx_collection\/ \/awx_devel\/awx_collection\nADD awxkit\/ \/awx_devel\/awxkit\nADD config\/ \/awx_devel\/config\nADD docs\/ \/awx_devel\/docs\nADD licenses\/ \/awx_devel\/licenses\nADD requirements\/ \/awx_devel\/requirements\nADD tools\/ \/awx_devel\/tools\nADD tools\/docker-compose\/supervisor.conf \/etc\/supervisord.conf\nADD tools\/docker-compose\/_sources\/local_settings.py \/etc\/tower\/conf.d\/local_settings.py\nADD tools\/docker-compose\/_sources\/nginx.conf \/etc\/nginx\/nginx.conf\nADD tools\/docker-compose\/_sources\/nginx.locations.conf \/etc\/nginx\/conf.d\/nginx.locations.conf\nADD tools\/docker-compose\/_sources\/receptor\/receptor-awx-1.conf \/etc\/receptor\/receptor.conf' tools/ansible/roles/dockerfile/templates/Dockerfile.j2
make ui-next
make docker-compose-build
make awx/projects docker-compose-sources
ansible-galaxy install --ignore-certs -r tools/docker-compose/ansible/requirements.yml;
#modify docker-compose.yml
docker-compose -f tools/docker-compose/_sources/docker-compose.yml up
"
#run $SH_command in a new ubuntu:24.04 docker container with var/run/docker.sock mounted
docker run -it -v /etc/timezone:/etc/timezone -v /var/run/docker.sock:/var/run/docker.sock.0 ubuntu:24.04 /bin/bash
