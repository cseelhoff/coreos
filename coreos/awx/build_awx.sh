# start a new docker container to build awx
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
tar cf git.tar .git

# create tools/docker-compose/create_passwords.sh
cat << END_OF_CREATE_PASSWORDS > tools/docker-compose/create_passwords.sh
#!/bin/bash
cat << EOF > "/etc/tower/conf.d/database.py"
DATABASES = {
    "default": {
        "ATOMIC_REQUESTS": True,
        "ENGINE": "awx.main.db.profiled_pg",
        "NAME": "awx",
        "USER": "awx",
        "PASSWORD": \\"\${TOWER_DATABASE_PASSWORD}\\",
        "HOST": "postgres",
        "PORT": "5432",
    }
}
EOF
echo "BROADCAST_WEBSOCKET_SECRET = \\"\${BROADCAST_WEBSOCKET_SECRET}\\"\" > "/etc/tower/conf.d/websocket_secret.py"
echo "SECRET_KEY = \\"\${TOWER_SECRET_KEY}\\"\" > "/etc/tower/SECRET_KEY"
END_OF_CREATE_PASSWORDS

# modify awx_devel/tools/docker-compose/entrypoint.sh to run create_passwords.sh
sed -i '/exec \$@/i bash \/awx_devel\/tools\/docker-compose\/create_passwords.sh' tools/docker-compose/entrypoint.sh

# Define the string to be added to Dockerfile.j2
add_string=$(cat <<EOF
ADD ./ /awx_devel/
RUN tar xf /awx_devel/git.tar -C /awx_devel/.git
RUN chmod 666 /awx_devel/supervisord.log
RUN mkdir -p /etc/tower/conf.d
RUN touch /etc/tower/conf.d/database.py /etc/tower/conf.d/websocket_secret.py /etc/tower/SECRET_KEY
RUN chmod 662 /etc/tower/conf.d/database.py /etc/tower/conf.d/websocket_secret.py /etc/tower/SECRET_KEY
ADD tools/docker-compose/supervisor.conf /etc/supervisord.conf
ADD tools/docker-compose/_sources/local_settings.py /etc/tower/conf.d/local_settings.py
ADD tools/docker-compose/_sources/nginx.conf /etc/nginx/nginx.conf
ADD tools/docker-compose/_sources/nginx.locations.conf /etc/nginx/conf.d/nginx.locations.conf
ADD tools/docker-compose/_sources/receptor/receptor-awx-1.conf /etc/receptor/receptor.conf
EOF
)
# Escape slashes and newlines for sed
escaped_add_string=$(echo "$add_string" | sed -e 's/[\/&]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')
# Use the escaped string in the sed command
sed -i "/## File mappings/a $escaped_add_string" tools/ansible/roles/dockerfile/templates/Dockerfile.j2

# Escape slashes, newlines and spaces for sed
escaped_match_string=$(echo "$match_string" | sed -e 's/[\/&]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' -e 's/ /\\ /g')

# Define the string to be added to docker-compose.yml.j2
add_string=$(cat <<EOF
      TOWER_DATABASE_PASSWORD: password
      BROADCAST_WEBSOCKET_SECRET: password
      TOWER_SECRET_KEY: password
EOF
)
# Escape slashes, newlines and spaces for sed
escaped_add_string=$(echo "$add_string" | sed -e 's/[\/&]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' -e 's/ /\\ /g')
# after the escaped_match_string, add the escaped_add_string in the file tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i "/UWSGI_MOUNT_PATH/a $escaped_add_string" tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2

# Remove the following lines from docker-compose.yml.j2
sed -i '/- "..\/..\/..\/:\/awx_devel"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/supervisor.conf:\/etc\/supervisord.conf"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/database.py:\/etc\/tower\/conf.d\/database.py"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/websocket_secret.py:\/etc\/tower\/conf.d\/websocket_secret.py"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/local_settings.py:\/etc\/tower\/conf.d\/local_settings.py"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/nginx.conf:\/etc\/nginx\/nginx.conf"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/nginx.locations.conf:\/etc\/nginx\/conf.d\/nginx.locations.conf"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/SECRET_KEY:\/etc\/tower\/SECRET_KEY"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/receptor\/receptor-awx-{{ loop.index }}.conf:\/etc\/receptor\/receptor.conf"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2
sed -i '/- "..\/..\/docker-compose\/_sources\/receptor\/receptor.conf:\/etc\/receptor\/receptor.conf"/d' tools/docker-compose/ansible/roles/sources/templates/docker-compose.yml.j2

make ui-devel ui-next
make awx/projects docker-compose-sources
make docker-compose-build
#docker-compose -f tools/docker-compose/_sources/docker-compose.yml up

docker tag ghcr.io/ansible/awx_devel:23.7.0-ENV docker.177cpt.com/ansible/awx_devel:23.7.0-ENV
docker login docker.177cpt.com
docker push docker.177cpt.com/ansible/awx_devel:23.7.0-ENV

# awx-manage changepassword admin

# http://127.0.0.1:8013/ui_next
# http://127.0.0.1:8013/ui_next/dashboard
# http://127.0.0.1:8013/overview

#docker run -it -v /etc/timezone:/etc/timezone -v /var/run/docker.sock:/var/run/docker.sock.0 ubuntu:24.04 /bin/bash
#run $SH_command in a new ubuntu:24.04 docker container with var/run/docker.sock mounted

#ADD ./ /awx_devel/
#RUN tar xf /awx_devel/git.tar -C /awx_devel
#RUN mkdir -p /etc/tower/conf.d

# ## File mappings
# ADD ./ /awx_devel/
# RUN tar xf /awx_devel/git.tar -C /awx_devel
# RUN mkdir -p /etc/tower/conf.d
# RUN touch /etc/tower/conf.d/database.py /etc/tower/conf.d/websocket_secret.py /etc/tower/SECRET_KEY
# RUN chmod 662 /etc/tower/conf.d/database.py /etc/tower/conf.d/websocket_secret.py /etc/tower/SECRET_KEY
# ADD tools/docker-compose/supervisor.conf /etc/supervisord.conf
# ADD tools/docker-compose/_sources/local_settings.py /etc/tower/conf.d/local_settings.py
# ADD tools/docker-compose/_sources/nginx.conf /etc/nginx/nginx.conf
# ADD tools/docker-compose/_sources/nginx.locations.conf /etc/nginx/conf.d/nginx.locations.conf
# ADD tools/docker-compose/_sources/receptor/receptor-awx-1.conf /etc/receptor/receptor.conf
# RUN chmod 666 /awx_devel/supervisord.log /etc/supervisord.conf /etc/tower/conf.d/local_settings.py /etc/nginx/nginx.conf /etc/nginx/conf.d/nginx.locations.conf /etc/receptor/receptor.conf
