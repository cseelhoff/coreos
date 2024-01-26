docker container create --name awx -v etc_tower nothing

docker run -it -v /sys/fs/cgroup:/sys/fs/cgroup -v /opt/awx/supervisord.conf:/etc/supervisord.conf -v awx4_etc_tower:/etc/tower -v awx4_etc_nginx:/etc/nginx -v awx4_etc_receptor:/etc/receptor -v awx4_awx_devel:/awx_devel -v awx4_redis_socket:/var/run/redis ghcr.io/ansible /awx_devel:devel /bin/bash

#loop through each subdirectory found in /opt/awx copy it to the alpine container, using the same relative path
for dir in $(find /opt/awx -type d -printf '%P\n'); do
  # let parent equal the parent directory of the current directory
  parent=$(dirname $dir)
  docker cp /opt/awx/$dir alpine:/$parent
done

docker cp /opt/awx/etc_tower awx:/etc/tower/
docker cp /opt/awx/etc_nginx awx:/etc/nginx/
docker cp /opt/awx/etc_receptor awx:/etc/receptor/
docker cp /opt/awx/usr_local_etc_redis awx:/usr/local/etc/redis/
docker rm awx

cp /opt/awx/SECRET_KEY /var/lib/docker/volumes/awx_etc_tower/_data/
mkdir -p /var/lib/docker/volumes/awx_etc_tower/_data/conf.d/
cp /opt/awx/database.py /var/lib/docker/volumes/awx_etc_tower/_data/conf.d/
cp /opt/awx/websocket_secret.py /var/lib/docker/volumes/awx_etc_tower/_data/conf.d/
cp /opt/awx/local_settings.py /var/lib/docker/volumes/awx_etc_tower/_data/conf.d/
cp /opt/awx/nginx.conf /var/lib/docker/volumes/awx_etc_nginx/_data/
mkdir -p /var/lib/docker/volumes/awx_etc_nginx/_data/conf.d/
cp /opt/awx/nginx.locations.conf /var/lib/docker/volumes/awx_etc_nginx/_data/conf.d/
cp /opt/awx/receptor-awx-1.conf /var/lib/docker/volumes/awx_etc_receptor/_data/
cp /opt/awx/receptor-awx-1.conf.lock /var/lib/docker/volumes/awx_etc_receptor/_data/
cp /opt/awx/redis.conf /var/lib/docker/volumes/awx_usr_local_etc_redis/_data/

      - etc_tower:/etc/tower
      - etc_nginx:/etc/nginx
      - etc_receptor:/etc/receptor
      - /opt/awx/supervisord.conf:/etc/supervisord.conf
      - awx_devel:/awx_devel
      #- "../../../:/awx_devel"
      #- "../../docker-compose/supervisor.conf:/etc/supervisord.conf"
      #- "../../docker-compose/_sources/database.py:/etc/tower/conf.d/database.py"
      #- "../../docker-compose/_sources/websocket_secret.py:/etc/tower/conf.d/websocket_secret.py"
      #- "../../docker-compose/_sources/local_settings.py:/etc/tower/conf.d/local_settings.py"
      #- "../../docker-compose/_sources/nginx.conf:/etc/nginx/nginx.conf"
      #- "../../docker-compose/_sources/nginx.locations.conf:/etc/nginx/conf.d/nginx.locations.conf"
      #- "../../docker-compose/_sources/SECRET_KEY:/etc/tower/SECRET_KEY"
      #- "../../docker-compose/_sources/receptor/receptor-awx-1.conf:/etc/receptor/receptor.conf"
      #- "../../docker-compose/_sources/receptor/receptor-awx-1.conf.lock:/etc/receptor/receptor.conf.lock"
      # - "../../docker-compose/_sources/certs:/etc/receptor/certs"  # TODO: optionally generate certs
      - "/sys/fs/cgroup:/sys/fs/cgroup"
      #- "~/.kube/config:/var/lib/awx/.kube/config"
      - "redis_socket:/var/run/redis/:rw"