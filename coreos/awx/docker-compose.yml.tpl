version: '2.1'
services:
  # Primary AWX Development Container
  awx_1:
    user: "1000"
    image: "${AWX_GHCR_IMAGE}"
    container_name: awx
    hostname: awx_1
    command: launch_awx.sh
    environment:
      OS: " Operating System: Docker Desktop"
      SDB_HOST: 0.0.0.0
      SDB_PORT: 7899
      AWX_GROUP_QUEUES: tower
      MAIN_NODE_TYPE: hybrid
      RECEPTORCTL_SOCKET: /var/run/awx-receptor/receptor.sock
      CONTROL_PLANE_NODE_COUNT: 1
      EXECUTION_NODE_COUNT: 0
      AWX_LOGGING_MODE: stdout
      DJANGO_SUPERUSER_PASSWORD: ${DJANGO_SUPERUSER_PASSWORD}
      UWSGI_MOUNT_PATH: /
      RUN_MIGRATIONS: 1
    links:
      - postgres
      - redis
    networks:
      - awx
      - service-mesh
    working_dir: "/awx_devel"
    volumes:
      #- etc_tower:/etc/tower
      #- etc_nginx:/etc/nginx
      #- etc_receptor:/etc/receptor
      - "/opt/awx/etc/supervisord.conf:/etc/supervisord.conf"
      - /opt/awx_devel/awx:/awx_devel
      #- "../../../:/awx_devel"
      #- "../../docker-compose/supervisor.conf:/etc/supervisord.conf"
      - "/opt/awx/etc/tower/conf.d/database.py:/etc/tower/conf.d/database.py"
      - "/opt/awx/etc/tower/conf.d/websocket_secret.py:/etc/tower/conf.d/websocket_secret.py"
      - "/opt/awx/etc/tower/conf.d/local_settings.py:/etc/tower/conf.d/local_settings.py"
      - "/opt/awx/etc/nginx/nginx.conf:/etc/nginx/nginx.conf"
      - "/opt/awx/etc/nginx/conf.d/nginx.locations.conf:/etc/nginx/conf.d/nginx.locations.conf"
      - "/opt/awx/etc/tower/SECRET_KEY:/etc/tower/SECRET_KEY"
      - "/opt/awx/etc/receptor/receptor.conf:/etc/receptor/receptor.conf"
      - "/opt/awx/etc/receptor/receptor.conf.lock:/etc/receptor/receptor.conf.lock"
      #- "/opt/awx/etc/receptor/certs:/etc/receptor/certs"  # TODO: optionally generate certs
      - "/sys/fs/cgroup:/sys/fs/cgroup"
      #- "~/.kube/config:/var/lib/awx/.kube/config"
      - "redis_socket:/var/run/redis/:rw"
    privileged: true
    tty: true
    ports:
      - "7899-7999:7899-7999"  # sdb-listen
      - "6899:6899"
      #- "8080:8080"  # unused but mapped for debugging
      - "8888:8888"  # jupyter notebook
      - "8013:8013"  # http
      - "8043:8043"  # https
      - "2222:2222"  # receptor foo node
      - "3000:3001"  # used by the UI dev env
  redis:
    image: redis:latest
    container_name: redis
    volumes:
      #- usr_local_etc_redis:/usr/local/etc/redis
      - "/opt/awx/usr/local/etc/redis/redis.conf:/usr/local/etc/redis/redis.conf:Z"
      - "redis_socket:/var/run/redis/:rw"
    networks:
      - awx
    entrypoint: ["redis-server"]
    command: ["/usr/local/etc/redis/redis.conf"]
  # A useful container that simply passes through log messages to the console
  # helpful for testing awx/tower logging
  # logstash:
  #   build:
  #     context: ./docker-compose
  #     dockerfile: Dockerfile-logstash
  postgres:
    image: postgres:12
    container_name: postgres
    # additional logging settings for postgres can be found https://www.postgresql.org/docs/current/runtime-config-logging.html
    command: postgres -c log_destination=stderr -c log_min_messages=info -c log_min_duration_statement=1000 -c max_connections=1024
    environment:
      POSTGRES_HOST_AUTH_METHOD: trust
      POSTGRES_USER: awx
      POSTGRES_DB: awx
      POSTGRES_PASSWORD: ${AWX_POSTGRES_PASSWORD}
    volumes:
      - "postgresql:/var/lib/postgresql/data"
    networks:
      - awx
    ports:
       - "5441:5432"

volumes:
  postgresql:
  redis_socket:
networks:
  awx:
    name: awx
  service-mesh:
    name: service-mesh