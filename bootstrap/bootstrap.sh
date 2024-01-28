#!/bin/sh


NEXUS_ADMIN_PASSWORD=admin123
NEXUS_HOST=localhost
NEXUS_PORT=8081
NEXUS_URL=http://$NEXUS_HOST:$NEXUS_PORT
NEXUS_SERIVICE_REST_URL=$NEXUS_URL/service/rest/v1
NEXUS_CREDS=admin:$NEXUS_ADMIN_PASSWORD
DOCKER_REGISTRY_PORT=5000

# install nexus into docker container
docker run -d -p 8081:8081 --name nexus sonatype/nexus3

# change the default admin password
NEXUS_TEMP_PASSWORD=$(docker exec -it nexus cat /nexus-data/admin.password)
curl -v -u admin:$NEXUS_TEMP_PASSWORD -X PUT -d $NEXUS_ADMIN_PASSWORD -H "Content-Type: text/plain" $NEXUS_SERIVICE_REST_URL/security/users/admin/change-password

# use nexus api to add a docker-hosted registry
curl -v -u admin:$NEXUS_TEMP_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-hosted",
  "type": "groovy",
  "content": "repository.createDockerHosted('docker-hosted')"
}' -X POST $NEXUS_SERIVICE_REST_URL/script

# create a docker-proxy repository to pull from docker hub
curl -v -u admin:$NEXUS_TEMP_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-proxy",
  "type": "groovy",
  "content": "repository.createDockerProxy('docker-proxy', 'https://registry-1.docker.io')"
}' -X POST $NEXUS_SERIVICE_REST_URL/script

# create a docker-group repository to pull from docker-proxy and docker-hosted on port 5000 and allow anonymous access
curl -v -u admin:$NEXUS_TEMP_PASSWORD -H "Content-Type: application/json" -d '{
  "name": "docker-group",
  "type": "groovy",
  "content": "repository.createDockerGroup('docker-group', ['docker-hosted', 'docker-proxy'], '$DOCKER_REGISTRY_PORT', true)"
}' -X POST $NEXUS_SERIVICE_REST_URL/script
