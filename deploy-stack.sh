#!/bin/bash
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
PASSWORD=""

docker volume create openldap_database
docker volume create openldap_config
docker volume create openldap_certs

read -r -d '' PAYLOAD <<EOF
{
  "Username": "$USERNAME",
  "Password": "$PASSWORD"
}
EOF
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" $PORTAINER_URL/api/auth)
AUTH_TOKEN=$(echo $RESPONSE | jq -r .jwt)
read -r -d '' PAYLOAD <<EOF
{
  "name": "local"
}
EOF
URL="$PORTAINER_URL/api/endpoints"
LOCAL_ENDPOINTID=$(curl -s -X GET -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD" $URL  | jq '.[0].Id')
STACK_NAME="openldap"
DOCKER_COMPOSE_FILE="/opt/openldap/docker-compose.yml"
DOCKER_COMPOSE_JSON_STRING=$(cat /opt/openldap/docker-compose.yml | jq -Rs .)
read -r -d '' PAYLOAD <<EOF
{
  "name": "$STACK_NAME",
  "stackFileContent": $DOCKER_COMPOSE_JSON_STRING
}
EOF
URL="$PORTAINER_URL/api/stacks?type=2&method=string&endpointId=$LOCAL_ENDPOINTID"
curl -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD" $URL
