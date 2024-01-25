#!/bin/bash
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
if [ -z ${PASSWORD+x} ]; then
  echo "Enter Portainer password:"
  read -s PASSWORD
fi

AUTH_PAYLOAD='{"Username": "'"$USERNAME"'",  "Password": "'"$PASSWORD"'"}'
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$AUTH_PAYLOAD" $PORTAINER_URL/api/auth)
AUTH_TOKEN=$(echo $RESPONSE | jq -r .jwt)
ENDPOINT_PAYLOAD='{"name": "local"}'
ENDPOINTS_URL="$PORTAINER_URL/api/endpoints"
LOCAL_ENDPOINTID=$(curl -s -X GET -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$ENDPOINT_PAYLOAD" $ENDPOINTS_URL | jq '.[0].Id')
if [ "$LOCAL_ENDPOINTID" == "null" ]; then
  LOCAL_ENDPOINTID=$(curl -s -X POST $ENDPOINTS_URL -H "Authorization: Bearer $AUTH_TOKEN" -F "Name=local" -F "EndpointCreationType=1" | jq '.Id')
fi

STACK_NAME="openldap"
DOCKER_COMPOSE_JSON_STRING=$(cat /opt/openldap/docker-compose.yml | jq -Rs .)
STACK_PAYLOAD='{ "name": "'"$STACK_NAME"'", "stackFileContent": '"$DOCKER_COMPOSE_JSON_STRING"' }'
STACKS_URL="$PORTAINER_URL/api/stacks?type=2&method=string&endpointId=$LOCAL_ENDPOINTID"
curl -s -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$STACK_PAYLOAD" $STACKS_URL
