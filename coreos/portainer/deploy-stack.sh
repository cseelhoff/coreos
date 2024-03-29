#!/bin/bash
STACK_NAME=$1
DOCKER_COMPOSE_PATH=$2
PORTAINER_URL=$3 #http://localhost:9000
PORTAINER_PASSWORD=$4
# print help message if command line is not correct
if [ -z "$STACK_NAME" ] || [ -z "$DOCKER_COMPOSE_PATH" ] || [ -z "$PORTAINER_URL" ] || [ -z "$PORTAINER_PASSWORD" ]; then
  echo "Usage: deploy-stack.sh STACK_NAME DOCKER_COMPOSE_PATH PORTAINER_URL PORTAINER_PASSWORD"
  exit 1
fi

# authenticate with portainer and get jwt token
USERNAME="admin"
AUTH_PAYLOAD='{"Username": "'"$USERNAME"'",  "Password": "'"$PORTAINER_PASSWORD"'"}'
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$AUTH_PAYLOAD" $PORTAINER_URL/api/auth)
AUTH_TOKEN=$(echo $RESPONSE | jq -r .jwt)
ENDPOINT_PAYLOAD='{"name": "local"}'
ENDPOINTS_URL="$PORTAINER_URL/api/endpoints"
LOCAL_ENDPOINTID=$(curl -s -X GET -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$ENDPOINT_PAYLOAD" $ENDPOINTS_URL | jq '.[0].Id')
if [ "$LOCAL_ENDPOINTID" == "null" ]; then
  LOCAL_ENDPOINTID=$(curl -s -X POST $ENDPOINTS_URL -H "Authorization: Bearer $AUTH_TOKEN" -F "Name=local" -F "EndpointCreationType=1" | jq '.Id')
fi
DOCKER_COMPOSE_JSON_STRING=$(cat $DOCKER_COMPOSE_PATH | jq -Rs .)
STACK_PAYLOAD='{ "name": "'"$STACK_NAME"'", "stackFileContent": '"$DOCKER_COMPOSE_JSON_STRING"' }'
STACKS_URL="$PORTAINER_URL/api/stacks?type=2&method=string&endpointId=$LOCAL_ENDPOINTID"
curl -s -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$STACK_PAYLOAD" $STACKS_URL
