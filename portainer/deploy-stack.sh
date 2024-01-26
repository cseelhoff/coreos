#!/bin/bash
# get command line parameter STACK_NAME and store it to variable STACK_NAME
STACK_NAME=$1
# get command line parameter DOCKER_COMPOSE_PATH and store it to variable DOCKER_COMPOSE_PATH
DOCKER_COMPOSE_PATH=$2
# exit script if STACK_NAME is not set
if [ -z ${STACK_NAME+x} ]; then
  echo "STACK_NAME is not set"
  exit 1
fi
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
PORTAINER_PASSWORD="5JDyEjT5k6ooWGDa9JL4gggz/m/2qNGrHwQ5yZHZT9A="
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
