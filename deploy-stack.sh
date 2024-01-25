#!/bin/bash

# Portainer details
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
PASSWORD=""

# Create JSON payload
read -r -d '' PAYLOAD <<EOF
{
  "Username": "$USERNAME",
  "Password": "$PASSWORD"
}
EOF

# Send request to Portainer API
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" $PORTAINER_URL/api/auth)

# Extract auth token from response
AUTH_TOKEN=$(echo $RESPONSE | jq -r .jwt)

echo $AUTH_TOKEN

# Portainer details
PORTAINER_URL="http://localhost:9000"


# Create JSON payload
read -r -d '' PAYLOAD <<EOF
{
  "name": "local"
}
EOF
URL="$PORTAINER_URL/api/endpoints"
LOCAL_ENDPOINTID=$(curl -s -X GET -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD" $URL  | jq '.[0].Id')

# Stack details
STACK_NAME="openldap"
DOCKER_COMPOSE_FILE="/opt/openldap/docker-compose.yml"
# Convert docker-compose file to base64
DOCKER_COMPOSE_JSON_STRING=$(cat /opt/openldap/docker-compose.yml | jq -Rs .)
# Create JSON payload
read -r -d '' PAYLOAD <<EOF
{
  "name": "$STACK_NAME",
  "stackFileContent": $DOCKER_COMPOSE_JSON_STRING
}
EOF
# Send request to Portainer API
URL="$PORTAINER_URL/api/stacks?type=2&method=string&endpointId=$LOCAL_ENDPOINTID"
curl -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD" $URL
