#!/bin/bash
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
PORTAINER_PASSWORD="5wmjVNT8uRc+0dW1cguMd14SLYLnHGUV3JIjiIOkKXU="
AUTH_PAYLOAD='{"Username": "'"$USERNAME"'",  "Password": "'"$PORTAINER_PASSWORD"'"}'
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$AUTH_PAYLOAD" $PORTAINER_URL/api/auth)
AUTH_TOKEN=$(echo $RESPONSE | jq -r .jwt)
ENDPOINT_PAYLOAD='{"name": "local"}'
ENDPOINTS_URL="$PORTAINER_URL/api/endpoints"
LOCAL_ENDPOINTID=$(curl -s -X GET -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" -d "$ENDPOINT_PAYLOAD" $ENDPOINTS_URL | jq '.[0].Id')
if [ "$LOCAL_ENDPOINTID" == "null" ]; then
  LOCAL_ENDPOINTID=$(curl -s -X POST $ENDPOINTS_URL -H "Authorization: Bearer $AUTH_TOKEN" -F "Name=local" -F "EndpointCreationType=1" | jq '.Id')
fi
