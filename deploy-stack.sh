#!/bin/bash

# Portainer details
PORTAINER_URL="http://localhost:9000"
USERNAME="admin"
PASSWORD="password"

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