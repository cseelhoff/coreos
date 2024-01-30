### --- SECRETS --- ###
# Store and retrieve secrets from .env file
if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            Set-Content "env:\$($matches[1])" -Value $matches[2]
        }
    }
}

$keys = @("CF_DNS_API_TOKEN", "GOVC_PASSWORD", "COREOS_ADMIN_PASSWORD")
foreach ($key in $keys) {
    # Check if the key exists in the environment
    if ([string]::IsNullOrEmpty($env:$key)) {
        $value = Read-Host -Prompt "Enter a value for $key"
        Add-Content -Path .env -Value "$key=$value"
    }
}

# Reload the .env file
Get-Content .env | ForEach-Object {
    if ($_ -match '^(.*?)=(.*)$') {
        Set-Content "env:\$($matches[1])" -Value $matches[2]
    }
}

# making this a function so it can easily be collapsed in the editor
function Get-NetworkInfo {
    $HOST_IP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null })[0].IPv4Address
    $HOST_GATEWAY_IP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null })[0].IPv4DefaultGateway
    $HOST_SUBNET_MASK = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null })[0].IPv4Address.PrefixLength
    $CIDR = $HOST_SUBNET_MASK

    # Calculate the network address
    $HOST_IP_INT = [IPAddress]::Parse($HOST_IP).Address
    $HOST_GATEWAY_IP_INT = [IPAddress]::Parse($HOST_GATEWAY_IP).Address
    $NUM_IPS = [Math]::Pow(2, (32 - $CIDR))
    $CIDR_INT = [BitConverter]::ToUInt32([BitConverter]::GetBytes([UInt32]::MaxValue << (32 - $CIDR)), 0)
    $NETWORK_ADDRESS_INT = $HOST_IP_INT -band $CIDR_INT
    $NETWORK_ADDRESS_IP = ([IPAddress]$NETWORK_ADDRESS_INT).IPAddressToString
    $BROADCAST_INT = $NETWORK_ADDRESS_INT + $NUM_IPS - 1
    # let MIN_IP_ADDRESS be the smaller of the host IP and the gateway IP
    $MIN_IP_ADDRESS = [Math]::Min($HOST_IP_INT, $HOST_GATEWAY_IP_INT)
    $MAX_IP_ADDRESS = [Math]::Max($HOST_IP_INT, $HOST_GATEWAY_IP_INT)
    
    $RANGE1 = $MIN_IP_ADDRESS - $NETWORK_ADDRESS_INT
    $RANGE2 = $MAX_IP_ADDRESS - $MIN_IP_ADDRESS
    $RANGE3 = $BROADCAST_INT - $MAX_IP_ADDRESS
    # Find the greatest range
    if ($RANGE1 -gt $RANGE2 -and $RANGE1 -gt $RANGE3) {
        $STARTING_IP_INT = $NETWORK_ADDRESS_INT + 1
        $ENDING_IP_INT = $INT2 - 1
    } elseif ($RANGE2 -gt $RANGE1 -and $RANGE2 -gt $RANGE3) {
        $STARTING_IP_INT = $INT2 + 1
        $ENDING_IP_INT = $INT3 - 1
    } else {
        $STARTING_IP_INT = $INT3 + 1
        $ENDING_IP_INT = $BROADCAST_INT - 1
    }

    # convert the network address back to a dotted decimal
    $STARTING_IP = ([IPAddress]$STARTING_IP_INT).IPAddressToString
    $ENDING_IP = ([IPAddress]$ENDING_IP_INT).IPAddressToString
    # return the HOST_IP, HOST_GATEWAY_IP, STARTING_IP, and ENDING_IP
    return @{
        HOST_IP = $HOST_IP
        HOST_GATEWAY_IP = $HOST_GATEWAY_IP
        STARTING_IP = $STARTING_IP
        ENDING_IP = $ENDING_IP
    }
}

$networkInfo = Get-NetworkInfo
$HOST_IP = $networkInfo.HOST_IP
$HOST_GATEWAY_IP = $networkInfo.HOST_GATEWAY_IP
$STARTING_IP = $networkInfo.STARTING_IP
$ENDING_IP = $networkInfo.ENDING_IP
### --- VARIABLES --- ###
$ORGANIZATION_NAME='177th Cyber Protection Team'
$DOMAIN_NAME='177cpt.com'
$CLOUDFLARE_EMAIL='cseelhoff@gmail.com'
$TIMEZONE='America/Chicago'
$GOVC_URL='vsphere2.us.177cpt.com'
$GOVC_USERNAME='Administrator@VSPHERE.LOCAL'
$GOVC_HOST='10.0.1.31'
$GOVC_DATASTORE='esxi4_datastore'
$GOVC_VM='infravm'
$GOVC_NETWORK='Internal Management'
$GOVC_IP='10.0.1.41'
$DNS_SERVER_IP=$HOST_IP
$BOOTSTRAP_IP=$DNS_SERVER_IP
$DHCP_ROUTER_IP=$HOST_GATEWAY_IP
$DHCP_START_IP=$STARTING_IP
$DHCP_END_IP=$ENDING_IP

### --- OPTIONAL VARIABLES --- ###
$GOVC_INSECURE=$true
$GOVC_TLS_KNOWN_HOSTS='~/.govc_known_hosts'
$COREOS_OVA_URL='https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240104.3.0/x86_64/fedora-coreos-39.20240104.3.0-vmware.x86_64.ova'
$COREOS_OVA_NAME='fedora-coreos-39.20240104.3.0-vmware.x86_64'
$PIHOLE_DOCKER_IMAGE='pihole/pihole:2024.01.0'
$PORTAINER_DOCKER_IMAGE='portainer/portainer-ce:2.19.4'
$OPENLDAP_DOCKER_IMAGE='osixia/openldap:1.5.0'
$NEXUS_DOCKER_IMAGE='sonatype/nexus3:3.64.0'
$GITEA_DOCKER_IMAGE='gitea/gitea:1.21.4'
$TRAEFIK_DOCKER_IMAGE='traefik:v2.11'
$PHPLDAPADMIN_DOCKER_IMAGE='osixia/phpldapadmin:0.9.0'
$AWX_GHCR_IMAGE='ansible/awx_devel:devel'
$PIHOLE_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$TRAEFIK_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$NEXUS_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$LDAP_ADMIN_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$LDAP_CONFIG_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$PORTAINER_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$DJANGO_SUPERUSER_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$AWX_POSTGRES_PASSWORD='rzabMdUaDNuyQGmnYUQN'
$BROADCAST_WEBSOCKET_SECRET='QnJ1V0FzUG5Eb2pIRURCRnFKQ0Y='
$AWX_SECRET_KEY='JDqxKuQemHEajsZVZFQs'
$PIHOLE_SHORTNAME='pihole'
$NEXUS_SHORTNAME='nexus'
$TRAEFIK_SHORTNAME='traefik'
$DOCKER_SHORTNAME='docker'
$UPSTREAM_DNS_IPS="1.1.1.1;1.0.0.1"
$PORTAINER_PORT=9000
$PIHOLE_PORT=8001
$NEXUS_PORT=8081
$DOCKER_REGISTRY_PORT=8002
$VCENTER_LIBRARY_NAME='library'

### --- AUTO-GENERATED VARIABLES --- ###
$PIHOLE_FRONTEND_FQDN="$PIHOLE_SHORTNAME.$DOMAIN_NAME"
$NEXUS_FRONTEND_FQDN="$NEXUS_SHORTNAME.$DOMAIN_NAME"
$DOCKER_REGISTRY_FRONTEND_FQDN="$DOCKER_SHORTNAME.$DOMAIN_NAME"
$TRAEFIK_FQDN="$TRAEFIK_SHORTNAME.$DOMAIN_NAME"
$PIHOLE_BACKEND_FQDN="$PIHOLE_SHORTNAME-backend01.$DOMAIN_NAME"
$NEXUS_BACKEND_FQDN="$NEXUS_SHORTNAME-backend01.$DOMAIN_NAME"
$DOCKER_REGISTRY_BACKEND_FQDN="$DOCKER_SHORTNAME-backend01.$DOMAIN_NAME"
$TRAEFIK_IP=$BOOTSTRAP_IP
$PIHOLE_IP=$BOOTSTRAP_IP
$NEXUS_IP=$BOOTSTRAP_IP
$DOCKER_REGISTRY_IP=$BOOTSTRAP_IP
$PIHOLE_BACKEND_URL="http://$PIHOLE_BACKEND_FQDN:$PIHOLE_PORT"
$NEXUS_BACKEND_URL="http://$NEXUS_BACKEND_FQDN:$NEXUS_PORT"
$DOCKER_REGISTRY_BACKEND_URL="http://$DOCKER_REGISTRY_BACKEND_FQDN:$DOCKER_REGISTRY_PORT"
$PORTAINER_LOCALHOST_URL="http://localhost:$PORTAINER_PORT"
$PIHOLE_LOCALHOST_BASE_URL="http://localhost:$PIHOLE_PORT"
$PIHOLE_LOGIN_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/login.php"
$PIHOLE_INDEX_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/index.php"
$PIHOLE_SETTINGS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/settings.php?tab=dns"
$PIHOLE_CUSTOM_DNS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/scripts/pi-hole/php/customdns.php"
$NEXUS_SERIVICE_REST_URL="https://$NEXUS_FRONTEND_FQDN/service/rest/v1"
$GOVC_CONNECTION_STRING="$GOVC_USERNAME:$GOVC_PASSWORD@$GOVC_URL"
$TRAEFIK_AUTH = docker run --rm httpd:2.4-alpine htpasswd -nb admin $TRAEFIK_PASSWORD | %{ $_ -replace "\\$", "`$`$" }
$PORTAINER_BCRYPT = docker run --rm httpd:2.4-alpine htpasswd -nbB admin $PORTAINER_PASSWORD | %{ ($_ -split ":")[1] -replace "\\$", "`$`$" }
$COREOS_ADMIN_PASSWORD_HASH = docker run --rm debian:latest bash -c "apt-get update && apt-get install -y whois && mkpasswd --method=yescrypt $COREOS_ADMIN_PASSWORD"
Write-Host "Creating ssh keypair if it does not exist..."
if (!(Test-Path -Path "~/.ssh/id_rsa")) {
    ssh-keygen -t rsa -b 4096 -f "~/.ssh/id_rsa" -N '' > $null
}
$COREOS_SSH_PUBLIC_KEY = Get-Content "~/.ssh/id_rsa.pub"

Write-Host "Generating templates"

# Define a function to replace environment variables in a file
function Replace-EnvVars {
    param(
        [string]$InputFile,
        [string]$OutputFile
    )

    $content = Get-Content -Path $InputFile -Raw
    $envVars = [regex]::Matches($content, '\${\w+}') | foreach { $_.Value } | Sort-Object -Unique

    foreach ($var in $envVars) {
        $envVarName = $var.Trim('${', '}')
        $envVarValue = Get-Variable -Name "env:$envVarName" -ValueOnly
        $content = $content.Replace($var, $envVarValue)
    }

    Set-Content -Path $OutputFile -Value $content
}

# Use the function to process the template files
Replace-EnvVars -InputFile "bootstrap/traefik/docker-compose.yml.tpl" -OutputFile "bootstrap/traefik/docker-compose.yml"
Replace-EnvVars -InputFile "bootstrap/traefik/data/config.yml.tpl" -OutputFile "bootstrap/traefik/data/config.yml"
Replace-EnvVars -InputFile "bootstrap/traefik/data/traefik.yml.tpl" -OutputFile "bootstrap/traefik/data/traefik.yml"
Replace-EnvVars -InputFile "coreos/awx/docker-compose.yml.tpl" -OutputFile "bootstrap/traefik/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/database.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/database.py"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py"
Replace-EnvVars -InputFile "coreos/guacamole/docker-compose.yml.tpl" -OutputFile "coreos/guacamole/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/openldap/docker-compose.yml.tpl" -OutputFile "coreos/openldap/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/coreos.bu.tpl" -OutputFile "coreos/coreos.bu"
Set-Content -Path "coreos/awx/etc/tower/SECRET_KEY" -Value $AWX_SECRET_KEY
docker run --rm -v ${PWD}/coreos:/coreos quay.io/coreos/butane:release --files-dir /coreos --pretty --strict /coreos/coreos.bu --output /coreos/coreos.ign

function Remove-DockerContainer {
    param (
        [Parameter(Mandatory=$true)]
        [string]$containerName
    )

    Write-Host "Checking if the container named $containerName exists"
    if ((docker ps -a --format '{{.Names}}') -match $containerName) {
        Write-Host "Container '$containerName' exists. Checking if it is running"
        if ((docker ps --format '{{.Names}}') -match $containerName) {
            Write-Host "Container '$containerName' is running. Stopping container..."
            docker stop $containerName > $null
        } else {
            Write-Host "Container '$containerName' is not running"
        }
        Write-Host "Removing container '$containerName'..."
        docker rm $containerName > $null
    } else {
        Write-Host "Container '$containerName' does not exist"
    }
}

# Usage
Remove-DockerContainer -containerName "pihole"

Write-Host "Deploying Pi-hole for DNS and DHCP on bootstrap server. Password is $PIHOLE_PASSWORD"
docker run -d `
  --name=pihole `
  -h pihole `
  -e DNSMASQ_LISTENING=all `
  -e TZ=$TIMEZONE `
  -e PIHOLE_DNS_=$UPSTREAM_DNS_IPS `
  -e DHCP_ROUTER_IP=$DHCP_ROUTER_IP `
  -e DHCP_START_IP=$DHCP_START_IP `
  -e DHCP_END_IP=$DHCP_END_IP `
  -e PIHOLE_DOMAIN=$DOMAIN_NAME `
  -e VIRTUAL_HOST=pihole `
  -e WEBPASSWORD=$PIHOLE_PASSWORD `
  -e WEB_PORT=$PIHOLE_PORT `
  -v /etc/pihole/ `
  -v /etc/dnsmasq.d/ `
  --cap-add NET_ADMIN `
  --restart=unless-stopped `
  --network=host `
  $PIHOLE_DOCKER_IMAGE

# Define the custom DNS list
$CUSTOM_DNS_LIST = @"
$PIHOLE_IP $PIHOLE_BACKEND_FQDN
$NEXUS_IP $PIHOLE_BACKEND_FQDN
$NEXUS_IP $NEXUS_BACKEND_FQDN
$DOCKER_REGISTRY_IP $DOCKER_REGISTRY_BACKEND_FQDN
$TRAEFIK_IP $TRAEFIK_FQDN
$TRAEFIK_IP $PIHOLE_FRONTEND_FQDN
$TRAEFIK_IP $NEXUS_FRONTEND_FQDN
$TRAEFIK_IP $DOCKER_REGISTRY_FRONTEND_FQDN
$GOVC_IP $GOVC_URL
"@

# Append the custom DNS list to the pihole custom list file and restart the DNS service
docker exec -it pihole sh -c "echo -e `"$CUSTOM_DNS_LIST`" >> /etc/pihole/custom.list && pihole restartdns"
Write-Host "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig before changing local DNS settings"
dig +short $NEXUS_FRONTEND_FQDN
Write-Host "Setting default DNS servers on Pi-hole to cloudflare 1.1.1.1 and 1.0.0.1"
Invoke-WebRequest -Uri $PIHOLE_SETTINGS_URL -Method POST -Body "DNSserver1.1.1.1=true&DNSserver1.0.0.1=true&custom1val=&custom2val=&custom3val=&custom4val=&DNSinterface=all&rate_limit_count=1000&rate_limit_interval=60&field=DNS&token=$PIHOLE_TOKEN" -UseBasicParsing -SessionVariable cookies -OutFile $null
Write-Host "Setting DNS to use 127.0.0.1 (Pi-hole) and setting search domain to $DOMAIN_NAME"
Set-Content -Path /etc/resolv.conf -Value "nameserver 127.0.0.1`nsearch $DOMAIN_NAME"
Set-Content -Path /etc/systemd/resolved.conf -Value "[Resolve]`nDNS=127.0.0.1`nDNSStubListener=no`n"
Write-Host "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig after changing local DNS settings"
dig +short $NEXUS_FRONTEND_FQDN

Remove-DockerContainer -containerName "traefik"
Write-Host "Setting permissions to 600 on Traefik acme.json"
#icacls bootstrap/traefik/data/acme.json /grant:r "BUILTIN\Administrators:(F)" "NT AUTHORITY\SYSTEM:(F)" "BUILTIN\Users:(R)" "Everyone:(R)"
#icacls bootstrap/traefik/data/acme.json /inheritance:r
icacls bootstrap/traefik/data/acme.json /grant Everyone:R
Write-Host "Checking if proxy network for Traefik exists"
if (docker network inspect proxy > $null 2>&1) {
  Write-Host "Proxy network exists. Checking if any containers are using it"
  if ((docker network inspect proxy) -match '"Containers": {}') {
    Write-Host "No containers are using the proxy network. Removing the proxy network"
    docker network rm proxy > $null
  } else {
    Write-Host "Other containers are still using the proxy network. Exiting script as failed."
    exit 1
  }
}
Write-Host "Creating proxy network for Traefik"
docker network create proxy > $null
Write-Host "Starting Traefik with password: $TRAEFIK_PASSWORD"
docker-compose -f bootstrap/traefik/docker-compose.yml -p traefik up -d
Remove-DockerContainer -containerName "nexus"
Write-Host "Checking if the volume named nexus-data exists"
if (docker volume inspect nexus-data > $null 2>&1) {
  Write-Host "Volume 'nexus-data' exists. Removing volume..."
  docker volume rm nexus-data > $null
}
Write-Host "Creating volume 'nexus-data'"
docker volume create --name nexus-data
if (Test-Path backup/nexus-backup.tar.gz) {
    Write-Host "Restoring Nexus from backup"
    docker run --rm -v nexus-data:/nexus-data -v $(Get-Location)/backup:/backup alpine tar -xzf /backup/nexus-backup.tar.gz -C /nexus-data
} else {
    Write-Host "No backup found, creating new Nexus"
    Write-Host "Starting Nexus"
    docker run -d -p $env:NEXUS_PORT:$env:NEXUS_PORT -p $env:DOCKER_REGISTRY_PORT:$env:DOCKER_REGISTRY_PORT --name nexus -v nexus-data:/nexus-data $env:NEXUS_DOCKER_IMAGE
    Write-Host "Waiting for Nexus to start on: $env:NEXUS_SERIVICE_REST_URL/security/users"
    do {
        Write-Host -NoNewline '.'
        Start-Sleep -Seconds 1
        if ([string]::IsNullOrEmpty($env:NEXUS_TEMP_PASSWORD)) {
            $env:NEXUS_TEMP_PASSWORD = docker exec nexus cat /nexus-data/admin.password 2>$null
            if (-not [string]::IsNullOrEmpty($env:NEXUS_TEMP_PASSWORD)) {
                Write-Host
                Write-Host "Nexus temp password is: $env:NEXUS_TEMP_PASSWORD"
                Write-Host "Continuing to wait for Nexus to start"
            }
        }
    } until ((Invoke-WebRequest -Uri $env:NEXUS_SERIVICE_REST_URL/security/users -Method Head -Credential (New-Object System.Management.Automation.PSCredential ('admin', (ConvertTo-SecureString -String $env:NEXUS_TEMP_PASSWORD -AsPlainText -Force))) -ErrorAction SilentlyContinue).StatusCode -eq 200)
    Write-Host
    Write-Host "Changing Nexus password from: $env:NEXUS_TEMP_PASSWORD to: $env:NEXUS_PASSWORD"
    Invoke-WebRequest -Uri $env:NEXUS_SERIVICE_REST_URL/security/users/admin/change-password -Method Put -Body $env:NEXUS_PASSWORD -ContentType "text/plain" -Credential (New-Object System.Management.Automation.PSCredential ('admin', (ConvertTo-SecureString -String $env:NEXUS_TEMP_PASSWORD -AsPlainText -Force)))
    $nexus_creds = New-Object System.Management.Automation.PSCredential('admin', (ConvertTo-SecureString -String $env:NEXUS_PASSWORD -AsPlainText -Force))
    Write-Host "Setting active realms to LdapRealm, DockerToken, and NexusAuthenticatingRealm"
    Invoke-RestMethod -Uri "$env:NEXUS_SERIVICE_REST_URL/security/realms/active" -Method Put -Body '[
            "LdapRealm",
            "DockerToken",
            "NexusAuthenticatingRealm"
    ]' -ContentType "application/json" -Credential $nexus_creds

    Write-Host "Creating docker-hosted repository"
    Invoke-RestMethod -Uri "$env:NEXUS_SERIVICE_REST_URL/repositories/docker/hosted" -Method Post -Body '{
        "name": "docker-hosted",
        "online": true,
        "storage": {
            "blobStoreName": "default",
            "strictContentTypeValidation": true,
            "writePolicy": "ALLOW"
        },
        "docker": {
            "v1Enabled": false,
            "forceBasicAuth": false
        }
    }' -ContentType "application/json" -Credential $nexus_creds

    Write-Host "Creating docker-proxy repository"
    Invoke-RestMethod -Uri "$env:NEXUS_SERIVICE_REST_URL/repositories/docker/proxy" -Method Post -Body '{
        "name": "docker-proxy",
        "online": true,
        "storage": {
            "blobStoreName": "default",
            "strictContentTypeValidation": true
        },
        "proxy": {
            "remoteUrl": "https://registry-1.docker.io",
            "contentMaxAge": 1440,
            "metadataMaxAge": 1440
        },
        "negativeCache": {
            "enabled": true,
            "timeToLive": 1440
        },
        "httpClient": {
            "blocked": false,
            "autoBlock": false
        },
        "docker": {
            "v1Enabled": false,
            "forceBasicAuth": false
        },
        "dockerProxy": {
            "indexType": "HUB"
        }
    }' -ContentType "application/json" -Credential $nexus_creds
    Write-Host "Creating ghcr-proxy repository"
    Invoke-RestMethod -Uri "$env:NEXUS_SERIVICE_REST_URL/repositories/docker/proxy" -Method Post -Body '{
            "name": "ghcr-proxy",
            "online": true,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": true
            },
            "proxy": {
                "remoteUrl": "https://ghcr.io",
                "contentMaxAge": 1440,
                "metadataMaxAge": 1440
            },
            "negativeCache": {
                "enabled": true,
                "timeToLive": 1440
            },
            "httpClient": {
                "blocked": false,
                "autoBlock": false
            },
            "docker": {
                "v1Enabled": false,
                "forceBasicAuth": false
            },
            "dockerProxy": {
                "indexType": "REGISTRY"
            }
    }' -ContentType "application/json" -Credential $nexus_creds
    Write-Host "Creating docker-group repository for docker-hosted, docker-proxy, and ghcr-proxy"
    # Define the body of the request as a hashtable
    $jsonBody = @{
        "name"   = "docker-group"
        "online" = $true
        "storage" = @{
            "blobStoreName" = "default"
            "strictContentTypeValidation" = $true
        }
        "group" = @{
            "memberNames" = @("docker-hosted", "docker-proxy", "ghcr-proxy")
        }
        "docker" = @{
            "v1Enabled" = $false
            "forceBasicAuth" = $false
            "httpPort" = $env:DOCKER_REGISTRY_PORT
        }
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "$env:NEXUS_SERIVICE_REST_URL/repositories/docker/group" -Method Post -Body $jsonBody -ContentType "application/json" -Credential $nexus_creds
    Write-Host "Removing local docker images cache"
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:NEXUS_DOCKER_IMAGE
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:PORTAINER_DOCKER_IMAGE
    #docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:OPENLDAP_DOCKER_IMAGE
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:TRAEFIK_DOCKER_IMAGE
    #docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:AWX_GHCR_IMAGE

    Write-Host "Caching docker images in Nexus"
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:NEXUS_DOCKER_IMAGE
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:PORTAINER_DOCKER_IMAGE
    #docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:OPENLDAP_DOCKER_IMAGE
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:TRAEFIK_DOCKER_IMAGE
    #docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:AWX_GHCR_IMAGE

    Write-Host "Stopping Nexus to create backup"
    docker stop --time=120 nexus

    Write-Host "Creating Nexus backup"
    if (!(Test-Path -Path backup)) {
        New-Item -ItemType Directory -Path backup
    }
    docker run --rm -v nexus-data:/nexus-data -v $(Get-Location)/backup:/backup alpine sh -c "tar -C /nexus-data -czf /backup/nexus-backup.tar.gz ."

    Write-Host "Starting Nexus"
    docker start nexus
}
Write-Host "Waiting for Nexus to start on: $env:NEXUS_SERIVICE_REST_URL/security/users"
do {
    Write-Host -NoNewline '.'
    Start-Sleep -Seconds 1
} until ((Invoke-WebRequest -Uri $env:NEXUS_SERIVICE_REST_URL/security/users -Method Head -Credential (New-Object System.Management.Automation.PSCredential ('admin', (ConvertTo-SecureString -String $env:NEXUS_PASSWORD -AsPlainText -Force))) -ErrorAction SilentlyContinue).StatusCode -eq 200)
Write-Host
Write-Host 'Bootstrap complete!'

Write-Host "Logging into vCenter"
govc about.cert -u $env:GOVC_URL -k -thumbprint | Out-File -Append $env:GOVC_TLS_KNOWN_HOSTS
govc about -u $env:GOVC_USERNAME:$env:GOVC_PASSWORD@$env:GOVC_URL
govc session.login -u $env:GOVC_CONNECTION_STRING
# why this fixes things, we don't know...
govc library.ls -u $env:GOVC_CONNECTION_STRING > $null

Write-Host "Creating library and importing OVA"
if ((govc library.ls -u $env:GOVC_CONNECTION_STRING -json | ConvertFrom-Json).name -contains $env:VCENTER_LIBRARY_NAME) {
    Write-Host "Library name: $env:VCENTER_LIBRARY_NAME already exists"
} else {
    Write-Host "Creating library $env:VCENTER_LIBRARY_NAME"
    govc library.create -u $env:GOVC_CONNECTION_STRING -ds=$env:GOVC_DATASTORE $env:VCENTER_LIBRARY_NAME
}

Write-Host "Checking if OVA already exists in library"
if ((govc library.ls -u $env:GOVC_CONNECTION_STRING $env:VCENTER_LIBRARY_NAME/*) -match $env:COREOS_OVA_NAME) {
    Write-Host "OVA $env:COREOS_OVA_NAME already exists in library $env:VCENTER_LIBRARY_NAME"
} else {
    Write-Host "Importing OVA $env:COREOS_OVA_NAME into library $env:VCENTER_LIBRARY_NAME"
    govc library.import -u $env:GOVC_CONNECTION_STRING -n=$env:COREOS_OVA_NAME $env:VCENTER_LIBRARY_NAME $env:COREOS_OVA_URL
}

Write-Host "Deploying VM from OVA"
govc library.deploy -u $env:GOVC_CONNECTION_STRING -host=$env:GOVC_HOST /$env:VCENTER_LIBRARY_NAME/$env:COREOS_OVA_NAME $env:GOVC_VM
$ignitionConfigData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content -Path coreos/coreos.ign -Raw)))
govc vm.change -u $env:GOVC_CONNECTION_STRING -vm $env:GOVC_VM -e="guestinfo.ignition.config.data=$ignitionConfigData"
govc vm.change -u $env:GOVC_CONNECTION_STRING -vm $env:GOVC_VM -e="guestinfo.ignition.config.data.encoding=base64"
govc vm.change -u $env:GOVC_CONNECTION_STRING -vm $env:GOVC_VM -m=32000 -c=8
govc vm.power -u $env:GOVC_CONNECTION_STRING -on $env:GOVC_VM

Write-Host "Waiting for VM to be ready..."
$VM_IP = govc vm.ip -u $env:GOVC_CONNECTION_STRING $env:GOVC_VM
Write-Host "YOUR PORTAINER PASSWORD IS: $env:PORTAINER_PASSWORD"
Write-Host "$env:GOVC_VM's IP: $VM_IP"
Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") -- deployment complete!"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# prompt user to press y to delete the VM
$REPLY = Read-Host "Press y to delete the VM: "
if ($REPLY -eq 'y' -or $REPLY -eq 'Y') {
    # delete the VM
    govc vm.power -u $env:GOVC_CONNECTION_STRING -off $env:GOVC_VM
    govc vm.destroy -u $env:GOVC_CONNECTION_STRING $env:GOVC_VM
}