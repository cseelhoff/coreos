### --- SECRETS --- ###
# Store and retrieve secrets from .env file
if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match '^export (.*?)=(.*)$') {
            Write-Host "Found export variable in .env file with name $($matches[1]) and value $($matches[2])"
            Set-Content "env:\$($matches[1])" -Value $matches[2]
        }
    }
}

$keys = @("CF_DNS_API_TOKEN", "GOVC_PASSWORD", "COREOS_ADMIN_PASSWORD")
foreach ($key in $keys) {
    # Check if the key exists in the environment
    $value = Get-Content "env:$key"
    if ([string]::IsNullOrEmpty($value)) {
        $value = Read-Host -Prompt "Enter a value for $key"
        Add-Content -Path .env -Value "export $key=$value"
    }
}

# Reload the .env file
Get-Content .env | ForEach-Object {
    if ($_ -match ('^export (.*?)=' + "'" + '(.*)' + "'$")) {
        Write-Host "Found export variable in .env file with name $($matches[1]) and value $($matches[2])"
        Set-Content "env:\$($matches[1])" -Value $matches[2]
    } elseif ($_ -match '^export (.*?)=(.*)$') {
        Write-Host "Found export variable in .env file with name $($matches[1]) and value $($matches[2])"
        Set-Content "env:\$($matches[1])" -Value $matches[2]
    }
}
function Convert-IPToInteger {
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$ip
    )

    process {
        $octets = $ip.Split('.')
        return ([int]$octets[0] * [Math]::Pow(2, 24)) + ([int]$octets[1] * [Math]::Pow(2, 16)) + ([int]$octets[2] * [Math]::Pow(2, 8)) + [int]$octets[3]
    }
}

function Convert-IntToIP {
    param (
        [Parameter(ValueFromPipeline=$true)]
        [int]$networkAddressInt
    )
    process {
        return "{0}.{1}.{2}.{3}" -f (($networkAddressInt -shr 24) % 256), (($networkAddressInt -shr 16) % 256), (($networkAddressInt -shr 8) % 256), ($networkAddressInt % 256)
    }
}

# making this a function so it can easily be collapsed in the editor
function Get-NetworkInfo {
    # get host ip of the first network adapter that has a default gateway
    $HOST_IP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }) | Select-Object -First 1 -ExpandProperty IPv4Address | Select-Object -ExpandProperty IPAddress
    $HOST_GATEWAY_IP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }) | Select-Object -First 1 -ExpandProperty IPv4DefaultGateway | Select-Object -ExpandProperty NextHop
    $CIDR = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }) | Select-Object -First 1 -ExpandProperty IPv4Address | Select-Object -First 1 -ExpandProperty PrefixLength

    # Calculate the network address
    $HOST_GATEWAY_IP_INT = $HOST_GATEWAY_IP | Convert-IPToInteger
    # Convert the IP to an integer
    $ipInt = $HOST_IP | Convert-IPToInteger
    $numIps = [Math]::Pow(2, (32 - $cidr))
    # Calculate the binary mask for the CIDR as an integer
    $cidrInt = (([Math]::Pow(2, 32) -1) -shl (32 - $CIDR)) % [Math]::Pow(2, 32)

    $networkAddressInt = $cidrInt -band $ipInt
    $networkAddressIp = $networkAddressInt | Convert-IntToIP
    $broadcastInt = $networkAddressInt + $numIps - 1
    # Calculate the network address

    # Convert the network address and broadcast address back to IPs
    $networkAddressIp = ([IPAddress]$networkAddressInt).IPAddressToString
    $broadcastAddressIp = ([IPAddress]$broadcastAddressInt).IPAddressToString

    # let MIN_IP_ADDRESS be the smaller of the host IP and the gateway IP
    $MIN_IP_ADDRESS = [Math]::Min($ipInt, $HOST_GATEWAY_IP_INT)
    $MAX_IP_ADDRESS = [Math]::Max($ipInt, $HOST_GATEWAY_IP_INT)
    
    $RANGE1 = $MIN_IP_ADDRESS - $networkAddressInt
    $RANGE2 = $MAX_IP_ADDRESS - $MIN_IP_ADDRESS
    $RANGE3 = $broadcastInt - $MAX_IP_ADDRESS
    # Find the greatest range
    if ($RANGE1 -gt $RANGE2 -and $RANGE1 -gt $RANGE3) {
        $STARTING_IP_INT = $networkAddressInt + 1
        $ENDING_IP_INT = $MIN_IP_ADDRESS - 1
    } elseif ($RANGE2 -gt $RANGE1 -and $RANGE2 -gt $RANGE3) {
        $STARTING_IP_INT = $MIN_IP_ADDRESS + 1
        $ENDING_IP_INT = $MAX_IP_ADDRESS - 1
    } else {
        $STARTING_IP_INT = $MAX_IP_ADDRESS + 1
        $ENDING_IP_INT = $broadcastInt - 1
    }

    # convert the network address back to a dotted decimal
    $STARTING_IP = $STARTING_IP_INT | Convert-IntToIP
    $ENDING_IP = $ENDING_IP_INT | Convert-IntToIP
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
$env:ORGANISATION_NAME='177th Cyber Protection Team'
$env:DOMAIN_NAME='177cpt.com'
$env:CLOUDFLARE_EMAIL='cseelhoff@gmail.com'
$env:TIMEZONE='America/Chicago'
$env:GOVC_URL='vsphere2.us.177cpt.com'
$env:GOVC_USERNAME='Administrator@VSPHERE.LOCAL'
$env:GOVC_HOST='10.0.1.31'
$env:GOVC_DATASTORE='esxi4_datastore'
$env:GOVC_VM='infravm'
$env:GOVC_NETWORK='Internal Management'
$GOVC_IP='10.0.1.41'
$DNS_SERVER_IP=$HOST_IP
$BOOTSTRAP_IP=$DNS_SERVER_IP
$DHCP_ROUTER_IP=$HOST_GATEWAY_IP
$DHCP_START_IP=$STARTING_IP
$DHCP_END_IP=$ENDING_IP

### --- OPTIONAL VARIABLES --- ###
$env:GOVC_INSECURE=$true
$env:GOVC_TLS_KNOWN_HOSTS='~/.govc_known_hosts'
$COREOS_OVA_URL='https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240104.3.0/x86_64/fedora-coreos-39.20240104.3.0-vmware.x86_64.ova'
$COREOS_OVA_NAME='fedora-coreos-39.20240104.3.0-vmware.x86_64'
$PIHOLE_DOCKER_IMAGE='pihole/pihole:2024.01.0'
$env:PORTAINER_DOCKER_IMAGE='portainer/portainer-ce:2.19.4'
$env:OPENLDAP_DOCKER_IMAGE='osixia/openldap:1.5.0'
$NEXUS_DOCKER_IMAGE='sonatype/nexus3:3.64.0'
$GITEA_DOCKER_IMAGE='gitea/gitea:1.21.4'
$env:TRAEFIK_DOCKER_IMAGE='traefik:v2.11'
$env:PHPLDAPADMIN_DOCKER_IMAGE='osixia/phpldapadmin:0.9.0'
$env:AWX_GHCR_IMAGE='ansible/awx_devel:devel'
$PIHOLE_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$TRAEFIK_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$NEXUS_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$env:LDAP_ADMIN_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$env:LDAP_CONFIG_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$env:PORTAINER_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$env:DJANGO_SUPERUSER_PASSWORD=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).Guid)).Replace('+','0')
$env:AWX_POSTGRES_PASSWORD='rzabMdUaDNuyQGmnYUQN'
$env:BROADCAST_WEBSOCKET_SECRET='QnJ1V0FzUG5Eb2pIRURCRnFKQ0Y='
$AWX_SECRET_KEY='JDqxKuQemHEajsZVZFQs'
$PIHOLE_SHORTNAME='pihole'
$NEXUS_SHORTNAME='nexus'
$TRAEFIK_SHORTNAME='traefik'
$DOCKER_SHORTNAME='docker'
$UPSTREAM_DNS_IPS="1.1.1.1;1.0.0.1"
$env:PORTAINER_PORT=9000
$PIHOLE_PORT=8001
$NEXUS_PORT=8081
$DOCKER_REGISTRY_PORT=8002
$VCENTER_LIBRARY_NAME='library'
$env:DOCKER_CLI_HINTS='false'

### --- AUTO-GENERATED VARIABLES --- ###
$env:PIHOLE_FRONTEND_FQDN="$PIHOLE_SHORTNAME.$env:DOMAIN_NAME"
$env:NEXUS_FRONTEND_FQDN="$NEXUS_SHORTNAME.$env:DOMAIN_NAME"
$env:DOCKER_REGISTRY_FRONTEND_FQDN="$DOCKER_SHORTNAME.$env:DOMAIN_NAME"
$env:TRAEFIK_FQDN="$TRAEFIK_SHORTNAME.$env:DOMAIN_NAME"
$env:PIHOLE_BACKEND_FQDN="$PIHOLE_SHORTNAME-backend01.$env:DOMAIN_NAME"
$env:NEXUS_BACKEND_FQDN="$NEXUS_SHORTNAME-backend01.$env:DOMAIN_NAME"
$env:DOCKER_REGISTRY_BACKEND_FQDN="$DOCKER_SHORTNAME-backend01.$env:DOMAIN_NAME"
$TRAEFIK_IP=$BOOTSTRAP_IP
$PIHOLE_IP=$BOOTSTRAP_IP
$NEXUS_IP=$BOOTSTRAP_IP
$DOCKER_REGISTRY_IP=$BOOTSTRAP_IP
$env:PIHOLE_BACKEND_URL="http://$env:PIHOLE_BACKEND_FQDN`:$PIHOLE_PORT"
$env:NEXUS_BACKEND_URL="http://$env:NEXUS_BACKEND_FQDN`:$NEXUS_PORT"
$env:DOCKER_REGISTRY_BACKEND_URL="http://$env:DOCKER_REGISTRY_BACKEND_FQDN`:$DOCKER_REGISTRY_PORT"
$env:PORTAINER_LOCALHOST_URL="http://localhost`:$PORTAINER_PORT"
$PIHOLE_LOCALHOST_BASE_URL="http://localhost`:$PIHOLE_PORT"
$PIHOLE_LOGIN_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/login.php"
$PIHOLE_INDEX_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/index.php"
$PIHOLE_SETTINGS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/settings.php?tab=dns"
$PIHOLE_CUSTOM_DNS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/scripts/pi-hole/php/customdns.php"
$NEXUS_SERIVICE_REST_URL="https://$env:NEXUS_FRONTEND_FQDN/service/rest/v1"
$GOVC_CONNECTION_STRING="$env:GOVC_USERNAME`:$env:GOVC_PASSWORD`@$env:GOVC_URL"
$env:TRAEFIK_DATA_DIR = "$(Get-Location)/bootstrap/traefik/data"
$env:TRAEFIK_AUTH = ((docker run --rm httpd:2.4-alpine htpasswd -nb admin $TRAEFIK_PASSWORD) | Select-Object -First 1).Replace("`$", '$$')
$env:PORTAINER_BCRYPT = ((docker run --rm httpd:2.4-alpine htpasswd -nbB admin $env:PORTAINER_PASSWORD) | Select-Object -First 1).Replace("`$", '$$')
$env:COREOS_ADMIN_PASSWORD_HASH = ((docker run --rm quay.io/coreos/mkpasswd mkpasswd --method=yescrypt $COREOS_ADMIN_PASSWORD) | Select-Object -First 1).Replace("`$", '$$')
Write-Host "Creating ssh keypair if it does not exist..."
$sshKeyPath = "$env:HOMEDRIVE$env:HOMEPATH/.ssh"
if (!(Test-Path -Path "$sshKeyPath/id_rsa")) {
    ssh-keygen -t rsa -b 4096 -f "$sshKeyPath/id_rsa" -N '""'
}
$env:COREOS_SSH_PUBLIC_KEY = Get-Content "$sshKeyPath/id_rsa.pub"

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
        $envVarName = $var.Replace('${', '').Replace('}', '')
        $envVarValue = Get-Content "env:$envVarName"
        $content = $content.Replace($var, $envVarValue)
    }

    Set-Content -Path $OutputFile -Value $content
}

# Use the function to process the template files
Replace-EnvVars -InputFile "bootstrap/traefik/docker-compose.yml.tpl" -OutputFile "bootstrap/traefik/docker-compose.yml"
Replace-EnvVars -InputFile "bootstrap/traefik/data/config.yml.tpl" -OutputFile "bootstrap/traefik/data/config.yml"
Replace-EnvVars -InputFile "bootstrap/traefik/data/traefik.yml.tpl" -OutputFile "bootstrap/traefik/data/traefik.yml"
Replace-EnvVars -InputFile "coreos/awx/docker-compose.yml.tpl" -OutputFile "coreos/awx/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/database.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/database.py"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py"
Replace-EnvVars -InputFile "coreos/guacamole/docker-compose.yml.tpl" -OutputFile "coreos/guacamole/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/openldap/docker-compose.yml.tpl" -OutputFile "coreos/openldap/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/coreos.bu.tpl" -OutputFile "coreos/coreos.bu"
Set-Content -Path "coreos/awx/etc/tower/SECRET_KEY" -Value $AWX_SECRET_KEY
$coreos_volume_map=(Get-Location).Path + '/coreos:/coreos'
docker run --rm -it -v $coreos_volume_map quay.io/coreos/butane:release --files-dir /coreos /coreos/coreos.bu --pretty --strict --output /coreos/coreos.ign

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
  -h pihole-virtual `
  -p 53:53/tcp -p 53:53/udp -p 67:67/udp -p 8001:80/tcp `
  -e DNSMASQ_LISTENING=all `
  -e TZ=$env:TIMEZONE `
  -e PIHOLE_DNS_=$UPSTREAM_DNS_IPS `
  -e DHCP_ACTIVE=true `
  -e DHCP_START=$DHCP_START_IP `
  -e DHCP_END=$DHCP_END_IP `
  -e DHCP_ROUTER=$DHCP_ROUTER_IP `
  -e PIHOLE_DOMAIN=$env:DOMAIN_NAME `
  -e VIRTUAL_HOST=pihole-virtual.$env:DOMAIN_NAME `
  -e WEBPASSWORD=$PIHOLE_PASSWORD `
  -v /etc/pihole/ `
  -v /etc/dnsmasq.d/ `
  --cap-add NET_ADMIN `
  --restart=unless-stopped `
  $PIHOLE_DOCKER_IMAGE

#  -e WEB_PORT=$PIHOLE_PORT `
#  --network=host `

Write-Host "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig before changing local DNS settings"
Resolve-DnsName $env:NEXUS_FRONTEND_FQDN | Select-Object -ExpandProperty IPAddress

# Define the custom DNS list
$CUSTOM_DNS_LIST = @"
$PIHOLE_IP $env:PIHOLE_BACKEND_FQDN
$NEXUS_IP $env:NEXUS_BACKEND_FQDN
$DOCKER_REGISTRY_IP $env:DOCKER_REGISTRY_BACKEND_FQDN
$TRAEFIK_IP $env:TRAEFIK_FQDN
$TRAEFIK_IP $env:PIHOLE_FRONTEND_FQDN
$TRAEFIK_IP $env:NEXUS_FRONTEND_FQDN
$TRAEFIK_IP $env:DOCKER_REGISTRY_FRONTEND_FQDN
$GOVC_IP vsphere2.177cpt.com
$GOVC_IP $env:GOVC_URL
"@
$escapedList = $CUSTOM_DNS_LIST.Replace("`n", "\n").Replace("`r", "")
# Append the custom DNS list to the pihole custom list file and restart the DNS service
$dockerSHCommand = 'echo \"' + $escapedList + '\" >> /etc/pihole/custom.list && pihole restartdns'
docker exec pihole sh -c $dockerSHCommand

Write-Host "Setting Windows network settings to use only the DNS Server 127.0.0.1 (Pi-hole) and setting search domain to $env:DOMAIN_NAME"
$netconfig=(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }) | Select-Object -First 1
# set the DNS server to only use 127.0.0.1
$netconfig | Set-DnsClientServerAddress -ServerAddresses "127.0.0.1"
# set the search domain to $DOMAIN_NAME
$netconfig | Set-DnsClient -ConnectionSpecificSuffix $env:DOMAIN_NAME

Write-Host "Checking DNS A records for NEXUS_FRONTEND_FQDN using dig after changing local DNS settings"
Resolve-DnsName $env:NEXUS_FRONTEND_FQDN | Select-Object -ExpandProperty IPAddress

Remove-DockerContainer -containerName "traefik"
Write-Host "Checking if the volume named traefik-data exists"
if (docker volume inspect traefik-data) {
  Write-Host "Volume 'traefik-data' exists. Removing volume..."
  docker volume rm traefik-data
}
Write-Host "Creating volume 'traefik-data'"
docker volume create --name traefik-data
Write-Host "Creating temporary container to copy acme.json to traefik-data volume"
docker run --rm -d -v traefik-data:/data --name temp alpine tail -f /dev/null
# check if the acme.json file exists in the backup folder
if (Test-Path backup/acme.json) {
    Write-Host "Restoring acme.json from backup"
    docker cp backup/acme.json temp:/data/
} else {
    Write-Host "Creating new acme.json"
    docker exec temp touch /data/acme.json
}
Write-Host "Setting permissions to 600 on Traefik acme.json"
docker exec temp chmod 600 /data/acme.json
Write-Host "Stopping and removing temporary container"
docker stop temp

Write-Host "Checking if proxy network for Traefik exists"
if (docker network inspect proxy) {
  Write-Host "Proxy network exists. Checking if any containers are using it"
  if ((docker network inspect proxy) -match '"Containers": {}') {
    Write-Host "No containers are using the proxy network. Removing the proxy network"
    docker network rm proxy
  } else {
    Write-Host "Other containers are still using the proxy network. Exiting script as failed."
    exit 1
  }
}

Write-Host "Creating proxy network for Traefik"
docker network create proxy
Write-Host "Starting Traefik with password: $TRAEFIK_PASSWORD"
docker-compose -f bootstrap/traefik/docker-compose.yml -p traefik up -d


Remove-DockerContainer -containerName "nexus"
Write-Host "Checking if the volume named nexus-data exists"
if (docker volume inspect nexus-data) {
  Write-Host "Volume 'nexus-data' exists. Removing volume..."
  docker volume rm nexus-data
}
Write-Host "Creating volume 'nexus-data'"
docker volume create --name nexus-data
if (Test-Path backup/nexus-backup.tar.gz) {
    Write-Host "Restoring Nexus from backup"
    docker run --rm -v nexus-data:/nexus-data -v $(Get-Location)/backup:/backup alpine tar -xzf /backup/nexus-backup.tar.gz -C /nexus-data
} else {
    Write-Host "No backup found, creating new Nexus"
    Write-Host "Starting Nexus"
    docker run -d -p $NEXUS_PORT`:$NEXUS_PORT -p $DOCKER_REGISTRY_PORT`:$DOCKER_REGISTRY_PORT --name nexus -v nexus-data:/nexus-data $NEXUS_DOCKER_IMAGE
    
    Write-Host "Waiting for Nexus container to start" -NoNewline    
    while($true) {
        $NEXUS_TEMP_PASSWORD = (docker exec nexus cat /nexus-data/admin.password) | Select-Object -First 1
        if ([string]::IsNullOrEmpty($NEXUS_TEMP_PASSWORD) -eq $false) {
            Write-Host "`nNexus temp password is: $NEXUS_TEMP_PASSWORD"
            break
        }
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 1
    }
    # invoke web request with a get to $NEXUS_SERIVICE_REST_URL/security/users using basic web authentication
    $Nexus_Encoded_Creds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("admin:$NEXUS_TEMP_PASSWORD"))
    $Nexus_Headers = @{Authorization = "Basic $Nexus_Encoded_Creds"}
    Write-Host "Waiting for Nexus REST API to start on: $NEXUS_SERIVICE_REST_URL/security/users " -NoNewline 
    while($true) {
        if ((Invoke-WebRequest -Uri $NEXUS_SERIVICE_REST_URL/security/users -Method Get -Headers $Nexus_Headers -ErrorAction SilentlyContinue).StatusCode -eq 200) {
            Write-Host "`nNexus REST API has started"
            break
        }
        Write-Host -NoNewline '.'
        Start-Sleep -Seconds 1
    }
    Write-Host "Changing Nexus password from: $NEXUS_TEMP_PASSWORD to: $NEXUS_PASSWORD"
    Invoke-WebRequest -Uri $NEXUS_SERIVICE_REST_URL/security/users/admin/change-password -Method Put -Body $NEXUS_PASSWORD -ContentType "text/plain" -Headers $Nexus_Headers
    $Nexus_Encoded_Creds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("admin:$NEXUS_PASSWORD"))
    $Nexus_Headers = @{Authorization = "Basic $Nexus_Encoded_Creds"}
    Write-Host "Setting active realms to LdapRealm, DockerToken, and NexusAuthenticatingRealm"
    Invoke-RestMethod -Uri "$NEXUS_SERIVICE_REST_URL/security/realms/active" -Method Put -Body '[
            "LdapRealm",
            "DockerToken",
            "NexusAuthenticatingRealm"
    ]' -ContentType "application/json" -Headers $Nexus_Headers

    Write-Host "Creating docker-hosted repository"
    Invoke-RestMethod -Uri "$NEXUS_SERIVICE_REST_URL/repositories/docker/hosted" -Method Post -Body '{
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
    }' -ContentType "application/json" -Headers $Nexus_Headers

    Write-Host "Creating docker-proxy repository"
    Invoke-RestMethod -Uri "$NEXUS_SERIVICE_REST_URL/repositories/docker/proxy" -Method Post -Body '{
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
    }' -ContentType "application/json" -Headers $Nexus_Headers
    Write-Host "Creating ghcr-proxy repository"
    Invoke-RestMethod -Uri "$NEXUS_SERIVICE_REST_URL/repositories/docker/proxy" -Method Post -Body '{
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
    }' -ContentType "application/json" -Headers $Nexus_Headers
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
            "httpPort" = $DOCKER_REGISTRY_PORT
        }
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "$NEXUS_SERIVICE_REST_URL/repositories/docker/group" -Method Post -Body $jsonBody -ContentType "application/json" -Headers $Nexus_Headers
    Write-Host "Removing local docker images cache"
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:PORTAINER_DOCKER_IMAGE
    docker image rm $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:TRAEFIK_DOCKER_IMAGE

    Write-Host "Caching docker images in Nexus"
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$NEXUS_DOCKER_IMAGE
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:PORTAINER_DOCKER_IMAGE
    docker pull $env:DOCKER_REGISTRY_FRONTEND_FQDN/$env:TRAEFIK_DOCKER_IMAGE

    Write-Host "Stopping Nexus to create backup"
    docker stop --time=120 nexus

    Write-Host "Creating Nexus backup"
    if (!(Test-Path -Path backup)) {
        New-Item -ItemType Directory -Path backup
    }
    $nexus_volume_map=(Get-Location).Path + '/backup:/backup'
    docker run --rm -v nexus-data:/nexus-data -v $nexus_volume_map alpine sh -c "tar -C /nexus-data -czf /backup/nexus-backup.tar.gz ."

    Write-Host "Starting Nexus"
    docker start nexus
}
Write-Host "Waiting for Nexus to start on: $NEXUS_SERIVICE_REST_URL/security/users"
do {
    Write-Host -NoNewline '.'
    Start-Sleep -Seconds 1
} until (((Invoke-WebRequest -Uri $NEXUS_SERIVICE_REST_URL/security/users -Method Get -Headers $Nexus_Headers)).StatusCode -eq 200)
Write-Host

write-host "Creating backup of acme.json"
if (!(Test-Path -Path backup)) {
    New-Item -ItemType Directory -Path backup
}
docker cp traefik:/data/acme.json backup/

Write-Host 'Bootstrap complete!'

if (!(Test-Path -Path govc.exe)) {
    Write-Host "Downloading govc"
    Invoke-WebRequest -uri https://github.com/vmware/govmomi/releases/download/v0.34.2/govc_Windows_x86_64.zip -OutFile govc_Windows_x86_64.zip
    # extract specific file govc.exe from the zip
    Expand-Archive -Path govc_Windows_x86_64.zip -DestinationPath . -Force
    Remove-Item -Path govc_Windows_x86_64.zip
}

Write-Host "Logging into vCenter"
.\govc about.cert -u $env:GOVC_URL -k -thumbprint | Out-File -Append $env:GOVC_TLS_KNOWN_HOSTS
.\govc about -u $GOVC_CONNECTION_STRING
.\govc session.login -u $GOVC_CONNECTION_STRING
# why this fixes things, we don't know...
.\govc library.ls -u $GOVC_CONNECTION_STRING

Write-Host "Creating library and importing OVA"
if ((.\govc library.ls -u $GOVC_CONNECTION_STRING -json | ConvertFrom-Json).name -contains $VCENTER_LIBRARY_NAME) {
    Write-Host "Library name: $VCENTER_LIBRARY_NAME already exists"
} else {
    Write-Host "Creating library $VCENTER_LIBRARY_NAME"
    .\govc library.create -u $GOVC_CONNECTION_STRING -ds=$env:GOVC_DATASTORE $VCENTER_LIBRARY_NAME
}

Write-Host "Checking if OVA already exists in library"
if ((.\govc library.ls -u $GOVC_CONNECTION_STRING $VCENTER_LIBRARY_NAME/*) -match $COREOS_OVA_NAME) {
    Write-Host "OVA $COREOS_OVA_NAME already exists in library $env:VCENTER_LIBRARY_NAME"
} else {
    Write-Host "Importing OVA $COREOS_OVA_NAME into library $VCENTER_LIBRARY_NAME"
    .\govc library.import -u $GOVC_CONNECTION_STRING -n=$COREOS_OVA_NAME $VCENTER_LIBRARY_NAME $COREOS_OVA_URL
}

Write-Host "Deploying VM from OVA"
.\govc library.deploy -u $GOVC_CONNECTION_STRING -host $env:GOVC_HOST /$VCENTER_LIBRARY_NAME/$COREOS_OVA_NAME $env:GOVC_VM
$ignitionConfigData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content -Path coreos/coreos.ign -Raw)))
.\govc vm.change -u $GOVC_CONNECTION_STRING -vm $env:GOVC_VM -e="guestinfo.ignition.config.data=$ignitionConfigData"
.\govc vm.change -u $GOVC_CONNECTION_STRING -vm $env:GOVC_VM -e="guestinfo.ignition.config.data.encoding=base64"
.\govc vm.change -u $GOVC_CONNECTION_STRING -vm $env:GOVC_VM -m=32000 -c=8
.\govc vm.power -u $GOVC_CONNECTION_STRING -on $env:GOVC_VM

Write-Host "Waiting for VM to be ready..."
$VM_IP = .\govc vm.ip -u $GOVC_CONNECTION_STRING $env:GOVC_VM
Write-Host "YOUR PORTAINER PASSWORD IS: $env:PORTAINER_PASSWORD"
Write-Host "$env:GOVC_VM's IP: $VM_IP"
Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") -- deployment complete!"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i ~/.ssh/id_rsa admin@$VM_IP

# prompt user to press y to delete the VM
$REPLY = Read-Host "Press y to delete the VM: "
if ($REPLY -eq 'y' -or $REPLY -eq 'Y') {
    # delete the VM
    govc vm.power -u $GOVC_CONNECTION_STRING -off $env:GOVC_VM
    govc vm.destroy -u $GOVC_CONNECTION_STRING $env:GOVC_VM
}