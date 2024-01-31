### --- SECRETS --- ###
# Store and retrieve secrets from .env file
if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            Write-Host "Found variable in .env file with name $($matches[1]) and value $($matches[2])"
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
    if ($_ -match '^(.*?)=(.*)$') {
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
$env:PIHOLE_BACKEND_URL="http://$env:PIHOLE_BACKEND_FQDN\:$PIHOLE_PORT"
$env:NEXUS_BACKEND_URL="http://$env:NEXUS_BACKEND_FQDN\:$NEXUS_PORT"
$env:DOCKER_REGISTRY_BACKEND_URL="http://$env:DOCKER_REGISTRY_BACKEND_FQDN\:$DOCKER_REGISTRY_PORT"
$env:PORTAINER_LOCALHOST_URL="http://localhost\:$PORTAINER_PORT"
$PIHOLE_LOCALHOST_BASE_URL="http://localhost\:$PIHOLE_PORT"
$PIHOLE_LOGIN_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/login.php"
$PIHOLE_INDEX_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/index.php"
$PIHOLE_SETTINGS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/settings.php?tab=dns"
$PIHOLE_CUSTOM_DNS_URL="$PIHOLE_LOCALHOST_BASE_URL/admin/scripts/pi-hole/php/customdns.php"
$NEXUS_SERIVICE_REST_URL="https://$env:NEXUS_FRONTEND_FQDN/service/rest/v1"
$GOVC_CONNECTION_STRING="$env:GOVC_USERNAME:$env:GOVC_PASSWORD@$env:GOVC_URL"
$env:TRAEFIK_DATA_DIR = "$(Get-Location)/bootstrap/traefik/data"
$env:TRAEFIK_AUTH = ((docker run --rm httpd:2.4-alpine htpasswd -nb admin $TRAEFIK_PASSWORD) | Select-Object -First 1).Replace("`$", '$$')
$env:PORTAINER_BCRYPT = ((docker run --rm httpd:2.4-alpine htpasswd -nbB admin $PORTAINER_PASSWORD) | Select-Object -First 1).Replace("`$", '$$')
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
Replace-EnvVars -InputFile "coreos/awx/docker-compose.yml.tpl" -OutputFile "bootstrap/traefik/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/database.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/database.py"
Replace-EnvVars -InputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py.tpl" -OutputFile "coreos/awx/etc/tower/conf.d/websocket_secret.py"
Replace-EnvVars -InputFile "coreos/guacamole/docker-compose.yml.tpl" -OutputFile "coreos/guacamole/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/openldap/docker-compose.yml.tpl" -OutputFile "coreos/openldap/docker-compose.yml"
Replace-EnvVars -InputFile "coreos/coreos.bu.tpl" -OutputFile "coreos/coreos.bu"
Set-Content -Path "coreos/awx/etc/tower/SECRET_KEY" -Value $AWX_SECRET_KEY
docker run --rm -v ./coreos:/coreos quay.io/coreos/butane:release --files-dir /coreos --pretty --strict /coreos/coreos.bu --output /coreos/coreos.ign

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
  -e TZ=$env:TIMEZONE `
  -e PIHOLE_DNS_=$UPSTREAM_DNS_IPS `
  -e DHCP_ACTIVE=true `
  -e DHCP_ROUTER_IP=$DHCP_ROUTER_IP `
  -e DHCP_START_IP=$DHCP_START_IP `
  -e DHCP_END_IP=$DHCP_END_IP `
  -e PIHOLE_DOMAIN=$env:DOMAIN_NAME `
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
            $env:NEXUS_TEMP_PASSWORD = (docker exec nexus cat /nexus-data/admin.password 2>$null) | Select-Object -First 1
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