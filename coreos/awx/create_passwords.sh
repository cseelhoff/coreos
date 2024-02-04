#!/bin/bash
cat << EOF > "/etc/tower/conf.d/database.py"
DATABASES = {
    'default': {
        'ATOMIC_REQUESTS': True,
        'ENGINE': 'awx.main.db.profiled_pg',
        'NAME': "awx",
        'USER': "awx",
        'PASSWORD': "${TOWER_DATABASE_PASSWORD}",
        'HOST': "postgres",
        'PORT': "5432",
    }
}
EOF
echo "BROADCAST_WEBSOCKET_SECRET = \"${BROADCAST_WEBSOCKET_SECRET}\"" > "/etc/tower/conf.d/websocket_secret.py"
echo "SECRET_KEY = \"${TOWER_SECRET_KEY}\"" > "/etc/tower/SECRET_KEY"
