# Start from the specified image
FROM ghcr.io/ansible/awx_devel:HEAD

# Add files and directories to the image
ADD _build/ /awx_devel/_build
ADD awx/ /awx_devel/awx
ADD awx_collection/ /awx_devel/awx_collection
ADD awxkit/ /awx_devel/awxkit
ADD config/ /awx_devel/config
ADD docks/ /awx_devel/docs
ADD licenses/ /awx_devel/licenses
ADD requirements/ /awx_devel/requirements
ADD tools/ /awx_devel/tools
ADD tools/docker-compose/supervisor.conf /etc/supervisord.conf
#ADD tools/docker-compose/_sources/database.py /etc/tower/conf.d/database.py
#DATABASES = {
#    'default': {
#        'ATOMIC_REQUESTS': True,
#        'ENGINE': 'awx.main.db.profiled_pg',
#        'NAME': "awx",
#        'USER': "awx",
#        'PASSWORD': "hnNQQOpOxoXTzoySalso",
#        'HOST': "postgres",
#        'PORT': "5432",
#    }
#}

#ADD tools/docker-compose/_sources/websocket_secret.py /etc/tower/conf.d/websocket_secret.py
# BROADCAST_WEBSOCKET_SECRET = "TXBYUVlRRGNDdEtaZFlDSWpGb1k="

ADD tools/docker-compose/_sources/local_settings.py /etc/tower/conf.d/local_settings.py
ADD tools/docker-compose/_sources/nginx.conf /etc/nginx/nginx.conf
ADD tools/docker-compose/_sources/nginx.locations.conf /etc/nginx/conf.d/nginx.locations.conf
#ADD tools/docker-compose/_sources/SECRET_KEY /etc/tower/SECRET_KEY
# kXvUcSEoawQiQRjeVXFk

ADD tools/docker-compose/_sources/receptor/receptor-awx-1.conf /etc/receptor/receptor.conf
