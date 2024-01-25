FROM devopsinfra/docker-terragrunt:tf-1.7.0-tg-0.54.21
RUN curl -L -o - https://github.com/vmware/govmomi/releases/download/v0.34.2/govc_Linux_x86_64.tar.gz | tar -C /usr/local/bin -xvzf - govc
RUN curl -L https://github.com/coreos/butane/releases/download/v0.19.0/butane-x86_64-unknown-linux-gnu --output /usr/local/bin/butane && chmod +x /usr/local/bin/butane
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y apache2-utils && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
