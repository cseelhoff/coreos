variant: fcos
version: 1.4.0
passwd:
  users:
    - name: admin
      groups:
        - docker
        - wheel
      ssh_authorized_keys:
        - ${COREOS_SSH_PUBLIC_KEY}
      password_hash: ${COREOS_ADMIN_PASSWORD_HASH}
storage:
  files:
    - path: /usr/local/bin/docker-compose
      overwrite: true
      contents:
        source: https://github.com/docker/compose/releases/download/v2.24.2/docker-compose-linux-x86_64
        verification:
          hash: sha512-DBB485B512B885DE15FF92C24D3CA1B0F46D62BF5DBCD166FD286F545652FA673E4988CFD43A708F7ECFEA34AC92538D119C4625E7B3DBB3BB006277F76F9823
      mode: 0755

    - path: /opt/portainer/deploy-stack.sh
      mode: 0700
      contents:
        local: portainer/deploy-stack.sh

    - path: /opt/openldap/docker-compose.yml
      mode: 0644
      contents:
        local: openldap/docker-compose.yml

systemd:
  units:
# add vmware-tools
    - name: open-vm-tools.service
      enabled: true
      contents: |
        [Unit]
        Description=Open VM Tools
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        TimeoutStartSec=0
        ExecStartPre=-/usr/bin/docker stop %n
        ExecStartPre=-/usr/bin/docker rm %n
        ExecStartPre=/usr/bin/docker pull immutablecode/open-vm-tools:1.0.0
        ExecStart=/usr/bin/docker run -e SYSTEMD_IGNORE_CHROOT=1 -v  /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup -v /run/systemd:/run/systemd --pid=host --net=host --ipc=host --uts=host --rm  --privileged --name open-vm-tools immutablecode/open-vm-tools:1.0.0
        ExecStop=/usr/bin/docker stop -t 15 %n

        [Install]
        WantedBy=multi-user.target

# add portainer service
    - name: docker.portainer.service
      enabled: true
      contents: |-
        [Unit]
        Description=Portainer Admin Container
        After=docker.service
        Requires=docker.service network.target network-online.target
        
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        TimeoutStartSec=0
        ExecStartPre=-/usr/bin/docker stop portainer
        ExecStartPre=-/usr/bin/docker rm portainer
        ExecStartPre=/usr/bin/docker pull portainer/portainer-ce
        ExecStart=-/usr/bin/mkdir -p /var/portainer/data
        ExecStart=/usr/bin/docker run --privileged=true -d -p ${PORTAINER_PORT}:9000 --name portainer --restart always -v /var/run/docker.sock:/var/run/docker.sock -v /var/portainer/data:/data ${PORTAINER_DOCKER_IMAGE} --admin-password '${PORTAINER_BCRYPT}'
        ExecStop=/usr/bin/docker stop -t 15 portainer
        
        [Install]
        WantedBy=multi-user.target
    - name: docker.openldap.service
      enabled: true
      contents: |-
        [Unit]
        Description=OpenLDAP Container
        After=docker.portainer.service
        Requires=docker.service docker.portainer.service network.target network-online.target
        
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        TimeoutStartSec=0
        ExecStart=/usr/bin/sh /opt/portainer/deploy-stack.sh openldap /opt/openldap/docker-compose.yml
        
        [Install]
        WantedBy=multi-user.target
