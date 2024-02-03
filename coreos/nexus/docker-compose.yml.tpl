version: '3'
services:
  nexus:
    image: ${NEXUS_DOCKER_IMAGE}
    ports:
      - "${VM_NEXUS_PORT}:${VM_NEXUS_PORT}"
      - "${VM_DOCKER_REGISTRY_PORT}:${VM_DOCKER_REGISTRY_PORT}"
    volumes:
      - nexus-data:/nexus-data
    restart: always

volumes:
  nexus-data: