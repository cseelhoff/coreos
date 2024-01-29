# Build the Dockerfile
docker build -t atomic-infra -f ./.devcontainer/Dockerfile .

# Run a new container based on the new image
docker run -it -v "$(pwd):/workspaces/atomic-infra" -w /workspaces/atomic-infra atomic-infra /bin/bash
