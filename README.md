## Diversity: MiniTwit

This app was refactored to a golang application.


## Provisioning and Deployment

### Provisioning
The `cmd/scripts/provision.go` script will provision the server in Hetzner Cloud.

### Deployment
The deployment is done with the setup.sh script, which will be executed on the server after provisioning. It requires that docker and docker compose is installed on the server. It starts the building of the DockerFile for the webapp and it starts the docker compose.

```bash
chmod +x ./setup.sh
```

To run the setup script, execute the following command:

```bash
./setup.sh
```

The webapp will be available at `http://<server_ip>:80` after the setup script has finished.

## Building and Running the Docker Container

First build the image:

```bash
docker build -t minitwit .
```

Then run the container and map the port:

```bash
docker run -p 3000:3000 minitwit
```
