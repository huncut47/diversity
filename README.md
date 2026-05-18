## Diversity: MiniTwit

This app was refactored to a golang application.

## Provisioning and Deployment

### Provisioning

The `cmd/scripts/provision.go` script will provision the server in Hetzner Cloud. Insert the token in the .env file as `HCLOUD_TOKEN` and run the script:

```bash
go run cmd/scripts/provision.go
```

The script will output the IP address of the server after provisioning. You can use this IP address to ssh into the server.

```bash
ssh root@<server_ip>
```

### Bootstrapping

The bootstrapping logic uses Ansible to install it visit the official [installation guide](https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html).

There are two bootstrapping playbooks, `ansible/bootstrap.yml` and `ansible/bootstrap-docker.yml`. The `ansible/bootstrap.yml` playbook will setup up the server and harden the security. The `ansible/bootstrap-docker.yml` playbook will install docker and docker compose on the server. To run the playbooks, execute the following commands:

```bash
ansible-playbook -i ansible/inventory ansible/bootstrap.yml
```

```bash
ansible-playbook -i ansible/inventory ansible/bootstrap-docker.yml
```

Be sure to replace the `ansible/inventory` file with the correct IP address of the server.

### Go Format

Install the goformat tool to format the code:

```bash
go install mvdan.cc/gofumpt@latest
```

Then run the following command to format the code:

```bash
gofumpt -w .
```

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

## Building and Running the Docker Swarm

Setup the docker swarm on the server by running the following command:

```bash
docker swarm init
```

Then build the docker image for the webapp:

```bash
docker build -t minitwit-webapp:latest .
```

Then deploy the stack with the following command:

```bash
docker stack deploy -c docker-compose.yml minitwit
```
