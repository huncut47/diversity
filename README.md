## Diversity: MiniTwit

A Twitter-like microblogging service originally provided as a Python/Flask
app for the _DevOps, Software Evolution and Software Maintenance_ course,
refactored by our group into a Go application backed by PostgreSQL. It serves
a web UI and a simulator-facing API, and runs in production as a Docker Swarm
stack on a single Hetzner VPS.

**Tech stack:** Go (chi router) + PostgreSQL (GORM) · Docker Swarm · Caddy
(TLS) · Prometheus + Grafana (metrics) · Elasticsearch + Filebeat + Kibana
(logs) · GitHub Actions (CI/CD) · Hetzner API + Ansible (provisioning).

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

### Initial server setup

`setup.sh` performs the **one-time** initial bring-up on a freshly
bootstrapped server (builds the image and deploys the stack):

```bash
chmod +x ./setup.sh
./setup.sh
```

The webapp is then available at `http://<server_ip>:80` (and via Caddy on
the configured domain over HTTPS).

### How changes reach production

After the initial setup, **production deployment is fully automated through
GitHub Actions**:

1. Open a pull request against `main`.
2. CI (`.github/workflows/ci.yml`) runs `gofmt`, `golangci-lint`,
   `hadolint`, `integration_test`, `uitest`, `codeql`, and `image_scan`
   (Trivy). Branch protection requires these to pass.
3. Merge the PR into `main`.
4. The `deploy` job SSHes in as the `deploy` user, pulls the latest code,
   rebuilds the image, runs `docker stack deploy -c docker-compose.yml
diversity`, and force-updates the `web` service. Swarm performs a
   rolling update (one replica at a time, start-first).

Releases are tagged automatically every Friday 09:00 UTC by
`.github/workflows/weekly-release.yml`.

### Observability

- **Grafana** (metrics): `https://grafana.kulturbase.dk`
- **Kibana** (logs): `https://kibana.kulturbase.dk`

Both are reachable only through Caddy over HTTPS; dashboards are provisioned
from `monitoring/` so they are reproducible on every deployment.

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
