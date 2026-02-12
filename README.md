## Diversity: MiniTwit

This app was refactored to a golang application.

## Building and Running the Docker Container

First build the image:

```bash
docker build -t minitwit .
```

Then run the container and map the port:

```bash
docker run -p 3000:3000 minitwit
```
