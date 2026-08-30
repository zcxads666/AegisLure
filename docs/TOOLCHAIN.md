# Project-local toolchain

The workspace is currently an unprivileged Ubuntu 24.04 environment. To keep the project reproducible and avoid writing system directories, tools are installed under `.tools/` (ignored by Git):

| Tool | Version | Location |
| --- | --- | --- |
| Go | 1.26.5 | `.tools/go/bin/go` |
| Docker CLI | 29.1.3 | `.tools/bin/docker` |
| Docker Engine binaries | 29.1.3 | `.tools/bin/dockerd`, `containerd`, `runc` |
| Docker Compose CLI | 5.4.0 | `.tools/docker-config/cli-plugins/docker-compose` |
| Docker Buildx | 0.36.1 | `.tools/docker-config/cli-plugins/docker-buildx` |
| RootlessKit | 3.1.0 | `.tools/bin/rootlesskit` |
| slirp4netns | 1.3.4 | `.tools/bin/slirp4netns` |

Load the toolchain with:

```bash
source scripts/env.sh
```

Go module cache and build cache are also local: `.tools/gopath/pkg/mod` and `.tools/gocache`.

## Engine status

The Docker client and all static runtime binaries are present, but this environment cannot access `/var/run/docker.sock`. A rootless Engine attempt is also blocked because the host does not provide `newuidmap`/`newgidmap` and the required subuid/subgid configuration. The project therefore has a usable Go build/test toolchain and Docker/Compose CLI, but Compose images cannot be built until a host Docker daemon or a permitted remote Docker context is available.

For a normal Ubuntu host, install and start Docker Engine through the official Docker package repository, then add the deployment user to the Docker group only if that security trade-off is acceptable. For an isolated rootless deployment, configure subuid/subgid and the rootless prerequisites on the host rather than copying host privilege assumptions into AegisLure.
