# Docker

We also release Docker images `aquasec/starboard:{{ var.build.version }}` and
`public.ecr.aws/aquasecurity/starboard:{{ var.build.version }}` to run Starboard as a Docker container or to manually
schedule Kubernetes scan Jobs in your cluster.

```console
$ docker container run --rm public.ecr.aws/aquasecurity/starboard:{{ var.build.version }} version
Starboard Version: {Version:{{ var.build.version }} Commit:{{ var.build.commit }} Date:{{ var.build.date }}}
```
