We also release Docker images `aquasec/starboard:$VERSION` and `public.ecr.aws/aquasecurity/starboard:$VERSION` to run
Starboard as a Docker container or to manually schedule Kubernetes scan Jobs in your cluster.

```console
$ docker container run --rm public.ecr.aws/aquasecurity/starboard:0.8.0 version
Starboard Version: {Version:0.8.0 Commit:10a7cc45d646cefcf09447f9b26d5624551dd495 Date:2021-01-07T17:58:22Z}
```
