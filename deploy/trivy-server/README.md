# Trivy Server

> **Note:** This is just for testing Trivy in client-server mode. We should move away the YAML Manifests from this repository.
> Maybe even provide a Helm chart for Trivy server.

## Deploy with Static YAML Manifests

```
$ kubectl apply -f deploy/trivy-server
```

```
$ kubectl run trivy-client -it --rm --image aquasec/trivy:0.14.0 --command -- sh
/ # trivy client --format json --remote http://trivy-server.trivy-server:4954 wordpress:4.9
/ # trivy client --format json --remote http://trivy-server.trivy-server:4954 wordpress:5.5
```
