# Introduce a custom resource to represent a (trusted) registry

## TOC

- [Abstract](#abstract)
- [Problem statement](#problem-statement)
- [Solution](#solutions)
- [Use cases](#use-cases)
  - [Starboard Security Operator supervising trusted registries](#starboard-security-operator-supervising-trusted-registries)
  - [Repository webhooks integrated with Starboard](#repository-webhooks-integrated-with-starboard)

## Abstract

Common requirements for running secure Kubernetes workloads are:

- Pull container images only from trusted registries and/or repositories. For example, one might allow pulling
  images from private Harbor repository accessible at https://core.harbor.domain/library/nginx:1.16, but deny pull
  requests to the core.harbor.domain/library/redis:5 or https://docker.io/library/nginx:1.16 repositories.
- Statically scan container images, and implement rules to deny workloads that include critical, high or medium vulnerabilities. In general, these rules are configurable (for example, what level of severity will cause an image to be denied).
- Use a Kubernetes admission controller to deny workloads with non-compliant container images. For example, one may
  allow `kubectl run nginx-pod --image=core.harbor.domain/library/nginx:1.16`, but deny
  `kubectl run redis-pod --image core.harbor.domain/library/redis:5`.

## Problem statement

- Starboard CLI and Starboard Security Operator are able to scan workloads already deployed in a cluster. Hence, an 
  admission controller cannot use vulnerability reports for compliance checks.
- The `vulnerabilities.aquasecurity.github.io` resources are scoped to the same namespace as the underlying workload.
  However, for admission controllers we might want to introduce cluster-scoped resource to represent vulnerability
  report associated with a given container image digest, for example `registryvulnerabilities.aquasecurity.github.io`.
- Container images are not first-class citizens in Kubernetes-native world. There’s no built-in resource that represents
  a container image. Also, there’s no built-in representation of a (trusted) registry.
- An admission controller has certain performance requirements. Usually we cannot trigger a scanner when the admission
  controller is invoked for a given Kubernetes API request. Most likely it will take way too long to perform such
  ad hoc scans.

## Solutions

### Define registries.aquasecurity.github.io resource

First off, introduce a custom resource to represent a (trusted) container registry. For example, we can represent
a private Harbor registry with the following Kubernetes object:

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: Registry
metadata:
  name: my-harbor-registry
spec:
  name: My Harbor Registry
  description: |
    That's the only registry authorized to run production workloads.
  server: core.harbor.domain
  imagePullSecrets:
  - name: my-harbor-registry-credentials
  insecure: false
  trustedRepositories:
  - name: library/nginx:1.16
  - name: library/alpine
  - namePattern: trusted/**
status:
  trustedRepositoryStatuses:
  - name: library/nginx
    scanned: true
    lastScanTime: 2020-01-01T00:00:00Z
  - name: library/alpine
    scanned: false
    lastScanTime: null
```

The `Registry` entity has the `spec` property, which allows specifying trusted repositories. The `status` field might
contain scan status for individual repositories. In the example above, you can see that the `library/nginx` repository
has already been scanned, whereas the `library/alpine` repository has not.

### Define registryvulnerabilities.aquasecurity.github.io resource

Define the `RegistryVulnerability` entity to represent a vulnerability report for the specified image digest:


```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: RegistryVulnerability
metadata:
  name: ddbb8bfb-040a-42a1-a051-d5aff77a53e7
  labels:
    starboard.repository.name: library/nginx
    starboard.repository.tag: 1.16
    starboard.repository.digest: sha256.d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c
    starboard.resource.kind: Registry
    starboard.resource.name: my-harbor-registry
report:
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: 0.9.1
  registry:
    url: https://core.harbor.domain
  artifact:
      repository: "library/nginx"
      digest: "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c"
      tag: "1.16"
      mimeType: "application/vnd.docker.distribution.manifest.v2+json"
  summary:
    criticalCount: 0
    highCount: 0
    lowCount: 92
    mediumCount: 27
    noneCount: 0
    unknownCount: 3
  vulnerabilities:
  - id: CVE-2020-1879
  - id: CVE-2018-2342
```

## Starboard Security Operator supervising Registry entities

TODO Describe how Starboard Operator can have a control loop for watching `registries.aquasecurity.github.io` resources
and creating scan jobs for the underlying repositories listed under `spec.trustedRepositories[].name`. On scan jobs
completion the Operator will create instances of `registryvulnerabilities.aquasecurity.github.io` resources.

> **Note:** Instances of RegistryVulnerability entity hold `ownerRef` pointing to the `Registry` entity. This way
> vulnerability reports can be automatically garbage collected on Registry deletion.

## Repository webhooks integrated with Starboard

TODO For registries that do support vulnerability scanning and have integrations via webhooks (e.g. Quay or Harbor)
we can implement a webhook that creates an instance of the `registryvulnerabilities.aquasecurity.github.io` resource
for each image push to the registry.
