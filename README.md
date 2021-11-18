![Starboard logo](docs/images/starboard-logo.png)

> Kubernetes-native security toolkit.

[![GitHub Release][release-img]][release]
[![GitHub Build Actions][build-action-img]][actions]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls Starboard][docker-pulls-starboard]
![Docker Pulls Starboard Operator][docker-pulls-starboard-operator]

# Introduction

Starboard integrates security tools into the Kubernetes environment, so that users can find and view the risks that
relate to different resources in a Kubernetes-native way. Starboard provides [Custom Resource Definitions] and a
[Go module] to work with a range of existing security scanners, as well as a [kubectl]-compatible command, the
[Octant Plugin], and the [Lens Extension] that make security reports available through familiar Kubernetes tools.

<p align="center">
<img src="docs/images/starboard-overview.png" alt="Starboard Overview"/>
</p>

Starboard provides:

- Automated vulnerability scanning for Kubernetes applications.
- Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- Automated infrastructures scanning and compliance checks with CIS Benchmarks published by the Center for Internet Security (CIS).
- Penetration test results for a Kubernetes cluster.

Starboard can be run in two different modes:

- As a [Kubernetes operator] to automatically update security reports in response to workload and other changes on a
  Kubernetes cluster - for example, initiating a vulnerability scan when a new Pod is started or running CIS Benchmarks
  when a new Node is added.
- As a [command][cli], so you can trigger scans and view the risks in a kubectl-compatible way or as part of your CI/CD
  pipeline.

  ![](docs/images/starboard-cli-with-octant-demo.gif)

# Status

Although we are trying to keep new releases backward compatible with previous versions, this project is still incubating
and some APIs and custom resource definitions may change.

# Documentation

The official [Documentation] provides detailed installation, configuration, troubleshooting, and quick start guides.

Start by installing the Starboard command [From the Binary Releases] and follow the [Getting Started] guide to generate
your first vulnerability and configuration audit reports!

Read more about the motivations for the project and use cases in this [blog][aqua-starboard-blog] and join our
[discussions].

# Contributing

At this early stage we would love your feedback on the overall concept of Starboard. Over time we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

* See [CONTRIBUTING.md](CONTRIBUTING.md) for information about setting up your development environment, and the
  contribution workflow that we expect.
* See [ROADMAP.md](ROADMAP.md) for tentative features in a 1.0 release.
* Join our [discussions][discussions].

---
Starboard is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).  
Contact us about any matter by opening a GitHub Discussion [here](https://github.com/aquasecurity/starboard/discussions).

[release-img]: https://img.shields.io/github/release/aquasecurity/starboard.svg?logo=github
[release]: https://github.com/aquasecurity/starboard/releases
[build-action-img]: https://github.com/aquasecurity/starboard/workflows/build/badge.svg
[actions]: https://github.com/aquasecurity/starboard/actions
[cov-img]: https://codecov.io/github/aquasecurity/starboard/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/starboard
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/starboard
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/starboard
[license-img]: https://img.shields.io/github/license/aquasecurity/starboard.svg
[license]: https://github.com/aquasecurity/starboard/blob/main/LICENSE
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/starboard/total?logo=github
[docker-pulls-starboard]: https://img.shields.io/docker/pulls/aquasec/starboard?logo=docker&label=docker%20pulls%20%2F%20starboard
[docker-pulls-starboard-operator]: https://img.shields.io/docker/pulls/aquasec/starboard-operator?logo=docker&label=docker%20pulls%20%2F%20starboard%20operator
[aqua-starboard-blog]: https://blog.aquasec.com/starboard-kubernetes-tools
[discussions]: https://github.com/aquasecurity/starboard/discussions

[Custom Resource Definitions]: https://aquasecurity.github.io/starboard/latest/crds/
[Go module]: https://pkg.go.dev/github.com/aquasecurity/starboard/pkg
[cli]: https://aquasecurity.github.io/starboard/latest/cli
[Documentation]: https://aquasecurity.github.io/starboard/
[From the Binary Releases]: https://aquasecurity.github.io/starboard/latest/cli/installation/binary-releases/
[Getting Started]: https://aquasecurity.github.io/starboard/latest/cli/getting-started/
[Kubernetes operator]: https://aquasecurity.github.io/starboard/latest/operator

[Octant Plugin]: https://aquasecurity.github.io/starboard/latest/integrations/octant
[Lens Extension]: https://aquasecurity.github.io/starboard/latest/integrations/lens
[kubectl]: https://kubernetes.io/docs/reference/kubectl
