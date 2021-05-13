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
relate to different resources in a Kubernetes-native way. Starboard provides [custom resources definitions][crds]
and a [Go module][go-module] to work with a range of existing security scanners, as well as a [kubectl]-compatible
command, the [Octant plugin][octant-plugin], and the [Lens extension][lens-extension] that make security
reports available through familiar Kubernetes tools.

<p align="center">
<img src="docs/images/starboard-overview.png" alt="Starboard Overview"/>
</p>

Starboard can be run in two different modes:

- As a [command][cli], so you can trigger scans and view the risks in a kubectl-compatible way or as part of your CI/CD pipeline.
- As an [operator] to automatically update security reports in response to workload and other changes on a Kubernetes
  cluster - for example, initiating a vulnerability scan when a new pod is started.

> **NOTE** Even though manual scanning through the command-line is useful, the fact that it's not automated makes it
> less suitable with numerous Kubernetes workloads. Therefore, the [operator] provides a better option
> for these scenarios, constantly monitoring built-in Kubernetes resources, such as Deployments, and running appropriate
> scanners against the underlying deployment descriptors.

You can read more about the motivations and use cases in this [blog][aqua-starboard-blog] and join our [discussions][discussions].

![](docs/images/starboard-cli-with-octant-demo.gif)

# Status

This project is incubating and the APIs are not considered stable.

# Documentation

The official documentation, which provides detailed installation, configuration, and quick start guides, is available
at https://aquasecurity.github.io/starboard/.

Try the [getting started guide][cli-getting-started] to install the Starboard command and generate your first
vulnerability report.

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

[crds]: https://aquasecurity.github.io/starboard/latest/crds/
[go-module]: https://pkg.go.dev/github.com/aquasecurity/starboard/pkg
[cli]: https://aquasecurity.github.io/starboard/latest/cli
[cli-getting-started]: https://aquasecurity.github.io/starboard/latest/cli/getting-started/
[operator]: https://aquasecurity.github.io/starboard/latest/operator

[octant-plugin]: https://aquasecurity.github.io/starboard/latest/integrations/octant
[lens-extension]: https://aquasecurity.github.io/starboard/latest/integrations/lens
[kubectl]: https://kubernetes.io/docs/reference/kubectl
