# Welcome to {{ config.site_name }}

Starboard integrates security tools into the Kubernetes environment, so that users can find and view the risks that
relate to different resources in a Kubernetes-native way. Starboard provides [Custom Resource Definitions] and a
[Go module] to work with a range of existing security scanners, as well as a [kubectl]-compatible command, the
[Octant Plugin], and the [Lens Extension] that make security reports available through familiar Kubernetes tools.

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

## What's Next?

- Follow the getting started guides for [Starboard CLI](./cli/getting-started.md) and [Starboard Operator](./operator/getting-started.md).
- Read more about the motivations and use cases on the [Starboard: The Kubernetes-Native Toolkit for Unifying Security][use-cases] blog.
- See a detailed introduction to Starboard with demos at [KubeCon + CloudNativeCon NA 2020][kubecon-video].
- Join our [discussions] on GitHub.

[Custom Resource Definitions]: ./crds/index.md
[cli]: cli/index.md
[Kubernetes operator]: operator/index.md
[Go module]: https://pkg.go.dev/github.com/aquasecurity/starboard@{{ var.tag }}
[Octant Plugin]: ./integrations/octant.md
[Lens Extension]: integrations/lens.md
[kubectl]: https://kubernetes.io/docs/reference/kubectl/
[use-cases]: https://blog.aquasec.com/starboard-kubernetes-tools
[discussions]: https://github.com/aquasecurity/starboard/discussions
[kubecon-video]: https://www.youtube.com/watch?v=cgcwIY1HVI0
[kube-hunter]: https://github.com/aquasecurity/kube-hunter