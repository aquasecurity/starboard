# Welcome to {{ config.site_name }}

Starboard integrates security tools into the Kubernetes environment, so that
users can find and view the risks that relate to different resources in
a Kubernetes-native way. Starboard provides [custom resources definitions][crds]
and a [Go module][go-module] to work with a range of existing security scanners,
as well as a [kubectl]-compatible command, the [Octant plugin][octant-plugin],
and the [Lens extension][lens-extension] that make security reports available
through familiar Kubernetes tools.

Starboard can be run in two different modes:

- As a [command][cli], so you can trigger scans and view the risks in
  a kubectl-compatible way or as part of your CI/CD pipeline.
- As an [operator] to automatically update security reports in response
  to workload and other changes on a Kubernetes cluster - for example,
  initiating a vulnerability scan when a new pod is started.

!!! tip
    Even though manual scanning through the command-line is useful, the
    fact that it's not automated makes it less suitable with a large number
    of Kubernetes workloads. Therefore, the [operator] provides a better option
    for these scenarios, constantly monitoring built-in Kubernetes resources,
    such as Deployments, and running appropriate scanners against the underlying
    deployment descriptors.

You can read more about the motivations and use cases [here][use-cases] and join
our [discussions]. We also gave a detailed introduction to Starboard with demos
at [KubeCon + CloudNativeCon NA 2020][kubecon-video].

[crds]: crds.md
[cli]: cli/index.md
[operator]: operator/index.md
[go-module]: https://pkg.go.dev/github.com/aquasecurity/starboard/pkg
[octant-plugin]: integrations/octant.md
[lens-extension]: integrations/lens.md
[kubectl]: https://kubernetes.io/docs/reference/kubectl/
[use-cases]: https://blog.aquasec.com/starboard-kubernetes-tools
[discussions]: https://github.com/aquasecurity/starboard/discussions
[kubecon-video]: https://www.youtube.com/watch?v=cgcwIY1HVI0
