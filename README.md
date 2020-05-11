[![License][license-img]][license]

# Starboard

Kubernetes-native security tool kit.

## Table of Contents

- [Abstract](#abstract)
- [Rationale](#rationale)
- [Use Cases](#use-cases)
  - [Security Tool Kit for Development and DevOps Teams](#security-tool-kit-for-development-and-devops-teams)
  - [Security Tool Kit for Enterprises](#security-tool-kit-for-enterprises)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

## Abstract

Starboard is a Kubernetes-native security tool kit for finding risks in your Kubernetes workloads and environments.
It provides [custom security resources definitions][starboard-crds] and the [Go module][starboard-go-module] to work
alongside a range of existing security tools, allowing for use cases such as these:

- Develop Kubernetes-native security applications such as:
  - admission webhook servers (like [Anchore Image Validator][anchore-image-validator]
    and [Starboard Admission Webhook][starboard-admission-webhook])
  - container security operators (like [Container Security Operator][container-security-operator]
    and [Starboard Security Operator][starboard-security-operator])
  - vulnerability adapters and exporters (like [KubeTrivyExporter][kube-trivy-exporter])
  - Kubernetes audit tools (like [kubeaudit][kubeaudit] and [Polaris][polaris])
  - Kubernetes resources sanitizers and linters (like [Popeye][popeye])
  - [kubectl plugins][kubectl-plugins] to scan workloads early on in the development stage
    (like [kubectl starboard][kubectl-starboard] plugin)
  - webhook servers for integrating with enterprise cloud native artifacts registries
    (like [Starboard Harbor Webhook][starboard-harbor-webhook])
  - webhook servers for integrating with commercial cloud native security platforms
    (like [Starboard Aqua CSP Webhook][starboard-aqua-csp-webhook])
- Extend existing Kubernetes dashboards, such as [Octant][octant] or [OpenShift Console][openshift-console], with
  vulnerability assessment reports
- Implement scoring, health check, and metrics systems for the whole Kubernetes cluster or a single namespace,
  aggregating results from different tools to simplify overall security assessments
- Implement custom security dashboards from scratch

## Rationale

By looking at existing Kubernetes security tools you can quickly realize two things. On one hand they differ in many
ways, i.e. have different capabilities, data models, output sinks, license, maturity level and credibility.
On the other hand, they usually have the same or very similar modus operandi, i.e.:

1. Discover Kubernetes workloads via Kubernetes API or by parsing descriptor YAML files
2. Invoke some type of scanner which finds risks, e.g. execute a [Trivy][trivy] binary executable to find container
   image vulnerabilities, invoke a Go function to check SecurityContext of a given Pod, or evaluate a Pod spec against
   some [Rego][opa-rego] rules.
3. Save risk assessment report somewhere, typically to the standard output or a file. JSON/YAML with a free-style schema
   seems to be an "industry" standard.

It's not easy to deal with the results from these different, standalone Kubernetes security tools. 
With all these heterogeneous data models it's very hard to take advantage of all the features provided by a given tool.
Especially when you want to use a few or all of them.

What if all the Kubernetes security tools spoke the same language that everyone knows and understands?
Similarly to the standardized and well known Pod spec, we could come up with the schema for a *vulnerability*,
a *risk assessment check*, a *black-* or *white-listed vulnerability*, or maybe even a *scanner config*. What if you
could combine the results from different tools to give an easy-to-understand overview of current security status? 
This would allow security vendors to focus on what they do best, whereas others could consume the data in the
homogeneous format.

Project Starboard illustrates how the outputs from different security tools can be stored and combined using native
Kubernetes approaches: 

* Storing results in Kubernetes CRDs that can be queried using the Kubernetes API
* Using Kubernetes Operators to efficiently manage security assessments of different resources within the cluster
* Using Kubernetes Operators to aggregate results, using flexible policies, into Kubernetes-native CRDs 

## Use Cases

### Security Tool Kit for Development and DevOps Teams

One idea behind Starboard is to help development and DevOps teams deliver secure and compliant applications from the
get-go. As shown in the figure below, Dave Loper is using [`kubectl`][kubectl] to deploy and test his applications.
Without learning the whole new tool, he can now use a familiar [`kubectl starboard`][kubectl-starboard] plugin interface
to scan container images, which comprise his applications, for potentially dangerous and exploitable vulnerabilities. He
can also look for configuration issues that might affect stability, reliability, and scalability of his deployment. This
makes Dave Loper a new security guard of his organization. What's more, by doing that his organization effectively
implemented the shift left security principle in SDLC.

Sometimes, to better understand the complexity of his applications, Dave is using [Octant][octant], a Kubernetes
introspective and object management platform. With [Starboard Octant plugin][starboard-octant-plugin] we extended the
Octant's capabilities to present vulnerability and configuration audits in user-friendly manner.

![](./docs/images/starboard-for-devops.png)

### Security Tool Kit for Enterprises

Manual scanning through the [`kubectl starboard`][kubectl-starboard] plugin is useful, but it has its limitations:  it doesn't scale well with a huge number of Kubernetes workloads and / or
multi-tenant clusters as is the case for enterprises.

In such cases a more suitable option is to deploy the [Starboard Security Operator][starboard-security-operator], which
constantly monitors Kubernetes-native resources, such as Deployments, and runs appropriate scanners against the
underlying deployment descriptors. The scan reports can be saved as custom resources in the same instance of
[etcd][etcd] used by the Kubernetes cluster running the workloads, or an etcd instance external to the cluster.

Because they are accessible over the Kubernetes API, the vulnerability reports or any other security audits can be used to build or integrate with dashboards tailored for
SRE and Security teams.

The same data can be used by the [Starboard Admission Webhook][starboard-admission-webhook] to accept or reject new
deployments based on security policies put in place, e.g. number of critical vulnerabilities found in a container
image.

Another interesting scenario would be to take advantage of [Starboard Harbor Webhook][starboard-harbor-webhook] or
[Starboard Aqua CSP Webhook][starboard-aqua-csp-webhook] components to import existing vulnerability reports generated
by Harbor or Aqua CSP respectively via Webhook integrations.

![](./docs/images/starboard-for-enterprises.png)

## Getting started

For those who're familiar with [`kubectl`][kubectl], the easiest way to get started is to use the
[`kubectl starboard`][kubectl-starboard] plugin, which allows you to scan any Kubernetes workload deployed in the cluster.
For example, you can find vulnerabilities in the Deployment named `booking-svc` in the `dev` namespace with the
following command:

```
$ kubectl starboard find vulnerabilities -n dev deployment/booking-svc
```

After that you can pull the vulnerabilities reports using the `kubectl get` command:

```
$ kubectl get vulnerabilities -n dev -o yaml \
    -l starboard.workload.kind=Deployment \
    -l starboard.workload.name=booking-svc
```

> **NOTE** The label selectors are used to find vulnerability reports for the specified Deployment.
> For Deployments with *N* containers Starboard creates *N* instances of `vulnerabilities.aquasecurity.github.com`
> resources. There's the `starboard.workload.container` label to associate the vulnerability report with a particular
> container image.

Additionally, you could check for other risks with:

```
$ kubectl starboard find risks -n dev deployments.apps/booking-svc
```

And get the corresponding report(s):

```
$ kubectl get risks -n dev -o yaml \
    -l starboard.workload.kind=Deployment \
    -l starboard.workload.name=booking-svc
```

## Contributing

At this early stage we would love your feedback on the overall concept of Starboard. Over time we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

## License

This repository is available under the [Apache License 2.0][license].

[license-img]: https://img.shields.io/github/license/aquasecurity/starboard.svg
[license]: https://github.com/aquasecurity/starboard/blob/master/LICENSE

[starboard-crds]: https://github.com/aquasecurity/starboard-crds
[starboard-go-module]: https://github.com/aquasecurity/kubectl-starboard/tree/master/pkg
[kubectl-starboard]: https://github.com/aquasecurity/kubectl-starboard/tree/master/cmd/kubectl-starboard
[starboard-octant-plugin]: https://github.com/aquasecurity/octant-starboard-plugin
[starboard-security-operator]: https://github.com/aquasecurity/starboard-security-operator
[starboard-admission-webhook]: https://github.com/aquasecurity/starboard-admission-webhook
[starboard-aqua-csp-webhook]: https://github.com/aquasecurity/starboard-aqua-csp-webhook
[starboard-harbor-webhook]: https://github.com/aquasecurity/starboard-harbor-webhook

[kubectl]: https://kubernetes.io/docs/reference/kubectl
[kubectl-plugins]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins
[security-context]: https://kubernetes.io/docs/tasks/configure-pod-container/security-context

[octant]: https://github.com/vmware-tanzu/octant
[anchore-image-validator]: https://github.com/banzaicloud/anchore-image-validator
[kube-trivy-exporter]: https://github.com/kaidotdev/kube-trivy-exporter
[container-security-operator]: https://github.com/quay/container-security-operator
[kubeaudit]: https://github.com/Shopify/kubeaudit
[openshift-console]: https://github.com/openshift/console
[popeye]: https://github.com/derailed/popeye
[polaris]: https://github.com/FairwindsOps/polaris
[etcd]: https://etcd.io
[trivy]: https://github.com/aquasecurity/trivy
[opa-rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
