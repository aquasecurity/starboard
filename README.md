![Starboard](./docs/images/starboard-logo.png)

[![License][license-img]][license]

# Starboard

Starboard is a Kubernetes-native security tool kit for finding risks in your Kubernetes workloads and environments. It provides [custom security resources definitions][k8s-security-crds]
and the [Go module][starboard-go-module] to work alongside a range of existing security tools, allowing for use cases such as these:

- Develop Kubernetes-native security applications such as:
  - admission webhook servers (like [Anchore Image Validator][anchore-image-validator])
  - container security operators (like [Container Security Operator][container-security-operator])
  - vulnerability adapters and exporters (like [KubeTrivyExporter][kube-trivy-exporter])
  - Kubernetes audit tools (like [kubeaudit][kubeaudit])
  - Kubernetes resources sanitizers and linters (like [Popeye][popeye])
  - [kubectl plugins][kubectl-plugins] to scan workloads early on in the development stage
    (like [kubectl starboard][kubectl-starboard] plugin)
- Extend existing Kubernetes dashboards, such as [Octant][octant] or [OpenShift Console][openshift-console], with
  vulnerability assessment reports
- Implement scoring, health check, and metrics systems for the whole Kubernetes cluster or a single namespace, aggregating results from different tools to simplify overall security assessments
- Implement custom security dashboards from scratch

## Rationale

By looking at existing Kubernetes security tools you can quickly realize two things. On one hand they differ in many
ways, i.e. have different capabilities, data models, output sinks, license, maturity level and credibility.
On the other hand, they usually have the same or very similar modus operandi, i.e.:

1. Discover Kubernetes workloads via Kubernetes API or by parsing descriptor YAML files
2. Invoke some type of scanner which finds risks, e.g. execute a Trivy binary executable to find container image
   vulnerabilities or invoke a Go function to check SecurityContext of a given Pod. More ambitious evaluate some
   Rego rules against Pod spec.
3. Save risk assessment report somewhere, typically to the standard output or a file. JSON/YAML with a free-style schema
   seems to be an "industry" standard.

It's not easy to deal with the results from these different, standalone Kubernetes security tools. 
With all these heterogeneous data models it's very hard to take advantage of all the features provided by a given tool.
Especially when you want to use a few or all of them.

What if all the Kubernetes security tools spoke the same language that everyone knows and understands?
Similarly to the standardized and well known Pod spec, we could come up with the schema for a *vulnerability*,
a *risk assessment check*, a *black-* or *white-listed vulnerability*, or maybe even a *scanner config*. What if you could combine the results from different tools to give an easy-to-understand overview of current security status? 
This would allow security vendors to focus on what they do best, whereas others could consume the data in the
homogeneous format.

Project Starboard illustrates how the outputs from different security tools can be stored and combined using native Kubernetes approaches: 
* Storing results in Kubernetes CRDs that can be queried using the Kubernetes API
* Using Kubernetes Operators to efficiently manage security assessments of different resources within the cluster
* Using Kubernetes Operators to aggregate results, using flexible policies, into Kubernetes-native CRDs 

## Getting started

For those who're familiar with `kubectl`, the easiest way to get started is to use the starboard plugin, which allows you to
scan any Kubernetes workload deployed in the cluster. For, example you can find vulnerabilities in the
Deployment named `booking-svc` in the `dev` namespace with the following command:

```
$ kubectl starboard find vulnerabilities -n dev deployments.apps/booking-svc
```

With the that you can pull the vulnerabilities report(s) using kubectl get command and label selectors:

```
$ kubectl get vulnerabilities -n dev -o yaml \
    -l starboard.workload.kind=Deployment \
    -l starboard.workload.name=booking-svc
```

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

We'd love to see contributions such as security companies especially when it comes to standardizing custom security resources.

## License

This repository is available under the [Apache License 2.0][license].

[license-img]: https://img.shields.io/github/license/aquasecurity/starboard.svg
[license]: https://github.com/aquasecurity/starboard/blob/master/LICENSE
[k8s-security-crds]: https://github.com/aquasecurity/k8s-security-crds
[starboard-go-module]: https://github.com/aquasecurity/kubectl-starboard/tree/master/pkg
[kubectl-starboard]: https://github.com/aquasecurity/kubectl-starboard/tree/master/cmd/kubectl-starboard
[starboard-octant-plugin]: https://github.com/aquasecurity/starboard-octant-plugin
[octant]: https://github.com/vmware-tanzu/octant
[anchore-image-validator]: https://github.com/banzaicloud/anchore-image-validator
[kube-trivy-exporter]: https://github.com/kaidotdev/kube-trivy-exporter
[container-security-operator]: https://github.com/quay/container-security-operator
[kubectl-plugins]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/
[kubeaudit]: https://github.com/Shopify/kubeaudit
[openshift-console]: https://github.com/openshift/console
[popeye]: https://github.com/derailed/popeye
