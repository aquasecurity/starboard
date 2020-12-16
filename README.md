![Starboard logo](docs/images/starboard-logo.png)

> Kubernetes-native security tool kit.

[![GitHub Release][release-img]][release]
[![GitHub Build Actions][build-action-img]][actions]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls Starboard][docker-pulls-starboard]
![Docker Pulls Starboard Operator][docker-pulls-starboard-operator]

## Table of Contents

> **NOTE** We are in the process of creating the website that will contain
> all the information related to installation, configuration, and troubleshooting
> of Starboard. You can access an early preview at https://aquasecurity.github.io/starboard/

- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Next Steps](#next-steps)
- [Starboard CLI](#starboard-cli)
  - [Installation](#installation)
    - [From the Binary Releases](#from-the-binary-releases)
      - [As a kubectl plugin](#kubectl-plugin)
    - [From Source (Linux, macOS)](#from-source-linux-macos)
    - [Docker](#docker)
- [Starboard Operator](#starboard-operator)
  - [Deployment](#deployment)
    - [With Static YAML Manifests](https://aquasecurity.github.io/starboard/operator/#kubectl)
    - [With Helm](https://aquasecurity.github.io/starboard/operator/#helm)
    - [From OperatorHub.io or ArtifactHUB](#from-operatorhubio-or-artifacthub)
  - [Environment Variables](https://aquasecurity.github.io/starboard/operator/#configuration)
    - [Install Modes](https://aquasecurity.github.io/starboard/operator/#install-modes)
  - [Supported Vulnerability Scanners](#supported-vulnerability-scanners)
- [Configuration](https://aquasecurity.github.io/starboard/configuration/)
- [Custom Security Resources Definitions](#custom-security-resources-definitions)
- [Contributing](#contributing)
- [Troubleshooting](https://aquasecurity.github.io/starboard/troubleshooting/)

## Introduction

Starboard integrates security tools into the Kubernetes environment, so that users can find and view the risks that
relate to different resources in a Kubernetes-native way. Starboard provides
[custom security resources definitions][starboard-crds] and a [Go module][starboard-go-module] to work with a range
of existing security tools, as well as a `kubectl`-compatible command-line tool and an Octant plug-in that make security
reports available through familiar Kubernetes tools.

Starboard can be run in two different modes:

* As a [command-line tool][starboard-cli], so you can trigger scans and view the risks in a `kubectl`-compatible way
  or as part of your CI/CD pipeline.
* As an [operator][starboard-operator] to automatically update security report resources in response to workload and
  other changes on a Kubernetes cluster - for example, initiating a vulnerability scan when a new pod is started.

You can read more about the motivations and use cases [here][aqua-starboard-blog] and join our discussions [here][discussions]. 

![](docs/images/starboard-cli-with-octant-demo.gif)

## Getting Started

The easiest way to get started with Starboard is to use [Starboard CLI][starboard-cli], which allows scanning Kubernetes
workloads deployed in your cluster.

> **NOTE:** Even though manual scanning through the command-line is useful, the fact that it's not automated makes it less suitable with a large number
> of Kubernetes workloads. Therefore, the [Starboard Operator][starboard-operator]
> provides a better option for these scenarios, constantly monitoring built-in Kubernetes resources, such as Deployments,
> and running appropriate scanners against the underlying deployment descriptors.

To begin with, execute the following one-time setup command:

```
$ starboard init
```

The `init` subcommand creates the `starboard` namespace, in which Starboard executes Kubernetes Jobs to perform
scans. It also sends custom security resources definitions to the Kubernetes API:

```
$ kubectl api-resources --api-group aquasecurity.github.io
NAME                   SHORTNAMES    APIGROUP                 NAMESPACED   KIND
ciskubebenchreports    kubebench     aquasecurity.github.io   false        CISKubeBenchReport
configauditreports     configaudit   aquasecurity.github.io   true         ConfigAuditReport
kubehunterreports      kubehunter    aquasecurity.github.io   false        KubeHunterReport
vulnerabilityreports   vulns,vuln    aquasecurity.github.io   true         VulnerabilityReport
```

> There's also a `starboard cleanup` subcommand, which can be used to remove all resources created by Starboard.

As an example let's run an old version of `nginx` that we know has vulnerabilities. First, let's create a `dev` namespace:

```
$ kubectl create namespace dev
```

Create an `nginx` Deployment in the `dev` namespace:

```
$ kubectl create deployment nginx --image nginx:1.16 --namespace dev
```

Run the scanner to find the vulnerabilities:

```
$ starboard find vulnerabilities deployment/nginx --namespace dev
```

Behind the scenes, this uses [Trivy][trivy] to identify vulnerabilities in the container images associated with the
specified deployment. Once this has been done, you can retrieve the latest vulnerability reports for this workload:

```
$ starboard get vulnerabilities deployment/nginx \
  --namespace dev \
  --output yaml
```

Starboard relies on labels and label selectors to associate vulnerability reports with the specified Deployment.
For a Deployment with *N* container images Starboard creates *N* instances of `vulnerabilityreports.aquasecurity.github.io`
resources. In addition, each instance has the `starboard.container.name` label to associate it with a particular
container's image. This means that the same data retrieved by the `starboard get vulnerabilities` subcommand can be
fetched with the standard `kubectl get` command:

```
$ kubectl get vulnerabilityreport \
  --selector starboard.resource.kind=Deployment,starboard.resource.name=nginx \
  --namespace dev \
  --output yaml
```

In this example, the `nginx` deployment has a single container called `nginx`, hence only one instance of the
`vulnerabilityreports.aquasecurity.github.io` resource is created with the label `starboard.container.name=nginx`.

To read more about custom resources and label selectors check [Custom Security Resources Specification][starboard-crds-spec].

The [Starboard Octant plugin][starboard-octant-plugin] displays the same vulnerability reports in Octant's UI.

<p align="center">
  <img src="docs/images/getting-started/deployment_vulnerabilities.png">
</p>

Check the plugin's repository for installation instructions.

## Next Steps

Let's take the same `nginx` Deployment and audit its Kubernetes configuration. As you remember we've created it with
the `kubectl create deployment` command which applies the default settings to the deployment descriptors. However, we
also know that in Kubernetes the defaults are usually the least secure.

Run the scanner to audit the configuration using [Polaris][polaris]:

```
$ starboard polaris deployment/nginx --namespace dev
```

Retrieve the configuration audit report:

```
$ starboard get configaudit deployment/nginx \
  --namespace dev \
  --output yaml
```

or

```
$ kubectl get configauditreport \
  --selector starboard.resource.kind=Deployment,starboard.resource.name=nginx \
  --namespace dev \
  --output yaml
```

Similar to vulnerabilities the Starboard Octant plugin can visualize config audit reports. What's more important,
Starboard and Octant provide a single pane view with visibility into potentially dangerous and exploitable
vulnerabilities as well as configuration issues that might affect stability, reliability, and scalability of the
`nginx` Deployment.

<p align="center">
  <img src="docs/images/next-steps/deployment_configauditreports.png">
</p>

To learn more about the available Starboard commands and scanners, such as [kube-bench][aqua-kube-bench] or
[kube-hunter][aqua-kube-hunter], use `starboard help`.



## Starboard CLI

Starboard CLI is a single executable binary which can be used to find risks, such as vulnerabilities or insecure Pod
specs, in Kubernetes workloads. By default, the risk assessment reports are stored as
[custom security resources][starboard-crds].

To learn more about the available Starboard CLI commands, run `starboard help` or type a command followed by the
`-h` flag:

```
$ starboard kube-hunter -h
```

### Installation

This guide shows how to install the [Starboard CLI][starboard-cli] from source,
or from pre-built binary releases.

#### From the Binary Releases

Every [release][release] of Starboard provides binary releases for a variety of operating systems. These
binary versions can be manually downloaded and installed.

1. Download your [desired version][release]
2. Unpack it (`tar -zxvf starboard_darwin_x86_64.tar.gz`)
3. Find the `starboard` binary in the unpacked directory, and move it to its desired destination
   (`mv starboard_darwin_x86_64/starboard /usr/local/bin/starboard`)

From there, you should be able to run Starboard CLI commands: `starboard help`

##### kubectl plugin

The Starboard CLI is compatible with [kubectl][kubectl] and is intended as [kubectl plugin][kubectl-plugins],
but it's perfectly fine to run it as a stand-alone executable. If you rename the `starboard` executable to
`kubectl-starboard` and if it's in your path, you can invoke it using `kubectl starboard`.

You can also install Starboard as a kubectl plugin with the [Krew][krew] plugins manager:

```
$ kubectl krew install starboard
$ kubectl starboard help
```

#### From Source (Linux, macOS)

Building from source is slightly more work, but is the best way to go if you want to test the latest (pre-release)
version of Starboard.

You must have a working Go environment.

```
$ git clone git@github.com:aquasecurity/starboard.git
$ cd starboard
$ make
```

If required, it will fetch the dependencies and cache them. It will then compile `starboard` and place it in
`bin/starboard`.

#### Docker

We also release the Docker image `aquasec/starboard:$VERSION` to run Starboard as a Docker container or to
manually schedule Kubernetes scan Jobs in your cluster.

```
$ docker container run --rm aquasec/starboard:0.4.0 version
Starboard Version: {Version:0.4.0 Commit:dd8e49701c1817ea174061c8731fe5bdbfb73d93 Date:2020-09-21T09:36:59Z}
```

## Starboard Operator

This operator automatically updates security report resources in response to workload and other changes on a Kubernetes
cluster - for example, initiating a vulnerability scan when a new pod is started. In other words, the desired state
for this operator is that for each workload there are security reports stored in the cluster as custom resources.

Currently, the operator implements two reconciliation loops and only supports [vulnerabilityreports][vulnerabilityreports-crd]
security resources as depicted below. However, we plan to support all [custom security resources][starboard-crds].

| Controller | Description |
| ---------- | ----------- |
| [PodController](pkg/operator/controller/pod/pod_controller.go) | Watches for pod events in target namespaces to lookup the immediate owner of a pod. Then it checks whether there's the VulnerabilityReport owned by this owner. If not, it schedules a scan job in the operator's namespace. |
| [JobController](pkg/operator/controller/job/job_controller.go) | Watches for job events in the operator's namespace. If a given job is completed it parses the logs of the controlee pod and converts the logs output to an instance of the VulnerabilityReport resource. |

![](docs/images/operator/starboard-operator.png)

### Deployment

#### From OperatorHub.io or ArtifactHUB

The [Operator Lifecycle Manager (OLM)][olm] provides a declarative way to install and upgrade operators and their
dependencies.

You can install the Starboard operator from [OperatorHub.io](https://operatorhub.io/operator/starboard-operator)
or [ArtifactHUB](https://artifacthub.io/) by creating an optional OperatorGroup, which defines the operator's
multitenancy, and Subscription that links everything together to run the operator's pod.

1. Install the Operator Lifecycle Manager:

   ```
   $ curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/0.16.1/install.sh | bash -s 0.16.1
   ```
2. Create the namespace to install the operator in:

   ```
   $ kubectl create ns starboard-operator
   ```
3. Declare the target namespaces by creating the OperatorGroup:

   ```
   cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1alpha2
   kind: OperatorGroup
   metadata:
     name: starboard-operator
     namespace: starboard-operator
   spec:
     targetNamespaces:
     - foo
     - bar
   EOF
   ```
4. Install the operator by creating the Subscription:

   ```
   cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1alpha1
   kind: Subscription
   metadata:
     name: starboard-operator
     namespace: starboard-operator
   spec:
     channel: alpha
     name: starboard-operator
     source: operatorhubio-catalog
     sourceNamespace: olm
   EOF
   ```

   The operator will be installed in the `starboard-operator` namespace and will be usable from `foo` and `bar`
   namespaces.
5. After install, watch the operator come up using the following command:

   ```
   $ kubectl get csv -n starboard-operator
   NAME                        DISPLAY              VERSION   REPLACES   PHASE
   starboard-operator.v0.6.0   Starboard Operator   0.6.0                Succeeded
   ```

### Supported Vulnerability Scanners

To enable Aqua as vulnerability scanner set the value of the `OPERATOR_SCANNER_AQUA_CSP_ENABLED` to `true` and
disable the default Trivy scanner by setting `OPERATOR_SCANNER_TRIVY_ENABLED` to `false`.

To configure the Aqua scanner create the `starboard-operator` secret in the `operators` namespace:

```
$ kubectl create secret generic starboard-operator \
 --namespace $OPERATOR_NAMESPACE \
 --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
 --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
 --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
 --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
```

## Custom Security Resources Definitions

This project houses CustomResourceDefinitions (CRDs) related to security and compliance checks along with the code
generated by Kubernetes [code generators][k8s-code-generator] to write such custom resources in a natural way.

| NAME                                             | SHORTNAMES   | APIGROUP               | NAMESPACED |  KIND               |
| ------------------------------------------------ | ------------ | ---------------------- | ---------- | ------------------- |
| [vulnerabilityreports][vulnerabilityreports-crd] | vulns,vuln   | aquasecurity.github.io | true       | VulnerabilityReport |
| [configauditreports][configauditreports-crd]     | configaudit  | aquasecurity.github.io | true       | ConfigAuditReport   |
| [ciskubebenchreports][ciskubebenchreports-crd]   | kubebench    | aquasecurity.github.io | false      | CISKubeBenchReport  |
| [kubehunterreports][kubehunterreports-crd]       | kubehunter   | aquasecurity.github.io | false      | KubeHunterReport    |

See [Custom Security Resources Specification][starboard-crds-spec] for the detailed explanation of custom resources
used by Starboard and their lifecycle.

## Contributing

At this early stage we would love your feedback on the overall concept of Starboard. Over time we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

* See [CONTRIBUTING.md](CONTRIBUTING.md) for information about setting up your development environment, and the
  contribution workflow that we expect.
* See [ROADMAP.md](ROADMAP.md) for tentative features in a 1.0 release.
* Join our [discussions][discussions].

[release-img]: https://img.shields.io/github/release/aquasecurity/starboard.svg?logo=github
[release]: https://github.com/aquasecurity/starboard/releases
[build-action-img]: https://github.com/aquasecurity/starboard/workflows/build/badge.svg
[actions]: https://github.com/aquasecurity/starboard/actions
[cov-img]: https://codecov.io/github/aquasecurity/starboard/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/starboard
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/starboard
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/starboard
[license-img]: https://img.shields.io/github/license/aquasecurity/starboard.svg
[license]: https://github.com/aquasecurity/starboard/blob/master/LICENSE
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/starboard/total?logo=github
[docker-pulls-starboard]: https://img.shields.io/docker/pulls/aquasec/starboard?logo=docker&label=docker%20pulls%20%2F%20starboard
[docker-pulls-starboard-operator]: https://img.shields.io/docker/pulls/aquasec/starboard-operator?logo=docker&label=docker%20pulls%20%2F%20starboard%20operator

[aqua-starboard-blog]: https://blog.aquasec.com/starboard-kubernetes-tools
[discussions]: https://github.com/aquasecurity/starboard/discussions
[starboard-crds]: #custom-security-resources-definitions
[starboard-crds-spec]: ./SECURITY_CRDS_SPEC.md
[vulnerabilityreports-crd]: ./deploy/crd/vulnerabilityreports.crd.yaml
[ciskubebenchreports-crd]: ./deploy/crd/ciskubebenchreports.crd.yaml
[kubehunterreports-crd]: ./deploy/crd/kubehunterreports.crd.yaml
[configauditreports-crd]: ./deploy/crd/configauditreports.crd.yaml
[starboard-go-module]: ./pkg
[starboard-cli]: #starboard-cli
[starboard-operator]: #starboard-operator
[starboard-octant-plugin]: https://github.com/aquasecurity/octant-starboard-plugin
[aqua-kube-bench]: https://github.com/aquasecurity/kube-bench
[aqua-kube-hunter]: https://github.com/aquasecurity/kube-hunter
[octant]: https://github.com/vmware-tanzu/octant
[polaris]: https://github.com/FairwindsOps/polaris
[trivy]: https://github.com/aquasecurity/trivy

[k8s-code-generator]: https://github.com/kubernetes/code-generator
[kubectl]: https://kubernetes.io/docs/reference/kubectl
[kubectl-plugins]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins

[krew]: https://github.com/kubernetes-sigs/krew
[helm]: https://helm.sh/
[helm-charts]: https://helm.sh/docs/topics/charts/
[olm]: https://github.com/operator-framework/operator-lifecycle-manager/

[default-polaris-config]: ./deploy/init/03-starboard.cm.yaml
