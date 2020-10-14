![Starboard logo](docs/images/starboard-logo.png)

> Kubernetes-native security tool kit.

[![GitHub Release][release-img]][release]
[![GitHub Build Actions][build-action-img]][actions]
[![GitHub Release Action][release-action-img]][actions]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls Starboard][docker-pulls-starboard]

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Next Steps](#next-steps)
- [Starboard CLI](#starboard-cli)
  - [Installation](#installation)
    - [From the Binary Releases](#from-the-binary-releases)
      - [As a kubectl plugin](#kubectl-plugin)
    - [From Source (Linux, macOS)](#from-source-linux-macos)
    - [Docker](#docker)
  - [Configuration](#configuration)
- [Starboard Operator](#starboard-operator)
  - [Deployment](#deployment)
    - [With Static YAML Manifests](#with-static-yaml-manifests)
    - [With Helm](#with-helm)
    - [From OperatorHub.io or ArtifactHUB](#from-operatorhubio-or-artifacthub)
  - [Environment Variables](#environment-variables)
  - [Install Modes](#install-modes)
  - [Supported Vulnerability Scanners](#supported-vulnerability-scanners)
- [Custom Security Resources Definitions](#custom-security-resources-definitions)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)

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

> **NOTE:** Even though manual scanning through the command-line is useful, it doesn't scale well with a huge number
> of Kubernetes workloads and / or multi-tenant clusters. Therefore, the [Starboard Operator][starboard-operator]
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

We also release the Docker image `docker.io/aqusec/starbaord` to run Starboard as a Docker container or to manually
schedule Kubernetes scan Jobs in your cluster.

```
$ docker container run --rm docker.io/aquasec/starboard:0.4.0 version
Starboard Version: {Version:0.4.0 Commit:dd8e49701c1817ea174061c8731fe5bdbfb73d93 Date:2020-09-21T09:36:59Z}
```

### Configuration

The `starboard init` command creates the `starboard` ConfigMap in the `starboard` namespace, which contains the default
configuration parameters. You can change the default config values with `kubectl patch` or `kubectl edit` commands.

For example, by default Trivy displays vulnerabilities with all severity levels (`UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`).
However, you can opt in to display only `HIGH` and `CRITICAL` vulnerabilities by patching the `trivy.severity` value
in the `starboard` ConfigMap:

```
$ kubectl patch configmap starboard -n starboard \
  --type merge \
  -p '{"data": {"trivy.severity":"HIGH,CRITICAL"}}'
```

The following table lists available configuration parameters.

| CONFIGMAP KEY         | DEFAULT                                                | DESCRIPTION |
| --------------------- | ------------------------------------------------------ | ----------- |
| `trivy.httpProxy`     | N/A                                                    | The HTTP proxy used by Trivy to download the vulnerabilities database from GitHub |
| `trivy.githubToken`   | N/A                                                    | The GitHub personal access token used by Trivy to download the vulnerabilities database from GitHub |
| `trivy.severity`      | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`                     | A comma separated list of severity levels reported by Trivy |
| `trivy.imageRef`      | `docker.io/aquasec/trivy:0.9.1`                        | Trivy image reference |
| `polaris.config.yaml` | [Check the default value here][default-polaris-config] | Polaris configuration file |

> **Note:** You can find it handy to delete a configuration key, which was not created by default by the
> `starboard init` command. For example, the following `kubectl patch` command deletes the `trivy.httpProxy` key:
>
> ```
> $ kubectl patch configmap starboard -n starboard \
>   --type json \
>   -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
> ```

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

#### With Static YAML Manifests

You can install the operator with provided static YAML manifests with fixed values. However, this approach has its
shortcomings. For example, if you want to change the container image or modify default configuration parameters, you
have to create new manifests or edit existing ones.

To deploy the operator in the `starboard-operator` namespace and configure it to watch the `default`
namespace:

1. Send the definition of the [vulnerabilityreports][vulnerabilityreports-crd] custom resource to the Kubernetes API:

   ```
   $ kubectl apply -f deploy/crd/vulnerabilityreports.crd.yaml
   ```
2. Send the following Kubernetes objects definitions to the Kubernetes API:

   ```
   $ kubectl apply -f deploy/static/01-starboard-operator.ns.yaml \
       -f deploy/static/02-starboard-operator.sa.yaml \
       -f deploy/static/03-starboard-operator.clusterrole.yaml \
       -f deploy/static/04-starboard-operator.clusterrolebinding.yaml
   ```
3. Create the `starboard-operator` deployment in the `starboard-operator` namespace to run the operator's container:

   ```
   $ kubectl apply -f deploy/static/05-starboard-operator.deployment.yaml
   ```

#### With Helm

[Helm][helm], which is de facto standard package manager for Kubernetes, allows installing applications from
parameterized YAML manifests called Helm [charts][helm-charts].

To address shortcomings of static YAML manifests we provide the Helm chart to deploy the Starboard operator. The
[starboard-operator](./deploy/helm) Helm chart supports all [install modes](#install-modes). For example, to install
the operator in the `starboard-operator` namespace and configure it to watch `foo` and `bar` namespaces, run:

```
$ helm install starboard-operator ./deploy/helm \
    -n starboard-operator \
    --create-namespace \
    --set="targetNamespaces=foo\,bar"
```

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

### Environment Variables

Configuration of the operator is done via environment variables at startup.

| NAME                                 | DEFAULT                | DESCRIPTION |
| ------------------------------------ | ---------------------- | ----------- |
| `OPERATOR_NAMESPACE`                 | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_TARGET_NAMESPACES`         | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_SCANNER_TRIVY_ENABLED`     | `true`                 | The flag to enable Trivy vulnerability scanner |
| `OPERATOR_SCANNER_TRIVY_VERSION`     | `0.11.0`               | The version of Trivy to be used |
| `OPERATOR_SCANNER_TRIVY_IMAGE`       | `aquasec/trivy:0.11.0` | The Docker image of Trivy to be used |
| `OPERATOR_SCANNER_AQUA_CSP_ENABLED`  | `false`                | The flag to enable Aqua vulnerability scanner |
| `OPERATOR_SCANNER_AQUA_CSP_VERSION`  | `5.0`                  | The version of Aqua scanner to be used |
| `OPERATOR_SCANNER_AQUA_CSP_IMAGE`    | `aquasec/scanner:5.0`  | The Docker image of Aqua scanner to be used |
| `OPERATOR_LOG_DEV_MODE`              | `false`                | The flag to use (or not use) development mode (more human-readable output, extra stack traces and logging information, etc). |
| `OPERATOR_SCAN_JOB_TIMEOUT`          | `5m`                   | The length of time to wait before giving up on a scan job |
| `OPERATOR_METRICS_BIND_ADDRESS`      | `:8080`                | The TCP address to bind to for serving [Prometheus][prometheus] metrics. It can be set to `0` to disable the metrics serving. |
| `OPERATOR_HEALTH_PROBE_BIND_ADDRESS` | `:9090`                | The TCP address to bind to for serving health probes, i.e. `/healthz/` and `/readyz/` endpoints. |

### Install Modes

The values of the `OPERATOR_NAMESPACE` and `OPERATOR_TARGET_NAMESPACES` determine the install mode,
which in turn determines the multitenancy support of the operator.

| MODE            | OPERATOR_NAMESPACE | OPERATOR_TARGET_NAMESPACES | DESCRIPTION |
| --------------- | ------------------ | -------------------------- | ----------- |
| OwnNamespace    | `operators`        | `operators`                | The operator can be configured to watch events in the namespace it is deployed in. |
| SingleNamespace | `operators`        | `foo`                      | The operator can be configured to watch for events in a single namespace that the operator is not deployed in. |
| MultiNamespace  | `operators`        | `foo,bar,baz`              | The operator can be configured to watch for events in more than one namespace. |
| AllNamespaces   | `operators`        |                            | The operator can be configured to watch for events in all namespaces. |

> **CAUTION:** Although we do support the *AllNamespaces* install mode, please use it with caution when your cluster
> runs a moderate or high number of workloads. If the desired state of the cluster is much different from the actual
> state, the operator might spin up too many scan jobs and negatively impact the performance of your cluster.
> We're planning improvements to limit the number of parallel scan jobs and implement a back pressure logic.
> See [#202](https://github.com/aquasecurity/starboard/issues/202) to check the progress on that.

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

## Troubleshooting

### "starboard" cannot be opened because the developer cannot be verified. (macOS)

Since Starboard CLI is not registered with Apple by an identified developer, if you try to run it for the first time
you might get a warning dialog. This doesn't mean that something is wrong with the release binary, rather macOS can't
check whether the binary has been modified or broken since it was released.

<p align="center">
  <img src="docs/images/troubleshooting/developer-not-verified.png">
</p>

To override your security settings and use the Starboard CLI anyway, follow these steps:

1. In the Finder on your Mac, locate the `starboard` binary.
2. Control-click the binary icon, then choose Open from the shortcut menu.
3. Click Open.

   <p align="center">
     <img src="docs/images/troubleshooting/control-click-open.png">
   </p>

   The `starboard` is saved as an exception to your security settings, and you can use it just as you can any registered
   app.

You can also grant an exception for a blocked Starboard release binary by clicking the Allow Anyway button in the
General pane of Security & Privacy preferences. This button is available for about an hour after you try to run the
Starboard CLI command.

To open this pane on your Mac, choose Apple menu > System Preferences, click Security & Privacy, then click General.

<p align="center">
  <img src="docs/images/troubleshooting/developer-not-verified-remediation.png">
</p>


[release-img]: https://img.shields.io/github/release/aquasecurity/starboard.svg?logo=github
[release]: https://github.com/aquasecurity/starboard/releases
[build-action-img]: https://github.com/aquasecurity/starboard/workflows/build/badge.svg
[release-action-img]: https://github.com/aquasecurity/starboard/workflows/release/badge.svg
[actions]: https://github.com/aquasecurity/starboard/actions
[cov-img]: https://codecov.io/github/aquasecurity/starboard/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/starboard
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/starboard
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/starboard
[license-img]: https://img.shields.io/github/license/aquasecurity/starboard.svg
[license]: https://github.com/aquasecurity/starboard/blob/master/LICENSE
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/starboard/total?logo=github
[docker-pulls-starboard]: https://img.shields.io/docker/pulls/aquasec/starboard?logo=docker&label=docker%20pulls%20%2F%20starboard

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
[prometheus]: https://github.com/prometheus

[k8s-code-generator]: https://github.com/kubernetes/code-generator
[kubectl]: https://kubernetes.io/docs/reference/kubectl
[kubectl-plugins]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins

[krew]: https://github.com/kubernetes-sigs/krew
[helm]: https://helm.sh/
[helm-charts]: https://helm.sh/docs/topics/charts/
[olm]: https://github.com/operator-framework/operator-lifecycle-manager/

[default-polaris-config]: ./deploy/init/03-starboard.cm.yaml
