# Starboard Operator

## Overview

This operator automatically updates security report resources in response to
workload and other changes on a Kubernetes cluster - for example, initiating
a vulnerability scan when a new pod is started. In other words, the desired
state for this operator is that for each workload there are security reports
stored in the cluster as custom resources.

Currently, the operator only supports vulnerabilityreports security resources
as depicted below. However, we plan to support all custom security resources.

![](images/operator/starboard-operator.png)

## Installation

### kubectl

You can install the operator with provided static YAML manifests with fixed
values. However, this approach has its shortcomings. For example, if you want to
change the container image or modify default configuration parameters, you have
to create new manifests or edit existing ones.

To deploy the operator in the `starboard-operator` namespace and configure it to
watch the `default` namespace:

1. Send the definition of the `vulnerabilityreports` custom resource to the
   Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/crd/vulnerabilityreports.crd.yaml

2. Send the following Kubernetes objects definitions to the Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/01-starboard-operator.ns.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/02-starboard-operator.sa.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/03-starboard-operator.clusterrole.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/04-starboard-operator.clusterrolebinding.yaml

3. (Optional) Configure the operator by creating the `starboard` ConfigMap in
   the `starboard-operator` namespace. If you skip this step, the operator will
   ensure the ConfigMap on startup with the default configuration values.

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/05-starboard-operator.cm.yaml
   Review the default values and makes sure the operator is configured properly:

        kubectl describe cm starboard -n starboard-operator

4. Finally, create the `starboard-operator` Deployment in the `starboard-operator`
   namespace to start the operator's pod:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/static/06-starboard-operator.deployment.yaml

To confirm that the operator is running, check the number of replicas created by
the `starboard-operator` Deployment in the `starboard-operator` namespace:

    kubectl get deployment -n starboard-operator

You should see the output similar to the following:

    NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
    starboard-operator   1/1     1            1           11m

If for some reason it's not ready yet, check the logs of the Deployment for
errors:

    kubectl logs -n starboard-operator deployment/starboard-operator

In case of any error consult our [Troubleshooting](troubleshooting.md) guidelines.

## Getting Started

Assuming that you installed the operator in the `starboard-operator` namespace,
and it's configured to discover Kubernetes workloads in the `default` namespace,
let's create the `nginx` Deployment that we know is vulnerable:

    kubectl create deployment nginx --image nginx:1.16

When the first pod controlled by the `nginx` Deployment is created, the operator
immediately detects that and creates the Kubernetes job in the
`starboard-operator` namespace to scan the `nignx` container's image (`nginx:1.16`)
for vulnerabilities.

    kubectl get job -n starboard-operator

In our case you should see only one job with a random name scheduled to scan
the `nginx` Deployment:

    NAME                                   COMPLETIONS   DURATION   AGE
    69516243-c782-4445-88b4-689ffbb3cdb7   0/1           68s        68s

If everything goes fine, the scan job is deleted, and the operator creates the
`vulnerabilityreports` resource in the `default` namespace that corresponds to
the `nginx` container:

    kubectl get vulnerabilityreports -o wide

Notice that the `vulnerabilityreports` instance is associated with the active
ReplicaSet of the `nginx` Deployment by name, and the set of labels.

    NAME                                REPOSITORY      TAG    SCANNER   AGE   CRITICAL   HIGH   MEDIUM   LOW   UNKNOWN
    replicaset-nginx-6d4cf56db6-nginx   library/nginx   1.16   Trivy     14m   1          35     16       85    2

You can get and describe `vulnerabilityreports` as any other built-in Kubernetes
object. For example, you can display the report as JSON object:

    kubectl get vulnerabilityreports replicaset-nginx-6d4cf56db6-nginx -o json

## Configuration

Configuration of the operator is done via environment variables at startup.

| NAME                                 | DEFAULT                | DESCRIPTION |
| ------------------------------------ | ---------------------- | ----------- |
| `OPERATOR_NAMESPACE`                 | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_TARGET_NAMESPACES`         | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_SCANNER_TRIVY_ENABLED`     | `true`                 | The flag to enable Trivy vulnerability scanner |
| `OPERATOR_SCANNER_AQUA_CSP_ENABLED`  | `false`                | The flag to enable Aqua vulnerability scanner |
| `OPERATOR_SCANNER_AQUA_CSP_IMAGE`    | `aquasec/scanner:5.0`  | The Docker image of Aqua scanner to be used |
| `OPERATOR_LOG_DEV_MODE`              | `false`                | The flag to use (or not use) development mode (more human-readable output, extra stack traces and logging information, etc). |
| `OPERATOR_SCAN_JOB_TIMEOUT`          | `5m`                   | The length of time to wait before giving up on a scan job |
| `OPERATOR_METRICS_BIND_ADDRESS`      | `:8080`                | The TCP address to bind to for serving [Prometheus][prometheus] metrics. It can be set to `0` to disable the metrics serving. |
| `OPERATOR_HEALTH_PROBE_BIND_ADDRESS` | `:9090`                | The TCP address to bind to for serving health probes, i.e. `/healthz/` and `/readyz/` endpoints. |

### Install Modes

The values of the `OPERATOR_NAMESPACE` and `OPERATOR_TARGET_NAMESPACES` determine
the install mode, which in turn determines the multitenancy support of the operator.

| MODE            | OPERATOR_NAMESPACE | OPERATOR_TARGET_NAMESPACES | DESCRIPTION |
| --------------- | ------------------ | -------------------------- | ----------- |
| OwnNamespace    | `operators`        | `operators`                | The operator can be configured to watch events in the namespace it is deployed in. |
| SingleNamespace | `operators`        | `foo`                      | The operator can be configured to watch for events in a single namespace that the operator is not deployed in. |
| MultiNamespace  | `operators`        | `foo,bar,baz`              | The operator can be configured to watch for events in more than one namespace. |
| AllNamespaces   | `operators`        |                            | The operator can be configured to watch for events in all namespaces. |
