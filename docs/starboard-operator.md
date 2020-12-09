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

### With Static YAML Manifests

You can install the operator with provided static YAML manifests with fixed
values. However, this approach has its shortcomings. For example, if you want to
change the container image or modify default configuration parameters, you have
to create new manifests or edit existing ones.

To deploy the operator in the `starboard-operator` namespace and configure it to
watch the `default` namespace:

1. Send the definition of the `vulnerabilityreports` custom resource to the
   Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/crd/vulnerabilityreports.crd.yaml

2. Send the following Kubernetes objects definitions to the Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/01-starboard-operator.ns.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/02-starboard-operator.sa.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/03-starboard-operator.clusterrole.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/04-starboard-operator.clusterrolebinding.yaml

3. (Optional) Configure the operator by creating the `starboard` ConfigMap in
   the `starboard-operator` namespace. If you skip this step, the operator will
   ensure the ConfigMap on startup with the default configuration values.

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/05-starboard-operator.cm.yaml
   Review the default values and makes sure the operator is configured properly:

        kubectl describe cm starboard -n starboard-operator

4. Finally, create the `starboard-operator` Deployment in the `starboard-operator`
   namespace to start the operator's pod:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/v0.7.1/deploy/static/06-starboard-operator.deployment.yaml
