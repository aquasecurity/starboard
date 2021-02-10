# Overview

This operator automatically updates security report resources in response to
workload and other changes on a Kubernetes cluster - for example, initiating
a vulnerability scan and configuration audit when a new pod is started. In other
words, the desired state for this operator is that for each workload there are
security reports stored in the cluster as custom resources.

!!! warning
    Currently, the operator only supports [vulnerabilityreports] and
    [configauditreports] security resources as depicted below. However, we plan
    to support all [custom security resources][crds].

![](../images/operator/starboard-operator.png)

[vulnerabilityreports]: ./../crds.md#vulnerabilityreport
[configauditreports]: ./../crds.md#configauditreport
[crds]: ./../crds.md
