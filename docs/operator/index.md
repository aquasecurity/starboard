# Overview

This operator automatically updates security report resources in response to
workload and other changes on a Kubernetes cluster - for example, initiating
a vulnerability scan and configuration audit when a new pod is started. In other
words, the desired state for this operator is that for each workload there are
security reports stored in the cluster as custom resources.

!!! warning
    Currently, the operator supports [vulnerabilityreports], [configauditreports],
    and [ciskubebenchreports] security resources. We plan also to support
    [kubehunterreports].

![](../images/operator/starboard-operator.png)

[vulnerabilityreports]: ./../crds.md#vulnerabilityreport
[configauditreports]: ./../crds.md#configauditreport
[ciskubebenchreports]: ./../crds.md#ciskubebenchreport
[kubehunterreports]: ./../crds.md#kubehunterreport
