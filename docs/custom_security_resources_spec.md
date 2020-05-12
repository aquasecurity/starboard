# Aqua Security Starboard

## Custom Security Resources Specification

[Custom resources][k8s-custom-resources] (CR) is one of the central extension mechanisms used throughout the Kubernetes 
ecosystem. Custom resources can be used for small, in-house configuration or data objects without any corresponding
controller logic. But they may also play a central role in projects built on top of Kubernetes that want to offer
a Kubernetes-native API experience.

This specification defines custom resources related to security and compliance checks.

The goal of this specification is to enable the creation of interoperable security tools and standardize how such tools
produce and consume security and compliance reports in Kubernetes-native way.

### Table of Contents

- [Scope](#scope)
- [ciskubebenchreports.aquasecurity.github.com](#ciskubebenchreportsaquasecuritygithubcom)

## Scope

This specification covers ...

This specification includes the following features ...

### ciskubebenchreports.aquasecurity.github.com

The [ciskubebenchreports][crd-ciskubebenchreports] is a cluster-scoped resource that represents the output of running
the checks documented in the [CIS Kubernetes Benchmark][cis-kubernetes-benchmark] on a cluster [Node][k8s-nodes].

To take advantage of Kubernetes [garbage collection][k8s-garbage-collection], each instance of the ciskubebenchreports
resource has the reference to the owning Node set as the value of the `ownerReferences` property. It guarantees that
whenever a Node is removed from the cluster, the corresponding ciskubebenchreports are garbage collected.

```yaml
apiVersion: aquasecurity.github.com/v1alpha1
kind: CISKubeBenchReport
metadata:
  name: minikube-958bb5864
  ownerReferences:
    - apiVersion: v1
      kind: Node
      name: minikube
      controller: false
      uid: d9607e19-f88f-11e6-a518-42010a800195
  labels:
    starboard.resource.kind: Node
    starboard.resource.name: minikube
    starboard.scanner: kube-bench
    starboard.vendor: aqua
    starboard.latest: true
  annotations:
    starboard.historyLimit: "10"
report:
  generatedAt: "2020-05-12T08:19:47Z"
  scanner:
    name: kube-bench
    vendor: Aqua Security
    version: latest
    spec:
    - name: "kube-bench.command"
      value: "kube-bench --benchmark cis-1.5 run --targets master,node,etcd,policies"
  sections:
  - id: "1"
    node_type: master
    tests:
    - desc: 'Master Node Configuration Files '
      fail: 2
      info: 0
      pass: 14
      results:
      - remediation: |
          Run the below command (based on the file location on your system) on the
          master node.
          For example, chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml
        scored: true
        status: PASS
        test_desc: Ensure that the API server pod specification file permissions are
          set to 644 or more restrictive (Scored)
        test_number: 1.1.1
...
```

Typically, there's 0 to many instances of ciskubebenchreports for a given Node. Each instance is named as
`$(nodeName)-$(reportContentHash)`, where the `reportContentHash` is the content hash calculated from the payload of the
`report` property. Each instance is labeled with the standard labels as shown in the listing below:

```
$ kubectl get ciskubebenchreports.aquasecurity.github.com \
    -L starboard.resource.kind \
    -L starboard.resource.name \
    -L starboard.latest \
    -L starboard.scanner \
    -L starboard.vendor \
    --sort-by '.metadata.creationTimestamp'
NAME                AGE   STARBOARD.RESOURCE.KIND  STARBOARD.RESOURCE.NAME  STARBOARD.LATEST  STARBOARD.SCANNER  STARBOARD.VENDOR
minikube-fd4d44c68  9m    Node                     minikube                                   kube-bench         aqua
minikube-958bb5864  3m3s  Node                     minikube                 true              kube-bench         aqua
```

[k8s-custom-resources]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources
[k8s-nodes]: https://kubernetes.io/docs/concepts/architecture/nodes
[k8s-garbage-collection]: https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection

[crd-ciskubebenchreports]: ../kube/crd/ciskubernetesbenchmarks-crd.yaml
[cis-kubernetes-benchmark]: https://www.cisecurity.org/benchmark/kubernetes
