# ConfigAuditReport

An instance of the ConfigAuditReport represents checks performed by configuration auditing tools, such as [Polaris]
and [Conftest], against a Kubernetes object's configuration. For example, check that a given container image runs as
non-root user or that a container has resource requests and limits set. Checks might relate to Kubernetes workloads
and other namespaced Kubernetes objects such as Services, ConfigMaps, Roles, and RoleBindings.

Each report is owned by the underlying Kubernetes object and is stored in the same namespace, following the
`<workload-kind>-<workload-name>` naming convention.

The following listing shows a sample ConfigAuditReport associated with the ReplicaSet named `nginx-6d4cf56db6` in the
`default` namespace.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ConfigAuditReport
metadata:
  name: replicaset-nginx-6d4cf56db6
  namespace: default
  labels:
    starboard.resource.kind: ReplicaSet
    starboard.resource.name: nginx-6d4cf56db6
    starboard.resource.namespace: default
    plugin-config-hash: 7f65d98b75
    pod-spec-hash: 7cb64cb677
  uid: d5cf8847-c96d-4534-beb9-514a34230302
  ownerReferences:
    - apiVersion: apps/v1
      blockOwnerDeletion: false
      controller: true
      kind: ReplicaSet
      name: nginx-6d4cf56db6
      uid: aa345200-cf24-443a-8f11-ddb438ff8659
report:
  updateTimestamp: '2021-05-20T12:38:10Z'
  scanner:
    name: Polaris
    vendor: Fairwinds Ops
    version: '3.2'
  summary:
    dangerCount: 0
    passCount: 3
    warningCount: 2
  checks:
    - category: Security
      checkID: hostNetworkSet
      message: Host network is not configured
      severity: warning
      success: true
    - category: Security
      checkID: dangerousCapabilities
      message: Container does not have any dangerous capabilities
      severity: danger
      success: true
      scope:
        type: Container
        value: nginx
    - category: Security
      checkID: hostPortSet
      message: Host port is not configured
      severity: warning
      success: true
      scope:
        type: Container
        value: nginx
    - category: Security
      checkID: insecureCapabilities
      message: Container should not have insecure capabilities
      severity: warning
      success: false
      scope:
        type: Container
        value: nginx
    - category: Security
      checkID: notReadOnlyRootFilesystem
      message: Filesystem should be read only
      severity: warning
      success: false
      scope:
        type: Container
        value: nginx
```

Third party Kubernetes configuration checkers, linters, and sanitizers that are compliant with the ConfigAuditReport
schema can be integrated with Starboard.

!!! note
    The challenge with onboarding third party configuration checkers is that they tend to have different interfaces
    to perform scans and vary in output formats for a relatively common goal, which is inspecting deployment descriptors
    for known configuration pitfalls.

[Polaris]: ./../integrations/config-checkers/polaris.md
[Conftest]: ./../integrations/config-checkers/conftest.md