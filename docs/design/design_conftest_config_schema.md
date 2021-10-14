# Define Schema for Conftest Plugin

This is how we represent Rego policies as Conftest configuration object.

 ```yaml
 kind: ConfigMap
 apiVersion: v1
 metadata:
   namespace: starboard-system
   name: starboard-conftest-config
 data:
   conftest.imageRef: openpolicyagent/conftest:v0.25.0
   conftest.resources.requests.cpu: 50
   conftest.resources.requests.memory: 50M
   conftest.resources.limits.cpu: 300m
   conftest.resources.limits.memory: 300M

   conftest.policy.file_system_not_read_only.rego: "{REGO CODE}"
   conftest.policy.uses_image_tag_latest.rego: "{REGO CODE}"
   conftest.policy.configmap_with_sensitive_data.rego: "{REGO CODE}"
   conftest.policy.configmap_with_secret_data.rego: "{REGO CODE}"
   conftest.policy.service_with_external_ip.rego: "{REGO CODE}"
   conftest.policy.object_without_recommended_labels.rego: "{REGO CODE}"

   conftest.policy.kubernetes.rego: "{REGO CODE}"
   conftest.policy.utils.rego: "{REGO CODE}"
 ```

Structured configuration settings for Conftest plugin are flattened as key-value pairs and stored as data in the
`starboard-conftest-config` ConfigMap. This may be problematic in terms of validation and versioning. Therefore, we can
define a schema for all Conftest plugin config params and store the whole configuration object as YAML value under the
`config.yaml` key.

```yaml
kind: ConftestConfig
apiVersion: starboard.aquasecurity.github.io/v2
conftest:
  imageRef: openpolicyagent/conftest:v0.25.0
  resources:
    requests:
      cpu: 50m
      memory: 50M
    limits:
      cpu: 300m
      memory: 300M
  policy:
    - name: file_system_not_read_only
      code: "{REGO CODE}"
      kinds:
        - Pod
        - ReplicationController
        - ReplicaSet
        - StatefulSet
        - DaemonSet
        - Job
        - CronJob
    - name: uses_imag_tag_latest
      code: "{REGO CODE}"
      kinds:
        - Pod
        - ReplicationController
        - ReplicaSet
        - StatefulSet
        - DaemonSet
        - Job
        - CronJob
    - name: configmap_with_sensitive_data
      code: "{REGO CODE}"
      kinds:
        - ConfigMap
    - name: configmap_with_secret_data
      code: "{REGO CODE}"
      kinds:
        - ConfigMap
    - name: service_with_external_ip
      code: "{REGO CODE}"
      kinds:
        - Service
```

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  namespace: starboard-system
  name: starboard-conftest-config
  annotations:
    starboard.plugin.config.version: "v2"
data:
  config.yaml: |
    kind: ConftestConfig
    apiVersion: starboard.aquasecurity.github.io/v2
    conftest:
      imageRef: openpolicyagent/conftest:v0.25.0
      resources:
        requests:
          cpu: 50m
          memory: 50M
        limits:
          cpu: 300m
          memory: 300M
      policy:
        - name: file_system_not_read_only
          code: "{REGO CODE}"
          kinds:
            - Pod
            - ReplicationController
            - ReplicaSet
            - StatefulSet
            - DaemonSet
            - Job
            - CronJob
```
