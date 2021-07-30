# Starboard Settings

The Starboard CLI and Starboard Operator both read their configuration settings
from a ConfigMap, as well as a secret that holds confidential settings (such as
a GitHub token).

The `starboard init` command creates the `starboard` ConfigMap and the
`starboard` secret in the `starboard` namespace with default settings.

Similarly, the operator ensures the `starboard` ConfigMap and the `starboard`
secret in the `OPERATOR_NAMESPACE`.

You can change the default settings with `kubectl patch` or `kubectl edit`
commands.

For example, by default Trivy displays vulnerabilities with all severity levels
(`UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`). However, you can opt in to display only
`HIGH` and `CRITICAL` vulnerabilities by patching the `trivy.severity` value
in the `starboard` ConfigMap:

```
kubectl patch cm starboard -n <starboard_operator> \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.severity": "HIGH,CRITICAL"
  }
}
EOF
)"
```

To set the GitHub token used by Trivy in `Standalone` mode add the
`trivy.githubToken` value to the `starboard` secret instead:

```
GITHUB_TOKEN=<your token>

kubectl patch secret starboard -n <starboard_operator> \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.githubToken": "$(echo -n $GITHUB_TOKEN | base64)"
  }
}
EOF
)"
```

The following tables list available configuration settings with their default values.

!!! tip
    You only need to configure the settings for the scanner you are using (i.e. `trivy.*` parameters are
    used if `vulnerabilityReports.scanner` is set to `Trivy`). Check
    [integrations](./integrations/vulnerability-scanners/index.md) page to see example configuration settings for common use cases.

| CONFIGMAP KEY                        | DEFAULT                                                | DESCRIPTION |
| ------------------------------------ | ------------------------------------------------------ | ----------- |
| `vulnerabilityReports.scanner`       | `Trivy`                                                | The name of the plugin that generates vulnerability reports. Either `Trivy` or `Aqua`. |
| `configAuditReports.scanner`         | `Polaris`                                              | The name of the plugin that generates config audit reports. Either `Polaris` or `Conftest`. |
| `scanJob.tolerations`                | N/A                                                    | JSON representation of the [tolerations] to be applied to the scanner pods so that they can run on nodes with matching taints. Example: `'[{"key":"key1", "operator":"Equal", "value":"value1", "effect":"NoSchedule"}]'` |
| `scanJob.annotations`                | N/A                                                    | One-line comma-separated representation of the annotations which the user wants the scanner pods to be annotated with. Example: `foo=bar,env=stage` will annotate the scanner pods with the annotations `foo: bar` and `env: stage` |
| `kube-bench.imageRef`                | `docker.io/aquasec/kube-bench:0.6.3`                   | kube-bench image reference |
| `kube-hunter.imageRef`               | `docker.io/aquasec/kube-hunter:0.4.1`                  | kube-hunter image reference |
| `kube-hunter.quick`                  | `"false"`                                              | Whether to use kube-hunter's "quick" scanning mode (subnet 24). Set to `"true"` to enable. |
| `polaris.imageRef`                   | `quay.io/fairwinds/polaris:3.2`                        | Polaris image reference |
| `polaris.config.yaml`                | [Check the default value here][default-polaris-config] | Polaris configuration file |
| `polaris.resources.request.cpu`      | `50m`                                                  | The minimum amount of CPU required to run Polaris scanner pod. |
| `polaris.resources.request.memory`   | `50M`                                                  | The minimum amount of memory required to run Polaris scanner pod. |
| `polaris.resources.limit.cpu`        | `300m`                                                 | The maximum amount of CPU allowed to run Polaris scanner pod. |
| `polaris.resources.limit.memory`     | `300M`                                                 | The maximum amount of memory allowed to run polaris scanner pod. |
| `aqua.imageRef`                      | `docker.io/aquasec/scanner:5.3`                        | Aqua scanner image reference. The tag determines the version of the `scanner` binary executable and it must be compatible with version of Aqua console. |
| `aqua.serverURL`                     | N/A                                                    | The endpoint URL of Aqua management console |

| SECRET KEY                  | DESCRIPTION |
| --------------------------- | ----------- |
| `aqua.username`             | Aqua management console username |
| `aqua.password`             | Aqua management console password |

!!! tip
    You can find it handy to delete a configuration key, which was not created by default by the
    `starboard init` command. For example, the following `kubectl patch` command deletes the `trivy.httpProxy` key:
    ```
    kubectl patch cm starboard -n <starboard_operator> \
      --type json \
      -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
    ```

[default-polaris-config]: https://raw.githubusercontent.com/aquasecurity/starboard/{{ var.tag }}/deploy/static/05-starboard-operator.config.yaml
[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration