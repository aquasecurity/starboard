# Configuration

The `starboard init` command creates the `starboard` ConfigMap and the
`starboard` secret in the `starboard` namespace with default configuration
settings.

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

The following tables list available configuration parameters with their default
values.

> **NOTE** You only need to configure the settings for the scanner you are using (i.e. `trivy.*` parameters are
> used if `vulnerabilityReports.scanner` is set to `Trivy`). Check [integrations](./integrations.md) page to see
> example configuration settings for common use cases.

| CONFIGMAP KEY                  | DEFAULT                                                | DESCRIPTION |
| ------------------------------ | ------------------------------------------------------ | ----------- |
| `vulnerabilityReports.scanner` | `Trivy`                                                | The name of the scanner that generates vulnerability reports. Either `Trivy` or `Aqua`. |
| `trivy.httpProxy`              | N/A                                                    | The HTTP proxy used by Trivy to download the vulnerabilities database from GitHub. Only applicable in `Standalone` mode. |
| `trivy.severity`               | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`                     | A comma separated list of severity levels reported by Trivy |
| `trivy.imageRef`               | `docker.io/aquasec/trivy:0.14.0`                       | Trivy image reference |
| `trivy.mode`                   | `Standalone`                                           | Trivy client mode. Either `Standalone` or `ClientServer`. Depending on the active mode other settings might be applicable or required. |
| `trivy.serverURL`              | N/A                                                    | The endpoint URL of the Trivy server. Required in `ClientServer` mode. |
| `trivy.serverTokenHeader`      | `Trivy-Token`                                          | The name of the HTTP header to send the authentication token to Trivy server. Only application in `ClientServer` mode when `trivy.serverToken` is specified. |
| `aqua.imageRef`                | `docker.io/aquasec/scanner:5.3`                        | Aqua scanner image reference. The tag determines the version of the `scanner` binary executable and it must be compatible with version of Aqua console. |
| `aqua.serverURL`               | N/A                                                    | The endpoint URL of Aqua management console |
| `kube-bench.imageRef`          | `docker.io/aquasec/kube-bench:0.4.0`                   | kube-bench image reference |
| `kube-hunter.imageRef`         | `docker.io/aquasec/kube-hunter:0.4.0`                  | kube-hunter image reference |
| `kube-hunter.quick`            | `"false"`                                              | Whether to use kube-hunter's "quick" scanning mode (subnet 24). Set to `"true"` to enable. |
| `polaris.imageRef`             | `quay.io/fairwinds/polaris:3.0`                        | Polaris image reference |
| `polaris.config.yaml`          | [Check the default value here][default-polaris-config] | Polaris configuration file |

| SECRET KEY                  | DESCRIPTION |
| --------------------------- | ----------- |
| `trivy.githubToken`         | The GitHub access token used by Trivy to download the vulnerabilities database from GitHub. Only applicable in `Standalone` mode. |
| `trivy.serverToken`         | The token to authenticate Trivy client with Trivy server. Only applicable in `ClientServer` mode. |
| `trivy.serverCustomHeaders` | A comma-separated list of custom HTTP headers sent by Trivy client to Trivy server. Only applicable in `ClientServer` mode. |
| `aqua.username`             | Aqua management console username |
| `aqua.password`             | Aqua management console password |

> **NOTE** You can find it handy to delete a configuration key, which was not created by default by the
> `starboard init` command. For example, the following `kubectl patch` command deletes the `trivy.httpProxy` key:
>
>     kubectl patch cm starboard -n <starboard_operator> \
>       --type json \
>       -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'

[default-polaris-config]: https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/init/03-starboard.cm.yaml
