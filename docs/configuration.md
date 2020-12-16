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
kubectl patch configmap starboard -n starboard \
  --type merge \
  -p '{"data": {"trivy.severity":"HIGH,CRITICAL"}}'
```

To set the GitHub token used by Trivy in `Standalone` mode add the
`trivy.githubToken` value to the `starboard` secret instead:

```
GITHUB_TOKEN=<your token>
kubectl patch secret starboard -n starboard \
  --type merge \
  -p "{\"data\": {\"trivy.githubToken\":\"$(echo -n $GITHUB_TOKEN | base64)\"}}"
```

The following tables list available configuration parameters with their default
values.

| CONFIGMAP KEY         | DEFAULT                                                | DESCRIPTION |
| --------------------- | ------------------------------------------------------ | ----------- |
| `trivy.httpProxy`     | N/A                                                    | The HTTP proxy used by Trivy to download the vulnerabilities database from GitHub. Only applicable if Trivy runs in the `Standalone` mode. |
| `trivy.severity`      | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`                     | A comma separated list of severity levels reported by Trivy |
| `trivy.imageRef`      | `docker.io/aquasec/trivy:0.14.0`                       | Trivy image reference |
| `trivy.mode`          | `Standalone`                                           | Trivy client mode. Either `Standalone` or `ClientServer`. |
| `trivy.serverURL`     | `http://trivy-server.trivy-server:4954`                | The endpoint URL of the Trivy server. This parameter is required when Trivy runs in the `ClientServer` mode. |
| `polaris.config.yaml` | [Check the default value here][default-polaris-config] | Polaris configuration file |

| SECRET KEY          | DESCRIPTION |
| ------------------- | ----------- |
| `trivy.githubToken` | The GitHub personal access token used by Trivy to download the vulnerabilities database from GitHub. Only applicable if Trivy runs in the `Standalone` mode. |

> **NOTE** You can find it handy to delete a configuration key, which was not created by default by the
> `starboard init` command. For example, the following `kubectl patch` command deletes the `trivy.httpProxy` key:
>
>     kubectl patch configmap starboard -n starboard \
>       --type json \
>       -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'

[default-polaris-config]: https://raw.githubusercontent.com/aquasecurity/starboard/master/deploy/init/03-starboard.cm.yaml
