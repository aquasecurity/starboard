Configuration of the operator's pod is done via environment variables at startup.

| NAME                                        | DEFAULT                | DESCRIPTION |
| ------------------------------------------- | ---------------------- | ----------- |
| `OPERATOR_NAMESPACE`                        | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_TARGET_NAMESPACES`                | N/A                    | See [Install modes](#install-modes) |
| `OPERATOR_SERVICE_ACCOUNT`                  | `starboard-operator`   | The name of the service account assigned to the operator's pod |
| `OPERATOR_LOG_DEV_MODE`                     | `false`                | The flag to use (or not use) development mode (more human-readable output, extra stack traces and logging information, etc). |
| `OPERATOR_SCAN_JOB_TIMEOUT`                 | `5m`                   | The length of time to wait before giving up on a scan job |
| `OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT`       | `10`                   | The maximum number of scan jobs create by the operator |
| `OPERATOR_SCAN_JOB_RETRY_AFTER`             | `30s`                  | The duration to wait before retrying a failed scan job |
| `OPERATOR_METRICS_BIND_ADDRESS`             | `:8080`                | The TCP address to bind to for serving [Prometheus][prometheus] metrics. It can be set to `0` to disable the metrics serving. |
| `OPERATOR_HEALTH_PROBE_BIND_ADDRESS`        | `:9090`                | The TCP address to bind to for serving health probes, i.e. `/healthz/` and `/readyz/` endpoints. |
| `OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED` | `true`                 | The flag to enable CIS Kubernetes Benchmark reconciler |
| `OPERATOR_LEADER_ELECTION_ENABLED`          | `false`                | The flag to enable operator replica leader election |
| `OPERATOR_LEADER_ELECTION_ID`               | `starboard-operator`   | The name of the resource lock for leader election |

## Install Modes

The values of the `OPERATOR_NAMESPACE` and `OPERATOR_TARGET_NAMESPACES` determine
the install mode, which in turn determines the multitenancy support of the operator.

| MODE            | OPERATOR_NAMESPACE | OPERATOR_TARGET_NAMESPACES | DESCRIPTION |
| --------------- | ------------------ | -------------------------- | ----------- |
| OwnNamespace    | `operators`        | `operators`                | The operator can be configured to watch events in the namespace it is deployed in. |
| SingleNamespace | `operators`        | `foo`                      | The operator can be configured to watch for events in a single namespace that the operator is not deployed in. |
| MultiNamespace  | `operators`        | `foo,bar,baz`              | The operator can be configured to watch for events in more than one namespace. |
| AllNamespaces   | `operators`        | (blank string)             | The operator can be configured to watch for events in all namespaces. |

[prometheus]: https://github.com/prometheus
