# Conftest

[Conftest] helps you write tests against structured configuration data. Using Conftest you can write tests for your
Kubernetes configuration. Conftest uses the Rego language from [Open Policy Agent][OPA] for writing the assertions.

Here's a simple policy that checks whether a given container runs as root:

```opa
package main

deny[res] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"
  
  res := {
    "msg": msg,
    "title": "Runs as root user"
  }
}
```

To integrate Conftest scanner change the value of the `configAuditReports.scanner` property to `Conftest`:

```
kubectl patch cm starboard -n <starboard_namespace> \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "configAuditReports.scanner": "Conftest"
  }
}
EOF
)"
```

!!! warning
    Starboard does not ship with any default policies that can be used with Conftest plugin, therefore you have to add
    them manually.

In the following example, we'll use OPA polices provided by the [AppShield] project.

Start by cloning the AppShield repository and changing the current directory to the cloned repository:

```
git clone https://github.com/aquasecurity/appshield
cd appshield
```

Most of the Kubernetes policies defined by the AppShield project refer to OPA libraries called [kubernetes.rego]
and [utils.rego]. You must add such libraries to the `starboard-conftest-config` ConfigMap along with the actual
policies.

As an example, let's create the `starboard-conftest-config` ConfigMap with [file_system_not_read_only.rego] and
[uses_image_tag_latest.rego] policies. Those two are very common checks performed by many other tools:

```
kubectl create configmap starboard-conftest-config -n <starboard_namespace> \
--from-file=conftest.policy.kubernetes.rego=kubernetes/lib/kubernetes.rego \
--from-file=conftest.policy.utils.rego=kubernetes/lib/utils.rego \
--from-file=conftest.policy.file_system_not_read_only.rego=kubernetes/policies/general/file_system_not_read_only.rego \
--from-file=conftest.policy.uses_image_tag_latest.rego=kubernetes/policies/general/uses_image_tag_latest.rego
```

To test this setup out with Starboard CLI you can create the `nginx` Deployment with the latest `nginx` image and check
its configuration:

```
kubectl create deployment nginx --image nginx
kubectl starboard scan configauditreports deployment/nginx
```

Finally, inspect the ConfigAuditReport to confirm that the Deployment is not compliant with test policies:

```console
$ kubectl get configauditreport deployment-nginx -o jsonpath='{.report}' | jq
{
  "containerChecks": {},
  "podChecks": [
    {
      "category": "Security",
      "checkID": "Root file system is not read-only",
      "message": "container nginx of deployment nginx in default namespace should set securityContext.readOnlyRootFilesystem to true",
      "severity": "DANGER",
      "success": false
    },
    {
      "category": "Security",
      "checkID": "Image tag \":latest\" used",
      "message": "container nginx of deployment nginx in default namespace should specify image tag",
      "severity": "DANGER",
      "success": false
    }
  ],
  "scanner": {
    "name": "Conftest",
    "vendor": "Open Policy Agent",
    "version": "v0.23.0"
  },
  "summary": {
    "dangerCount": 2,
    "passCount": 0,
    "warningCount": 0
  },
  "updateTimestamp": "2021-04-15T13:54:49Z"
}
```

!!! Tip
    The steps for configuring Conftest with Starboard CLI and Starboard Operator are the same except the namespace
    in which the `starboard-conftest-config` ConfigMap is created.

[OPA]: https://www.openpolicyagent.org
[Conftest]: https://github.com/open-policy-agent/conftest
[AppShield]: https://github.com/aquasecurity/appshield
[kubernetes.rego]: https://raw.githubusercontent.com/aquasecurity/appshield/master/kubernetes/lib/kubernetes.rego
[utils.rego]: https://raw.githubusercontent.com/aquasecurity/appshield/master/kubernetes/lib/utils.rego
[file_system_not_read_only.rego]: https://raw.githubusercontent.com/aquasecurity/appshield/master/kubernetes/policies/general/file_system_not_read_only.rego
[uses_image_tag_latest.rego]: https://raw.githubusercontent.com/aquasecurity/appshield/master/kubernetes/policies/general/uses_image_tag_latest.rego