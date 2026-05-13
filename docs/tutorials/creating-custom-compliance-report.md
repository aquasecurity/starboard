# Creating Custom Compliance Reports

With the release of the NSA compliance reports, we have added the capability to create any type of report. You can find an example of a the `ClusterComplianceReport` in the [documentation](../crds/clustercompliance-report.md)

Otherwise, access the `ClusterComplianceReport` directly through your Kubernetes cluster by following the steps outlined below:

1. [Install the Starboard Operator](../operator/installation/helm.md) inside of your Kubernetes cluster
2. Wait a few minutes to allow the operator to generate all the reports
3. Run the following command to access the `ClusterComplianceReport`

    ```
    kubectl describe ClusterComplianceReport nsa
    ```

The report has two main sections: 

- spec: represents the NSA compliance control checks specification, check details, and the mapping to the security scanner
- status: represents the NSA compliance control checks results

We can customize the `Spec` by amending the control checks severity or cron expression to then generate a custom status output within the ClusterComplianceReport  CRD.
First, we are going to open the CRD in edit mode. This can be done with the following command:

```
kubectl edit compliance
```

Let's look at one of the scans within the `Spec` section:
```
 22   controls:
 23   - description: Check that container is not running as root
 24     id: "1.0"
 25     kinds:
 26     - Workload
 27     mapping:
 28       checks:
 29       - id: KSV012
 30       scanner: config-audit
 31     name: Non-root containers
 32     severity: MEDIUM
```

You can find the whole list of controls used within the `ClusterComplianceReport` in the specification.
Currently, we can run two types of scans, namely `config-audit` and `kube-bench`. 


Change any of the severity within the ClusterComplianceReport and then close the editor through `:wq`:
```
 22   controls:
 23   - description: Check that container is not running as root
 24     id: "1.0"
 25     kinds:
 26     - Workload
 27     mapping:
 28       checks:
 29       - id: KSV012
 30       scanner: config-audit
 31     name: Non-root containers
 32     severity: HIGH

```


This will regenerate the `status` section in accordance with the changes that you made.

We can the access the compliance status report in JSON format through the following command:
```
kubectl get compliance nsa  -o=jsonpath='{.status}' | jq .
{
  "controlCheck": [
    {
      "description": "Control checks whether anonymous-auth is unset",
      "failTotal": 0,
      "id": "7.0",
      "name": "Make sure anonymous-auth is unset",
      "passTotal": 1,
      "severity": "CRITICAL"
    },
    {
      "description": "Controls whether containers can use the host network",
      "failTotal": 0,
      "id": "1.5",
      "name": "Use the host network",
      "passTotal": 1,
      "severity": "HIGH"
    },

```
