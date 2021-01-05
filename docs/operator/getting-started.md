Assuming that you installed the operator in the `starboard-operator` namespace,
and it's configured to discover Kubernetes workloads in the `default` namespace,
let's create the `nginx` Deployment that we know is vulnerable:

    kubectl create deployment nginx --image nginx:1.16

When the first pod controlled by the `nginx` Deployment is created, the operator
immediately detects that and creates the Kubernetes job in the
`starboard-operator` namespace to scan the `nignx` container's image (`nginx:1.16`)
for vulnerabilities.

    kubectl get job -n starboard-operator

In our case you should see only one job with a random name scheduled to scan
the `nginx` Deployment:

    NAME                                   COMPLETIONS   DURATION   AGE
    69516243-c782-4445-88b4-689ffbb3cdb7   0/1           68s        68s

If everything goes fine, the scan job is deleted, and the operator creates the
`vulnerabilityreports` resource in the `default` namespace that corresponds to
the `nginx` container:

    kubectl get vulnerabilityreports -o wide

Notice that the `vulnerabilityreports` instance is associated with the active
ReplicaSet of the `nginx` Deployment by name, and the set of labels.

    NAME                                REPOSITORY      TAG    SCANNER   AGE   CRITICAL   HIGH   MEDIUM   LOW   UNKNOWN
    replicaset-nginx-6d4cf56db6-nginx   library/nginx   1.16   Trivy     14m   1          35     16       85    2

You can get and describe `vulnerabilityreports` as any other built-in Kubernetes
object. For example, you can display the report as JSON object:

    kubectl get vulnerabilityreports replicaset-nginx-6d4cf56db6-nginx -o json
