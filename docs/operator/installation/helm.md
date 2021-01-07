[Helm][helm], which is de facto standard package manager for Kubernetes, allows
installing applications from parameterized YAML manifests called Helm [charts][helm-charts].

To address shortcomings of static YAML manifests we provide the Helm chart to
deploy the Starboard operator. The Helm chart supports all [install modes](./../configuration.md#install-modes).

As an example, let's install the operator in the `starboard-operator` namespace and
configure it to watch the `default` namespaces:

1. Clone the chart repository:

        git clone https://github.com/aquasecurity/starboard.git
        cd starboard

2. Create the `starboard-operator` namespace:

        kubectl create namespace starboard-operator

3. (Optional) Configure the operator by creating the `starboard` ConfigMap and
   the `starboard` secret in the `starboard-operator` namespace. If you skip
   this step, the operator will ensure [configuration objects](./../../configuration.md)
   on startup with the default settings.

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/05-starboard-operator.config.yaml
   Review the default values and makes sure the operator is configured properly:

        kubectl describe cm starboard -n starboard-operator
        kubectl describe secret starboard -n starboard-operator

4. Install the chart:

        helm install starboard-operator ./deploy/helm \
          -n starboard-operator \
          --set="targetNamespaces=default"

Check that the `starboard-operator` Helm release is created in the `starboard-operator`
namespace:

```
helm list -n starboard-operator
```

```text
NAME              	NAMESPACE         	REVISION	UPDATED                             	STATUS  	CHART                   	APP VERSION
starboard-operator	starboard-operator	1       	2020-12-09 16:15:51.070673 +0100 CET	deployed	starboard-operator-0.2.1	0.7.1
```

To confirm that the operator is running, check the number of replicas created by
the `starboard-operator` Deployment in the `starboard-operator` namespace:

    kubectl get deployment -n starboard-operator

You should see the output similar to the following:

    NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
    starboard-operator   1/1     1            1           11m

If for some reason it's not ready yet, check the logs of the Deployment for
errors:

    kubectl logs -n starboard-operator deployment/starboard-operator

In case of any error consult our [Troubleshooting](./../../troubleshooting.md) guidelines.

You can uninstall the operator with the following command:

    helm uninstall starboard-operator -n starboard-operator

> **NOTE** You have to manually delete CRDs created by the `helm install` command:
>
>     kubectl delete crd vulnerabilityreports.aquasecurity.github.io

[helm]: https://helm.sh/
[helm-charts]: https://helm.sh/docs/topics/charts/
