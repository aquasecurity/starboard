# kubectl

You can use static YAML manifests to install the operator in the `starboard-system` namespace and configure it to watch
the `default` namespace:

```
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/{{ git.tag }}/deploy/static/starboard.yaml
```

To confirm that the operator is running, check that the `starboard-operator` Deployment in the `starboard-system`
namespace is available and all its containers are ready:

```console
$ kubectl get deployment -n starboard-system
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
starboard-operator   1/1     1            1           11m
```

If for some reason it's not ready yet, check the logs of the `starboard-operator` Deployment for errors:

```
kubectl logs deployment/starboard-operator -n starboard-system
```

Starboard ensures the default [settings] stored in ConfigMaps and Secrets created in the `starboard-system` namespace.
You can always change these settings by editing configuration objects. For example, you can use Trivy in [ClientServer]
mode, which is more efficient that the [Standalone] mode, or switch to [Aqua Enterprise] as an alternative vulnerability
scanner.

You can further [configure](./../configuration.md) the operator with environment variables. For example, to change the
target namespace from the `defaul` namespace to all namespaces set the value of the `OPERATOR_TARGET_NAMESPACES`
environment variable from `default` to a blank string (i.e., `OPERATOR_TARGET_NAMESPACES=""`).

Static YAML manifests with fixed values have shortcomings. For example, if you want to change the container image or
modify default configuration settings, you have to edit existing manifests or customize them with tools such as
[Kustomize]. Thus, we also provide [Helm] chart as an alternative installation option.

## Uninstall

!!! danger
    Uninstalling the operator and deleting custom resource definitions will also delete all generated security reports.

You can uninstall the operator with the following command:

```
kubectl delete -f https://raw.githubusercontent.com/aquasecurity/starboard/{{ git.tag }}/deploy/static/starboard.yaml
```

[settings]: ./../../settings.md
[Standalone]: ./../../integrations/vulnerability-scanners/trivy.md#standalone
[ClientServer]: ./../../integrations/vulnerability-scanners/trivy.md#clientserver
[Aqua Enterprise]: ./../../integrations/vulnerability-scanners/aqua-enterprise.md
[Kustomize]: https://kustomize.io
[Helm]: ./helm.md
