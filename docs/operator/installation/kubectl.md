You can install the operator with provided static YAML manifests with fixed
values. However, this approach has its shortcomings. For example, if you want to
change the container image or modify default configuration parameters, you have
to create new manifests or edit existing ones.

To deploy the operator in the `starboard-operator` namespace and configure it to
watch the `default` namespace:

1. Send the definition of the `vulnerabilityreports` custom resource to the
   Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/crd/vulnerabilityreports.crd.yaml

2. Send the following Kubernetes objects definitions to the Kubernetes API:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/01-starboard-operator.ns.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/02-starboard-operator.sa.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/03-starboard-operator.clusterrole.yaml \
          -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/04-starboard-operator.clusterrolebinding.yaml

3. (Optional) Configure the operator by creating the `starboard` ConfigMap and
   the `starboard` secret in the `starboard-operator` namespace. If you skip
   this step, the operator will ensure [configuration objects](./../../configuration.md)
   on startup with the default settings.

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/05-starboard-operator.config.yaml
   Review the default values and makes sure the operator is configured properly:

        kubectl describe cm starboard -n starboard-operator
        kubectl describe secret starboard -n starboard-operator

4. Finally, create the `starboard-operator` Deployment in the `starboard-operator`
   namespace to start the operator's pod:

        kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/06-starboard-operator.deployment.yaml

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

    kubectl delete -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/06-starboard-operator.deployment.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/05-starboard-operator.config.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/04-starboard-operator.clusterrolebinding.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/03-starboard-operator.clusterrole.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/02-starboard-operator.sa.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/static/01-starboard-operator.ns.yaml \
      -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/crd/vulnerabilityreports.crd.yaml
