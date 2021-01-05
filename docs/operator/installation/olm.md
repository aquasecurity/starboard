The [Operator Lifecycle Manager (OLM)][olm] provides a declarative way to install and upgrade operators and their
dependencies.

You can install the Starboard operator from [OperatorHub.io](https://operatorhub.io/operator/starboard-operator)
or [ArtifactHUB](https://artifacthub.io/) by creating the OperatorGroup, which defines the operator's
multitenancy, and Subscription that links everything together to run the operator's pod.

1. Install the Operator Lifecycle Manager:

        curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/0.16.1/install.sh | bash -s 0.16.1

2. Create the namespace to install the operator in:


        kubectl create ns starboard-operator

3. Declare the target namespaces by creating the OperatorGroup:


        cat << EOF | kubectl apply -f -
        apiVersion: operators.coreos.com/v1alpha2
        kind: OperatorGroup
        metadata:
          name: starboard-operator
          namespace: starboard-operator
        spec:
          targetNamespaces:
          - default
        EOF

4. Install the operator by creating the Subscription:

        cat << EOF | kubectl apply -f -
        apiVersion: operators.coreos.com/v1alpha1
        kind: Subscription
        metadata:
          name: starboard-operator
          namespace: starboard-operator
        spec:
          channel: alpha
          name: starboard-operator
          source: operatorhubio-catalog
          sourceNamespace: olm
        EOF
   The operator will be installed in the `starboard-operator` namespace and will be usable from the `default` namespace.

5. After install, watch the operator come up using the following command:

        kubectl get csv -n starboard-operator
        NAME                        DISPLAY              VERSION   REPLACES   PHASE
        starboard-operator.v0.6.0   Starboard Operator   0.6.0                Succeeded

[olm]: https://github.com/operator-framework/operator-lifecycle-manager/
