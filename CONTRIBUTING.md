# Contributing

These guidelines will help you get started with the Starboard project.

## Table of Contents

- [Contribution Workflow](#contribution-workflow)
  - [Issues and Discussions](#issues-and-discussions)
  - [Pull Requests](#pull-requests)
- [Set up your Development Environment](#set-up-your-development-environment)
- [Build Binaries](#build-binaries)
- [Run Tests](#run-tests)
  - [Run Unit Tests](#run-unit-tests)
  - [Run Integration Tests](#run-integration-tests)
  - [Cove Coverage](#code-coverage)
- [Custom Resource Definitions](#custom-resource-definitions)
  - [Generate Code](#generate-code)
- [Test Starboard Operator](#test-starboard-operator)
  - [Prerequisites](#prerequisites)
  - [In Cluster](#in-cluster)
  - [Out of Cluster](#out-of-cluster)
  - [Enable Aqua Scanner](#enable-aqua-scanner)
- [Operator Lifecycle Manager (OLM)](#operator-lifecycle-manager-olm)
  - [Install OLM and Operator Marketplace](#install-olm-and-operator-marketplace)
  - [Publish the OLM Bundle to Quay.io](#publish-the-olm-bundle-to-quayio)
  - [Install the OLM Bundle from Quay.io](#install-the-olm-bundle-from-quayio)

## Contribution Workflow

### Issues and Discussions

- Feel free to open issues for any reason as long as you make it clear what this issue is about: bug/feature/proposal/comment.
- For questions and general discussions, please do not open an issue, and instead create a discussion in the "Discussions" tab.
- Please spend a minimal amount of time giving due diligence to existing issues or discussions. Your topic might be a duplicate. If it is, please add your comment to the existing one.
- Please give your issue or discussion a meaningful title that will be clear for future users.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.
- For technical questions, please explain in detail what you were trying to do, provide an error message if applicable, and your versions of Starboard and your environment.

### Pull Requests

- Every Pull Request should have an associated Issue unless it is a trivial fix.
- Your PR is more likely to be accepted if it focuses on just one change.
- Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that start with "fix"/"add"/"improve"/"remove" are good examples.
- There's no need to add or tag reviewers, if your PR is left unattended for too long, you can add a comment to bring it up to attention, optionally "@" mention one of the maintainers that was involved with the issue.
- If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it and re-request a review.
- When addressing comments, try to fix each suggestion in a separate commit.
- Tests are not required at this point as Starboard is evolving fast, but if you can include tests that will be appreciated.

## Set up your Development Environment

1. Install Go

   The project requires [Go 1.15][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Get the source code:

   ```
   $ git clone git@github.com:aquasecurity/starboard.git
   $ cd starboard
   ```
3. Access to a Kubernetes cluster. We assume that you're using a [KIND][kind] cluster. To create a single-node KIND
   cluster, run:

   ```
   $ kind create cluster
   ```

## Build Binaries

| Binary                   | Image                                      | Description                                                   |
| ------------------------ | ------------------------------------------ |  ------------------------------------------------------------ |
| `starboard`              | `docker.io/aquasec/starboard:dev`          | Starboard command-line interface                              |
| `starboard-operator`     | `docker.io/aquasec/starboard-operator:dev` | Starboard Operator                                            |
| `starboard-scanner-aqua` | `docker.io/aquasec/starboard-scanner-aqua` | Starboard plugin to integrate with Aqua vulnerability scanner |

To build all Starboard binaries, run:

```
$ make
```

This uses the `go build` command and builds binaries in the `./bin` directory.

To build all Starboard binaries into Docker images, run:

```
$ make docker-build
```

To load Docker images into your KIND cluster, run:

```
$ kind load docker-image aquasec/starboard:dev
$ kind load docker-image aquasec/starboard-operator:dev
$ kind load docker-image aquasec/starboard-scanner-aqua:dev
```

## Run Tests

We generally require tests to be added for all, but the most trivial of changes. However, unit tests alone don't
provide guarantees about the behaviour of Starboard. To verify that each Go module correctly interacts with its
collaborators, more coarse grained integration tests might be required.

### Run Unit Tests

To run all unit tests with code coverage enabled, run:

```
$ make unit-tests
```

To open the test coverage report in your web browser, run:

```
$ go tool cover -html=coverage.txt
```

### Run Integration Tests

The integration tests assumes that you have a working kubernetes cluster (e.g KIND cluster) and `KUBECONFIG` environment
variable is pointing to that cluster configuration file. For example:

```
$ export KUBECONFIG=~/.kube/config
```

To run all integration tests with code coverage enabled, run:

```
$ make integration-tests
```

To open the test coverage report in your web browser, run:

```
$ go tool cover -html=itest/coverage.txt
```

### Code Coverage

In the CI workflow, after running all tests, we do upload code coverage reports to [Codecov][codecov]. Codecov will
merge the reports automatically while maintaining the original upload context as explained
[here][codecov-merging-reports].

## Custom Resource Definitions

### Generate Code

Code generators are used a lot in the implementation of native Kubernetes resources, and we're using the very same
generators here for custom security resources. This project follows the patterns of
[k8s.io/sample-controller][k8s-sample-controller], which is a blueprint for many controllers built in Kubernetes itself.

The code generation starts with:

```
$ go mod vendor
$ export GOPATH="$(go env GOPATH)"
$ ./hack/update-codegen.sh
```

In addition, there is a second script called `./hack/verify-codegen.sh`. This script calls the
`./hack/update-codegen.sh` script and checks whether anything changed, and then it terminates with a nonzero return
code if any of the generated files is not up-to-date. We're running it as a step in the CI workflow.

## Test Starboard Operator

You can deploy the operator in the `starboard-operator` namespace and configure it to watch the `default`
namespace. In OLM terms such install mode is called *SingleNamespace*. The *SingleNamespace* mode is good to get
started with a basic development workflow. For other install modes see [Operator Multitenancy with OperatorGroups][olm-operator-groups].

### Prerequisites

1. Send the definition of the VulnerabilityReport custom resource to the Kubernetes API:

   ```
   $ kubectl apply -f deploy/crd/vulnerabilityreports.crd.yaml
   ```
2. Send the following Kubernetes objects definitions to the Kubernetes API:

   ```
   $ kubectl apply -f deploy/static/01-starboard-operator.ns.yaml \
       -f deploy/static/02-starboard-operator.sa.yaml \
       -f deploy/static/03-starboard-operator.clusterrole.yaml \
       -f deploy/static/04-starboard-operator.clusterrolebinding.yaml
   ```

   This will create the `starboard-operator` namespace, and the `starboard-operator` service account. Beyond that,
   it will create the `starboard-operator` ClusterRole and bind it to the `starboard-operator` service account in the
   `starboard-operator` namespace via the `starboard-operator` ClusterRoleBinding.

### In cluster

1. Create the `starboard-operator` Deployment in the `starboard-operator` namespace to run the operator's container:

   ```
   $ kubectl apply -f deploy/static/05-starboard-operator.deployment.yaml
   ```

### Out of cluster

1. Run the main method of the operator program:

   ```
   $ OPERATOR_NAMESPACE=starboard-operator \
     OPERATOR_TARGET_NAMESPACES=default \
     OPERATOR_LOG_DEV_MODE=true \
     go run cmd/starboard-operator/main.go
   ```

### Enable Aqua Scanner

1. Create the `starboard-operator` secret in the `starboard-operator` namespace that holds the scanner's configuration:

   ```
   $ kubectl create secret generic starboard-operator \
     --namespace starboard-operator \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
     --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
   ```
2. Patch or edit the `starboard-operator` deployment and set the value of the `OPERATOR_SCANNER_AQUA_CSP_ENABLED` to
   `true` and disable the default Trivy scanner by setting `OPERATOR_SCANNER_TRIVY_ENABLED` to `false`.

## Operator Lifecycle Manager (OLM)

### Install OLM and Operator Marketplace

To install [Operator Lifecycle Manager][olm] (OLM) and [Operator Marketplace][operator-marketplace], run:

```
$ ./deploy/olm/install.sh
```

### Publish the OLM Bundle to Quay.io

1. [Sign up][quay] for a free Quay.io account if you're a new user.
2. Install [Operator Courier][operator-courier]:

   ```
   $ pip3 install operator-courier
   ```
3. Lint the OLM bundle:

   ```
   $ BUNDLE_SRC_DIR=deploy/olm/bundle
   $ operator-courier verify $BUNDLE_SRC_DIR
   ```
4. Retrieve a Quay.io token:
   ```
   $ QUAY_USERNAME=<your quay.io username>
   $ QUAY_PASSWORD=<your quay.io password>
   $ QUAY_URL=https://quay.io/cnr/api/v1/users/login

   $ QUAY_TOKEN=$(curl -s -H "Content-Type: application/json" -XPOST $QUAY_URL -d \
     '{"user":{"username":"'"${QUAY_USERNAME}"'","password": "'"${QUAY_PASSWORD}"'"}}' |
     jq -r .token)
   ```
5. Push the OLM bundle to Quay.io:
   ```
   $ QUAY_NAMESPACE=<quay.io namespace>
   $ PACKAGE_NAME=starboard-operator
   $ PACKAGE_VERSION=<next package version>

   $ operator-courier push "$BUNDLE_SRC_DIR" "$QUAY_NAMESPACE" \
     "$PACKAGE_NAME" "$PACKAGE_VERSION" "$QUAY_TOKEN"
   ```
6. Navigate to https://quay.io/application/$QUAY_USERNAME/starboard-operator?tab=settings and make the published
   bundle public by clicking the **Make Public** button.


### Install the OLM Bundle from Quay.io

1. Create the OperatorSource resource:

   ```
   QUAY_FULL_NAME=<your quay.io full name>
   $ cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1
   kind: OperatorSource
   metadata:
     name: $QUAY_USERNAME-operators
     namespace: marketplace
   spec:
     type: appregistry
     endpoint: https://quay.io/cnr
     displayName: "$QUAY_FULL_NAME Quay.io Applications"
     publisher: "$QUAY_FULL_NAME"
     registryNamespace: "$QUAY_USERNAME"
   EOF
   ```

   An OperatorSource resource defines the external data store used to host operator bundles. In this case, you will be
   defining an OperatorSource to point to your Quay.io account, which will provide access to its hosted OLM bundles.

2. Create the OperatorGroup resource:

   ```
   $ cat << EOF | kubectl apply -f -
   apiVersion: operators.coreos.com/v1alpha2
   kind: OperatorGroup
   metadata:
     name: starboard-operator
     namespace: marketplace
   spec:
     targetNamespaces:
     - default
   EOF
   ```

   You'll need an OperatorGroup to denote which namespaces the operator should watch. It must exist in the namespace
   where you want to deploy the operator.

3. Create the Subscription resource
   1. with Trivy scanner, which is enabled by default:

      ```
      $ cat << EOF | kubectl apply -f -
      apiVersion: operators.coreos.com/v1alpha1
      kind: Subscription
      metadata:
        name: starboard-operator
        namespace: marketplace
      spec:
        channel: alpha
        name: starboard-operator
        source: $QUAY_NAMESPACE-operators
        sourceNamespace: marketplace
      EOF
      ```
   2. with Aqua CSP scanner:

      ```
      $ kubectl create secret generic starboard-operator \
          --namespace marketplace \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_USERNAME=$AQUA_CONSOLE_USERNAME \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_PASSWORD=$AQUA_CONSOLE_PASSWORD \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_VERSION=$AQUA_VERSION \
          --from-literal OPERATOR_SCANNER_AQUA_CSP_HOST=http://csp-console-svc.aqua:8080
      ```

      ```
      $ cat << EOF | kubectl apply -f -
      apiVersion: operators.coreos.com/v1alpha1
      kind: Subscription
      metadata:
        name: starboard-operator
        namespace: marketplace
      spec:
        channel: alpha
        name: starboard-operator
        source: $QUAY_NAMESPACE-operators
        sourceNamespace: marketplace
        config:
          env:
          - name: OPERATOR_SCANNER_TRIVY_ENABLED
            value: "false"
          - name: OPERATOR_SCANNER_AQUA_CSP_ENABLED
            value: "true"
          envFrom:
          - secretRef:
              name: starboard-operator
      EOF
      ```

   A Subscription links the previous steps together by selecting an operator and one of its channels. OLM uses this
   information to start the corresponding operator Pod. The example above creates a new Subscription to the `alpha`
   channel for the Starboard Operator.

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[kind]: https://github.com/kubernetes-sigs/kind
[codecov]: https://codecov.io/
[codecov-merging-reports]: https://docs.codecov.io/docs/merging-reports/
[olm]: https://github.com/operator-framework/operator-lifecycle-manager
[operator-marketplace]: https://github.com/operator-framework/operator-marketplace
[operator-courier]: https://github.com/operator-framework/operator-courier
[olm-operator-groups]: https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/operatorgroups.md
[quay]: https://quay.io
[k8s-sample-controller]: https://github.com/kubernetes/sample-controller
