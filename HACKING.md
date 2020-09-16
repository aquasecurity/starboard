# Hacking

## Prerequisites

- [Go 1.14 or above](https://golang.org/dl/)

## Getting Started

```
$ git clone git@github.com:aquasecurity/starboard.git
$ cd starboard
$ make build
$ ./bin/starboard help
```

## Testing

We generally require tests to be added for all but the most trivial of changes. You can run the tests using the
commands below:

```
# To run only unit tests
$ make unit-tests

# To run only integration tests
# Please note that integration tests assumes that you have a working kubernetes cluster (e.g KIND cluster) and KUBECONFIG env variable is pointing to that cluster
$ make integration-tests

# To run both unit-tests and integration-tests
$ make test
```

## Generating Code

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
code if any of the generated files is not up-to-date. We're running it as a step in the CI/CD pipeline.

[k8s-sample-controller]: https://github.com/kubernetes/sample-controller
