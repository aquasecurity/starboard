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

## Using Generated Code

An instance of a client set can be created with the `NewForConfig` helper function. This is analogous to the client sets
for core Kubernetes resources. The following listings shows how to create an instance of the
`vulnerabilities.aquasecurity.github.io` resource and send it to the Kubernetes API.

```go
package main

import (
	"log"
	"os"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(_ []string) (err error) {
	config, err := clientcmd.BuildConfigFromFlags("", "~/.kube/config")
	if err != nil {
		return
	}
	client, err := starboardapi.NewForConfig(config)
	if err != nil {
		return
	}

	vulnerability := &starboard.Vulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name:      "a2a6b603-97b4-4e5d-bbcd-404723c4177a",
			Namespace: "dev",
			Labels: map[string]string{
				"starboard.resource.kind":  "Deployment",
				"starboard.resource.name":  "nginx",
				"starboard.container.name": "nginx",
			},
			Annotations: map[string]string{
				"starboard.history.limit": "10",
				"starboard.image.digest":  "sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb",
			},
		},
		Report: starboard.VulnerabilityReport{
			Scanner: starboard.Scanner{
				Name:    "Trivy",
				Vendor:  "Aqua Security",
				Version: "latest",
			},
			Artifact: starboard.Artifact{
				Repository: "library/nginx",
				Digest:     "sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb",
				Tag:        "1.16",
				MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
			},
			Summary: starboard.VulnerabilitySummary{
				CriticalCount: 0,
				HighCount:     0,
				MediumCount:   1,
				LowCount:      0,
				UnknownCount:  0,
			},
			Vulnerabilities: []starboard.VulnerabilityItem{
				{
					VulnerabilityID:  "CVE-2019-1549",
					Resource:         "openssl",
					Severity:         starboard.SeverityMedium,
					InstalledVersion: "1.1.1c-r0",
					FixedVersion:     "1.1.1d-r0",
					Title:            "openssl: information disclosure in fork()",
				},
			},
		},
	}

	_, err = client.AquasecurityV1alpha1().
		Vulnerabilities("dev").
		Create(vulnerability)
	return
}
```

Note that higher-level tools like informers and listers are also generated and available.

[k8s-sample-controller]: https://github.com/kubernetes/sample-controller
