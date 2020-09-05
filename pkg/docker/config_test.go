package docker_test

import (
	"errors"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/aquasecurity/starboard/pkg/docker"
	. "github.com/onsi/ginkgo/extensions/table"
	"github.com/stretchr/testify/assert"
)

// TODO Refactor to Ginkgo+Gomega
func TestConfig_Read(t *testing.T) {
	testCases := []struct {
		name string

		givenJSON string

		expectedAuth  map[string]docker.Auth
		expectedError error
	}{
		{
			name:         "Should return empty credentials when content is empty JSON object",
			givenJSON:    "{}",
			expectedAuth: map[string]docker.Auth{},
		},
		{
			name:         "Should return empty credentials when content is null JSON",
			givenJSON:    "null",
			expectedAuth: map[string]docker.Auth{},
		},
		{
			name:          "Should return error when content is blank",
			givenJSON:     "",
			expectedError: errors.New("unexpected end of JSON input"),
		},
		{
			name: "Should return server credentials with encoded username and password",
			givenJSON: `{
						"auths": {
							"https://index.docker.io/v1/": {
							"auth": "ZG9ja2VyOmh1Yg=="
							},
							"harbor.domain": {
							"auth": "YWRtaW46SGFyYm9yMTIzNDU="
							}
						}
						}`,
			expectedAuth: map[string]docker.Auth{
				"harbor.domain": {
					Auth:     "YWRtaW46SGFyYm9yMTIzNDU=",
					Username: "admin",
					Password: "Harbor12345",
				},
				"https://index.docker.io/v1/": {
					Auth:     "ZG9ja2VyOmh1Yg==",
					Username: "docker",
					Password: "hub",
				},
			},
		},
		{
			name: "Should skip empty server entries",
			givenJSON: `{
						"auths": {
						"https://index.docker.io/v1/": {
							
						},
						"harbor.domain": {
							"auth": "YWRtaW46SGFyYm9yMTIzNDU="
						}
						}
					}`,
			expectedAuth: map[string]docker.Auth{
				"harbor.domain": {
					Auth:     "YWRtaW46SGFyYm9yMTIzNDU=",
					Username: "admin",
					Password: "Harbor12345",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dockerConfig := &docker.Config{}
			err := dockerConfig.Read([]byte(tc.givenJSON))
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error())
			default:
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedAuth, dockerConfig.Auths)
			}
		})

	}
}

func TestDocker(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Docker")
}

var _ = Describe("Docker", func() {

	DescribeTable("GetHostFromServer", func(server, expectedHost string) {
		host, err := docker.GetHostFromServer(server)
		Expect(err).ToNot(HaveOccurred())
		Expect(host).To(Equal(expectedHost))
	},
		Entry("34.86.43.130.80",
			"34.86.43.130.80", "34.86.43.130.80"),
		Entry("core.harbor.domain:8080",
			"core.harbor.domain:8080", "core.harbor.domain:8080"),
		Entry("registry.aquasec.com",
			"registry.aquasec.com", "registry.aquasec.com"),
		Entry("https://index.docker.io/v1/",
			"https://index.docker.io/v1/", "index.docker.io"),
		Entry("https://registry:3780/",
			"https://registry:3780/", "registry:3780"),
	)

	DescribeTable("GetServerFromImageRef", func(imageRef, expectedServer string) {
		server, err := docker.GetServerFromImageRef(imageRef)
		Expect(err).ToNot(HaveOccurred())
		Expect(server).To(Equal(expectedServer))
	},
		Entry("aquasec/trivy:0.10.0",
			"aquasec/trivy:0.10.0", "index.docker.io"),
		Entry("docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			"docker.io/aquasec/harbor-scanner-trivy:0.10.0", "index.docker.io"),
		Entry("index.docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			"index.docker.io/aquasec/harbor-scanner-trivy:0.10.0", "index.docker.io"),
		Entry("gcr.io/google-samples/hello-app:1.0",
			"gcr.io/google-samples/hello-app:1.0", "gcr.io"),
	)

})
