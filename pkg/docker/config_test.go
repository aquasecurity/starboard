package docker_test

import (
	"errors"
	"testing"

	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBasicAuth(t *testing.T) {
	assert.Equal(t, docker.BasicAuth("Zm9vOmJhcg=="), docker.NewBasicAuth("foo", "bar"))
}

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

func TestGetServerFromDockerAuthKey(t *testing.T) {
	testCases := []struct {
		authKey        string
		expectedServer string
	}{
		{
			authKey:        "34.86.43.13:80",
			expectedServer: "34.86.43.13:80",
		},
		{
			authKey:        "core.harbor.domain:8080",
			expectedServer: "core.harbor.domain:8080",
		},
		{
			authKey:        "rg.pl-waw.scw.cloud/starboard",
			expectedServer: "rg.pl-waw.scw.cloud",
		},
		{
			authKey:        "rg.pl-waw.scw.cloud:7777/private",
			expectedServer: "rg.pl-waw.scw.cloud:7777",
		},
		{
			authKey:        "registry.aquasec.com",
			expectedServer: "registry.aquasec.com",
		},
		{
			authKey:        "https://index.docker.io/v1/",
			expectedServer: "index.docker.io",
		},
		{
			authKey:        "https://registry:3780/",
			expectedServer: "registry:3780",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.authKey, func(t *testing.T) {
			server, err := docker.GetServerFromDockerAuthKey(tc.authKey)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedServer, server)
		})
	}
}

func TestGetServerFromImageRef(t *testing.T) {
	testCases := []struct {
		imageRef       string
		expectedServer string
	}{
		{
			imageRef:       "nginx:1.16",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "aquasec/trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "index.docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "gcr.io/google-samples/hello-app:1.0",
			expectedServer: "gcr.io",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.imageRef, func(t *testing.T) {
			server, err := docker.GetServerFromImageRef(tc.imageRef)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedServer, server)
		})
	}
}
