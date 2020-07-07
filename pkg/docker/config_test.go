package docker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadCredentialsFromBytes(t *testing.T) {
	testCases := []struct {
		name string

		givenJSON string

		expectedCredentials map[string]ServerCredentials
		expectedError       error
	}{
		{
			name:                "Should return empty credentials when content is empty JSON object",
			givenJSON:           "{}",
			expectedCredentials: map[string]ServerCredentials{},
		},
		{
			name:                "Should return empty credentials when content is null JSON",
			givenJSON:           "null",
			expectedCredentials: map[string]ServerCredentials{},
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
			expectedCredentials: map[string]ServerCredentials{
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
			expectedCredentials: map[string]ServerCredentials{
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
			credentials, err := ReadCredentialsFromBytes([]byte(tc.givenJSON))
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error())
			default:
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCredentials, credentials)
			}
		})

	}
}
