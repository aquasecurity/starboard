package docker

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ServerCredentials represent credentials used to login to a Docker server.
type ServerCredentials struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Credentials represents Docker credentials which are typically stored in `~/.docker/config.json`.
type Credentials struct {
	Auths map[string]ServerCredentials `json:"auths"`
}

func ReadCredentialsFromBytes(contents []byte) (cfg map[string]ServerCredentials, err error) {
	var credentials Credentials
	if err = json.Unmarshal(contents, &credentials); err != nil {
		return nil, err
	}
	return encodeAuth(credentials.Auths)
}

func encodeAuth(config map[string]ServerCredentials) (encodedConfig map[string]ServerCredentials, err error) {
	encodedConfig = make(map[string]ServerCredentials)
	for server, entry := range config {
		if (ServerCredentials{}) == entry {
			continue
		}
		var decodedAuth []byte
		decodedAuth, err = base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			return
		}
		splitDecodedAuth := strings.Split(string(decodedAuth), ":")
		encodedConfig[server] = ServerCredentials{
			Auth:     entry.Auth,
			Username: splitDecodedAuth[0],
			Password: splitDecodedAuth[1],
		}

	}
	return
}
