package docker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

type BasicAuth string

func NewBasicAuth(username, password string) BasicAuth {
	var v = new(BasicAuth)
	v.Encode(username, password)
	return *v
}

func (v *BasicAuth) Encode(username, password string) {
	*v = BasicAuth(base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s", username, password))))
}

func (v *BasicAuth) Decode() (username, password string, err error) {
	bytes, err := base64.StdEncoding.DecodeString(string(*v))
	if err != nil {
		return
	}
	split := strings.Split(string(bytes), ":")

	username = split[0]
	password = split[1]
	return
}

func (v BasicAuth) String() string {
	return "[REDACTED]"
}

// Auth represent credentials used to login to a Docker registry.
type Auth struct {
	Auth     BasicAuth `json:"auth,omitempty"`
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
}

func (v Auth) String() string {
	return "[REDACTED]"
}

// Config represents Docker configuration which is typically saved as `~/.docker/config.json`.
type Config struct {
	Auths map[string]Auth `json:"auths"`
}

func (c *Config) Read(contents []byte) (err error) {
	if err := json.Unmarshal(contents, c); err != nil {
		return err
	}
	c.Auths, err = decodeAuths(c.Auths)
	return
}

func decodeAuths(auths map[string]Auth) (map[string]Auth, error) {
	decodedAuths := make(map[string]Auth)
	for server, entry := range auths {
		if (Auth{}) == entry {
			continue
		}

		username, password, err := entry.Auth.Decode()
		if err != nil {
			return nil, err
		}

		decodedAuths[server] = Auth{
			Auth:     entry.Auth,
			Username: username,
			Password: password,
		}

	}
	return decodedAuths, nil
}

func (c Config) Write() ([]byte, error) {
	bytes, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GetServerFromImageRef returns registry server from the specified imageRef.
func GetServerFromImageRef(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	return ref.Context().RegistryStr(), nil
}

// GetHostFromServer returns the host for the specified registry server.
//
// In ~/.docker/config.json auth keys can be specified as URLs or host names.
// For the sake of comparison we need to normalize the registry identifier.
func GetHostFromServer(server string) (string, error) {
	if strings.HasPrefix(server, "http://") ||
		strings.HasPrefix(server, "https://") {

		parsed, err := url.Parse(server)
		if err != nil {
			return "", err
		}

		return parsed.Host, nil
	}
	return server, nil
}
