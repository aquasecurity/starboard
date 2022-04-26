# grype plugin for Starboard

This plugin is derived from the Trivy plugin.

* [grype](https://github.com/anchore/grype)
* [grype config](https://github.com/anchore/grype#configuration)

# Notes on configuration
Most of the settings correspond directly to the settings mentioned in grype documentation.
In order to set optional parameters, e.g. `grype.onlyFixed`, they have to be set to `true`
There are two settings that are specific to this plugin:

key | description 
--- | --- 
`grype.insecureRegistryPrefixes` | comma separated list of prefixes of registries where TLS verification will be skipped 
`grype.nonSSLRegistyPrefixes` | comma separated list of prefixes of registries that use http
