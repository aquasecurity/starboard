# Overview

Starboard CLI is a single executable binary which can be used to find risks, such as vulnerabilities or insecure pod
descriptors, in Kubernetes workloads. By default, the risk assessment reports are stored as [custom resources][crds].

To learn more about the available Starboard CLI commands, run `starboard help` or type a command followed by the
`-h` flag:

```
starboard scan kubehunterreports -h
```

[crds]: ./../crds.md
