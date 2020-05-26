# Aqua Security Starboard

## Custom Security Resources Specification

[Custom resources][k8s-custom-resources] (CR) is one of the central extension mechanisms used throughout the Kubernetes 
ecosystem. Custom resources can be used for small, in-house configuration or data objects without any corresponding
controller logic. But they may also play a central role in projects built on top of Kubernetes that want to offer
a Kubernetes-native API experience.

This specification defines custom resources related to security and compliance checks.

The goal of this specification is to enable the creation of interoperable security tools and standardize how such tools
produce and consume security and compliance reports in Kubernetes-native way.

## Table of Contents

TODO Write the spec

[k8s-custom-resources]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources
