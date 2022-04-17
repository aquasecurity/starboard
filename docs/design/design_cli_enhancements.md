# CLI enhancements

## Overview
this document describes the enhancements we with to do with the CLI in order to improve the CLI starboard onboard experience and provide cluster wide data

## Motivation
Easy starboard CLI usage landing, simplification of the CLI flow, make it quick for demoing and return value which will represent starboard capabilities.

### TL;DR;

#### Background (CLI Today):
 - starboard CLI flow is composed of 3 main commands
   - `starboard install` (one time command) - to install starboard prerequisite resources (CRDs , configmaps ,rbac etc.)
   - `starboard scan` scan (vulnerability / configaudit / cis-benchmark / kube-hunter) on a specific resource on a specific namespace 
   - `starboard get` return crd report for specific resource in json or yaml formats
 - there is also `starboard report` command which produce html report out of the CRDs reports data 

