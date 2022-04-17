# CLI enhancements

## Overview
this document describes the enhancements we with to do with the CLI in order to improve the CLI starboard onboard experience and provide cluster wide data

## Motivation
- Easy starboard CLI usage landing
- simplification of the CLI flow, make it quick for demoing 
- return value which will represent starboard capabilities (cluster scope).
- format the return output

### TL;DR;

#### Background (CLI Today):
 - Starboard CLI flow is composed of 3 main commands
   - `starboard install` (one time command) - to install starboard prerequisite resources (CRDs , configmaps ,rbac etc.)
   - `starboard scan` scan (vulnerability / configaudit / cis-benchmark / kube-hunter) on a specific resource on a specific namespace 
   - `starboard get` return crd reports for specific resource in `json` or `yaml` formats
 - There is also `starboard report` command which produce html report out of the CRDs reports data 

### CLI audience
Developers, DevOps , security, or anyone who quickly wants to understand what Starboard can bring to the table

### Main Idea
- CLI should be easy to use - one line command
- CLI should provide a more broad ,cluster/namespace, security overview (cis-benchmark,vulnerability,config-audit,NSA and more) , in one command line
- CLI output should be aggregated and well-formatted to present the data for easy understanding and bring max value to the user

### Recommended solution
 - Automate scanning process (embed install command with scan commands) [issue #1065](https://github.com/aquasecurity/starboard/issues/1065)
 - Introduce new command `starboard scan namespace <namespace name>` [issue #1099](https://github.com/aquasecurity/starboard/issues/1099)
 - Introduce new command `starboard scan cluster` [issue #1098](https://github.com/aquasecurity/starboard/issues/1098)
 - formatted console output [issue #1097](https://github.com/aquasecurity/starboard/issues/1097)
 - Merge the existing `scan` and `get` commands [issue #1096](https://github.com/aquasecurity/starboard/issues/1096)

### Consideration:
Scanning namespace / cluster could take time and output should present to the user reporting on the progress, Example:<br>
` CIS-benchmark scanning:`<br>
   `node-1 ============> `<br>

`Vulnerability scanning:`<br>
   `mynamesapce/nginx   ============> `

`config-audit  scanning:`<br>
   `mynamesapce/nginx   ============> `

## Out of scope
running starboard CLI out of cluster (should be done probably in a separate discussion) ,however it does not contradict the proposed changes