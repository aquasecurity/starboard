# Support National Security Agency - Kubernetes Hardening Guidance

## Overview

It is required to extend starboard security tools capabilities by supporting the NSA - Kubernetes Hardening Guidance

1. A new NSA plugin will be added to starboard 
2. This new plugin will track different Resource Kinds as describe below: [NSA Tool Analysis](#nsa-tool-analysis) 
    and will trigger the relevant tool (conftest and kube-bench) based on the relevant kind 
3. A CRD will be introduced to represent the NSA checks report

## Solution

### TL;DR;

Add a new starboard plugin to support the NSA specification checks to enhance our Kubernetes Hardening capabilities.
The plugin will use the following tools to scan different kind of resources. 

1. conftest (later to be replaced by trivy-iac) will be triggered to scan all k8s config associated checks
2. kube-bench will be triggered to scan all k8s infra associated checks

### Deep Dive
The below  [NSA Tool Analysis](#nsa-tool-analysis) provides us with the separation of tool to be triggered based on resource kind for the NSA specification.
As seen with the analysis below, in order to make the NSA specification completed, checks need to be used and added to the relevant tools.

Code Changes:
- conftest - the following rego check need to be added to appshield :
  - new
    - `allowedHostPaths` for Limits containers to specific paths of the host file system.
    - `Set runAsUser to MustRunAsNonRoot` Controls whether container applications can run with root privileges
    - `ube-systm or kube-public` Domain should should not be used by users (need to confirm it can be done)
    - `policies that select Pods using podSelector and/or the namespaceSelector`


- kube-bench - a new kube-bench config check `nsa-1.0` need to be added with the following checks for `Node` resource kind:
  - existing
    - Use CNI plugin that supports NetworkPolicy API
    - use a default policy to deny all ingress and egress traffic. Ensures unselected Pods are isolated to all namespaces except kube-system
    - Use LimitRange and ResourceQuota policies to limit resources on a namespace or Pod level
    - TLS encryption
    - Etcd encryption
    - Kubeconfig files
    - Worker node segmentation
    - Encryption
    - Encryption / secrets
    - authentication
    - Role-based access control
    - Audit policy file
    - Audit log path
    - Audit log max age
    - service mesh usage
  - new
    - `use a default policy to deny all ingress and egress traffic` check that netowork policy deny all exist
    - `Usege of LimitRange` check the limit range resource has been define
    - `EncryptionConfiguration` check that encryption resource has been set
    - `service mesh usage` check serve mesh is used in cluster
  
#### Note: in order to check cluster resource existence check we will have to introduce a new functionality to kube-bench


### Deployment consideration
- nsa appshield rego checks should be preloaded with starboard deployment as NSA plugin will be the default tool  
 example : 
```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  namespace: starboard-operator
  name: starboard-nsa-config
  annotations:
    # Introduce a way to version configuration schema.
    starboard.plugin.config.version: "v2"
data:
  nsa.imageRef: openpolicyagent/conftest:v0.28.2
  nsa.resources.requests.cpu: 50
  nsa.resources.requests.memory: 50M
  nsa.resources.limits.cpu: 300m
  nsa.resources.limits.memory: 300M
  nsa.policy.3_runs_as_root.rego.rego: "{REGO CODE}"
  nsa.policy.file_system_not_read_only.rego: "{REGO CODE}"
  nsa.policy.2_privileged.rego: "{REGO CODE}"
  nsa.policy.1_host_ipc.rego: "{REGO CODE}"
  nsa.policy.1_host_pid..rego: "{REGO CODE}"
  nsa.policy.1_host_network.rego: "{REGO CODE}"
  nsa.policy.4_runs_with_a_root_gid.rego: "{REGO CODE}"
  nsa.policy.2_can_elevate_its_own_privileges.rego: "{REGO CODE}"
  nsa.policy.7_selinux_custom_options_set.rego: "{REGO CODE}"
  nsa.policy.6_apparmor_policy_disabled.rego: "{REGO CODE}"
  nsa.policy.5_runtime_default_seccomp_profile_not_set.rego: "{REGO CODE}"
  # For each K8s workload type a config hash will be the same.
  nsa.policy.3_runs_as_root.rego.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.file_system_not_read_only.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.2_privileged.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.1_host_ipc.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.1_host_pid.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.1_host_network.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.4_runs_with_a_root_gid.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.2_can_elevate_its_own_privileges.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.7_selinux_custom_options_set.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.6_apparmor_policy_disabled.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
  nsa.policy.5_runtime_default_seccomp_profile_not_set.kinds: "Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob"
```

### Permission changes:

it is required to update `02-starboard-operator.rbac.yaml` to include new permissions 
to support the following tracked resources kind by NSA plugin with (get,list and watch):
  - NetworkPolicy
  - EncryptionConfiguration
  - LimitRange

### NSA CRD:
  - a new CRD `nsareports.crd.yaml` will be added to include nsa check report
  - CRD structure TBD

### NSA Tool Analysis

<table cellspacing=0 border=1>
					<tr>
  					</tr>
					<tr>
 					</tr>
					<tr>
  					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>Num</td>
						<td style=min-width:50px>Test</td>
						<td style=min-width:50px>Description</td>
						<td style=min-width:50px>Kind</td>
						<td style=min-width:50px>Tool</td>
						<td style=min-width:50px>Check supported</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>1</td>
						<td style=min-width:50px>Non-root containers</td>
						<td style=min-width:50px>Check that container is not running as root</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield : kubernetes/policies/pss/restricted/3_runs_as_root.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>2</td>
						<td style=min-width:50px>Immutable container file systems</td>
						<td style=min-width:50px>check that container root file system is immutable</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/general/file_system_not_read_only.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>3</td>
						<td style=min-width:50px>Scan container images for possible vulnerabilities or misconfigurations</td>
						<td style=min-width:50px>can container for vulnerabilities and misconfiguration</td>
						<td style=min-width:50px>Workload</td>
						<td style=min-width:50px>Trivy</td>
						<td style=min-width:50px>Trivy</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>4</td>
						<td style=min-width:50px>Privileged container</td>
						<td style=min-width:50px>Controls whether Pods can run privileged containers.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/2_privileged.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>5</td>
						<td style=min-width:50px>hostIPC</td>
						<td style=min-width:50px>Controls whether containers can share host process namespaces.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/1_host_ipc.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>6</td>
						<td style=min-width:50px>hostPID</td>
						<td style=min-width:50px></td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/1_host_pid.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>7</td>
						<td style=min-width:50px>hostNetwork</td>
						<td style=min-width:50px>Controls whether containers can use the host network.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/1_host_network.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>8</td>
						<td style=min-width:50px>allowedHostPaths</td>
						<td style=min-width:50px>Limits containers to specific paths of the host file system.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px;color:darkorange>Need to be added to appshield : https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>9</td>
						<td style=min-width:50px>readOnlyRootFilesystem</td>
						<td style=min-width:50px>Requires the use of a read only root file system</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/general/file_system_not_read_only.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>10</td>
						<td style=min-width:50px>runAsUser : MustRunAsNonRoot</td>
						<td style=min-width:50px></td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px;color:darkorange>Need to be added to appshield : https://kubernetes.io/docs/concepts/policy/pod-security-policy/</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>11</td>
						<td style=min-width:50px>runAsUser , runAsGroup ,supplementalGroups</td>
						<td style=min-width:50px></td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: appshield/kubernetes/policies/pss/restricted/4_runs_with_a_root_gid.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>12</td>
						<td style=min-width:50px>allowPrivilegeEscalation</td>
						<td style=min-width:50px>Restricts escalation to root privileges.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/restricted/2_can_elevate_its_own_privileges.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>13</td>
						<td style=min-width:50px>seLinux</td>
						<td style=min-width:50px>Sets the SELinux context of the container.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/7_selinux_custom_options_set.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>14</td>
						<td style=min-width:50px>AppArmor annotations</td>
						<td style=min-width:50px>Sets the seccomp profile used to sandbox containers.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/baseline/6_apparmor_policy_disabled.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>15</td>
						<td style=min-width:50px>seccomp annotations</td>
						<td style=min-width:50px>Sets the seccomp profile used to sandbox containers.</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>appshield: kubernetes/policies/pss/restricted/5_runtime_default_seccomp_profile_not_set.rego</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>16</td>
						<td style=min-width:50px>Protecting Pod service account tokens</td>
						<td style=min-width:50px>disable secret token been mount</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px>Need to be added to appshield: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/ automountServiceAccountToken: false</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>17</td>
						<td style=min-width:50px>kube-systm or kube-public</td>
						<td style=min-width:50px>Domain should should not be used by users</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px;color:darkorange>Need to be added to appshield:</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>18</td>
						<td style=min-width:50px>Use CNI plugin that supports NetworkPolicy API</td>
						<td style=min-width:50px>check cni plugin installed</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>5.3.1 Ensure that the CNI in use supports Network Policies (need to be fixed)</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>19</td>
						<td style=min-width:50px>Create policies that select Pods using podSelector and/or the namespaceSelector</td>
						<td style=min-width:50px>Create policies that select Pods using podSelector and/or the namespaceSelector</td>
						<td style=max-width:50px>Pod,ReplicationController,ReplicaSet,StatefulSet,DaemonSet,Job,CronJob</td>
						<td style=min-width:50px>Conftest</td>
						<td style=min-width:50px;color:darkorange>Need to be added to appshield: https://kubernetes.io/docs/concepts/services-networking/network-policies/</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>20</td>
						<td style=min-width:50px>use a default policy to deny all ingress and egress traffic. Ensures unselected Pods are isolated to all namespaces except kube-system</td>
						<td style=min-width:50px>check that netowork policy deny all exist</td>
						<td style=min-width:50px>NetworkPolicy</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px;color:darkorange>Add logic to kube-bench https://kubernetes.io/docs/concepts/services-networking/network-policies/</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>21</td>
						<td style=min-width:50px>Use LimitRange and ResourceQuota policies to limit resources on a namespace or Pod level</td>
						<td style=min-width:50px>check the limit range resource has been define</td>
						<td style=min-width:50px>LimitRange</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px;color:darkorange>Add Logic to kube-bench https://kubernetes.io/docs/concepts/policy/limit-range/</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>22</td>
						<td style=min-width:50px>TLS encryption</td>
						<td style=min-width:50px>control plan disable insecure port</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.19 Ensure that the --insecure-port argument is set to 0</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>23</td>
						<td style=min-width:50px>Etcd encryption</td>
						<td style=min-width:50px>encrypt etcd communication</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>24</td>
						<td style=min-width:50px>Kubeconfig files</td>
						<td style=min-width:50px>ensure file permission</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>4.1.3, 4.1.4</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>25</td>
						<td style=min-width:50px>Worker node segmentation</td>
						<td style=min-width:50px>node segmentation</td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px>Note sure can be tested</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>26</td>
						<td style=min-width:50px>Encryption</td>
						<td style=min-width:50px>check that encyption resource has been set</td>
						<td style=min-width:50px>EncryptionConfiguration</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px;color:darkorange>Add Logic to kube-bench https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>27</td>
						<td style=min-width:50px>Encryption / secrets</td>
						<td style=min-width:50px></td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.33 Ensure that the --encryption-provider-config argument is set as</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>28</td>
						<td style=min-width:50px>authentication</td>
						<td style=min-width:50px></td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.1 Ensure that the --anonymous-auth argument is set to false</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>29</td>
						<td style=min-width:50px>Role-based access control</td>
						<td style=min-width:50px>--authorization-mode=RBAC</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.7/1.2.8 Ensure that the --authorization-mode argument is not set to AlwaysAllow</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>30</td>
						<td style=min-width:50px>Audit policy file</td>
						<td style=min-width:50px>check that policy is configure</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>3.2.1 Ensure that a minimal audit policy is created</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>31</td>
						<td style=min-width:50px>Audit log path</td>
						<td style=min-width:50px>check that log path is configure</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.22 Ensure that the --audit-log-path argument is set</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>32</td>
						<td style=min-width:50px>Audit log max age</td>
						<td style=min-width:50px>check audit log againg</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px>1.2.23 Ensure that the --audit-log-maxage argument is set to 30 or as appropriate</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px>33</td>
						<td style=min-width:50px>service mesh usage</td>
						<td style=min-width:50px>check serive mesh is used in cluster</td>
						<td style=min-width:50px>Node</td>
						<td style=min-width:50px>Kube-bench</td>
						<td style=min-width:50px;color:darkorange>Add Logic to kube-bench check service mesh existenace</td>
					</tr>
					<tr>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
						<td style=min-width:50px></td>
					</tr>
				</table>

```