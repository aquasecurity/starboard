# Proposal: Vulnerability scanning using Trivy file system scanner

Author(s): [ [Devendra Turkar](https://github.com/deven0t), [Daniel Pacak](https://github.com/danielpacak) ]

## Abstract

Add additional support in Trivy plugin to support file system scanning of an image. 

## Background

Starboard currently uses Trivy plugin to scan and generate Vulnerability Report for an image. Starboard runs Trivy as K8s 
Job and therefore we do not have access to images cached by container runtime on cluster nodes. Hence, Trivy requires 
credentials pass as TRIVY_USERNAME and TRIVY_PASSWORD envs to pull down an image before scan. Trivy can scan a container 
image by pulling the image from a remote registry. This mechanism works good for public registry image, but for private 
registry image Trivy is dependent on registry credentials. Currently, starboard has mechanism to provide these credentials
using ImagePullSecret or with ServiceAccount, based on how it is provided to application pod.
With this approach we have following problem:
1. When image pulled from private registry without ImagePullSecret or service account 
(https://kubernetes.io/docs/concepts/containers/images/#configuring-nodes-to-authenticate-to-a-private-registry)  
2. When image pulled from managed registry of managed cluster. Eg. in EKS cluster, user can authorize specific service 
account or node to pull image from managed registry.

Theoretically we could use hostPath volume mounts and other hacks, but it has its own disadvantages that we are trying to avoid. 
For example, more permissions and knowledge about infrastructure such as container runtime implementation. 

## Proposal

Use Trivy file system scanning option to scan an image. So that we will not need to provide registry credentials to trivy.
For the current proposal the main idea is to schedule a scan job on the same node where the scanned workload so we can 
leverage container image cached on that node and scan without providing credentials to Trivy. 
Same idea is talked here in POC [#692](https://github.com/aquasecurity/starboard/discussions/692)

### High level idea

Run scan job with image which we want to scan and override the default entrypoint of image with following command
```shell script
trivy fs --ignore-unfixed /
```
With above command trivy will scan entire file system of an image and it will give us the result.

To run trivy in that image we need trivy to be available in the container. To solve this problem we have a way for it.
1. Add an init container with tvivy image in the scan job which will pull trivy image, Copy trivy executable in a volume
 which will be shared with main container 
2. Add another init container to download trivy database and mount db file in volume which will be used as trivy database
during file system scan. This init container is only needed for Standalone mode, which only supported mode by file system
scanner.

### TL;DR;

Currently, clientServer mode is not supporting filesystem scan. So we will have to go with standalone mode. In future we
 can change it to client server mode and accordingly we will have to change our scan job spec.
 
 Configuration parameter can be added to enable this scan mode
``trivy.command: fs``. This trivy.command will support two values ``image`` and ``fs``. For backward compatibility. if 
this config parameter is not defined then it will consider it as ``image``.

We have two options to consider here
1. We can restrict scan job to run on same host where original pod is running.
    - ImagePullPolicy will be set to `Never`, so we will not need to pull the image on node
    - nodeName has to be provided for scan job to run on specific node
2. Allow scan job to run on any node in the cluster.  *This option will not be implemented for now*
    - ImagePullPolicy should be set as IfNotPresent
    - nodeName will be set as empty, so that scan job will run on any node.
    - make ImagePullSecret available for scan job
    
## Scan job running on same host

To run scan on same host where application pod is running then we have to identify host on which application pod is 
running. To do this we will search for active pod for any controller and we will get the nodename from first pod of it.

1. Scan job has to run on same host where pod is running.
    - Get the nodename of one of the pod. If we dont get nodename then return error.
    - No need to copy secret from the source namespace to starboard-operator namespace. We will ignore imagePullSecret of 
    source application workload.
    - ImagePullPolicy will be set as Never
    - nodeName will be passed explicitly. So that scan job is scheduled on same node where workload is running.

#### Example
 Reference is taken from [here](https://github.com/aquasecurity/starboard/discussions/692)
 
Let's assume that there's the `nginx` Deployment in the `poc-ns` namespace. It is running with 
image(`example.registry.com/nginx`) from from private registry `example.registry.com`. Registry is configured with secret
name `private-registry`. Same is provided in pod spec under ImagePullSecret(this registry can be configured at service account 
level as well).

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: poc-ns
spec: { }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: nginx
  name: nginx
  namespace: poc-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      imagePullSecrets:
        - name: private-registry
      nodeName: kind-control-plane
      containers:
        - name: nginx
          image: example.registry.com/nginx:1.16
``` 

 
***On Same Host***

To scan the `nginx` container of such Deployment, Starboard could create the following scan job in the 
`starboard-operator` namespace and observe it until it's completed or failed. Some points to note here
- In this mode, we don't need imagePullSecret/any secret to pass to scan job
- ImagePullPolicy should be set as Never
- nodeName should be configured explicitly. 

```yaml
---
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-nginx-with-trivy
  namespace: starboard-operator
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      # Explicit nodeName indicates our intention to schedule a scan pod
      # on the same node where the nginx workload is running.
      # This could also imply considering taints and tolerations and other
      # properties respected by K8s scheduler.
      nodeName: kind-control-plane
      volumes:
        - name: scan-volume
          emptyDir: { }
      initContainers:
        # The trivy-get-binary init container is used to copy out the trivy executable
        # binary from the upstream Trivy container image, i.e. aquasec/trivy:0.19.2,
        # to a shared emptyDir volume.
        - name: trivy-get-binary
          image: aquasec/trivy:0.19.2
          command:
            - cp
            - -v
            - /usr/local/bin/trivy
            - /var/starboard/trivy
          volumeMounts:
            - name: scan-volume
              mountPath: /var/starboard
         # The trivy-download-db container is using trivy executable binary
         # from the previous step to download Trivy vulnerability database
         # from GitHub releases page.
        - name: trivy-download-db
          image: aquasec/trivy:0.19.2
          command:
            - /var/starboard/trivy
            - --download-db-only
            - --cache-dir
            - /var/starboard/trivy-db
          volumeMounts:
            - name: scan-volume
              mountPath: /var/starboard
      containers:
        # The scan-nginx container is based on the container image that
        # we want to scan with Trivy. However, it has overwritten command (entrypoint)
        # to invoke trivy file system scan. The scan results are output to stdout
        # in JSON format so we can parse them and store as VulnerabiltyReport instance.
        - name: scan-nginx
          image: example.registry.com/nginx:1.16
          # To scan image layers cached on K8s node without pulling
          # it from a remote registry.
          imagePullPolicy: Never
          securityContext:
            # As Trivy need to run as root user, so we will have to pass explicite runasuser id 0
            # this will impact get impacted with PSP MustRunAsNonRoot
            runAsUser: 0
          command:
            - /var/starboard/trivy
            - --cache-dir
            - /var/starboard/trivy-db
            - fs
            - --format
            - json
            - --ignore-unfixed
            - /
          volumeMounts:
            - name: scan-volume
              mountPath: /var/starboard
```

##### Current Limitations for this option:
1. If controller is created, and it doesn’t have any active pods then this mode will not scan it
2. We cannot identify pods running for cronjob, so those will not be scanned.

### Note:
1. This will be implemented with only standalone mode till we trivy supports clientServer mode in filesystem scan command
    - Due to this Standalone mode we will have following problems
        1. For each scan job, trivy db will be downloaded and Trivy db download will take more time.
        2. Rate limiting on github
