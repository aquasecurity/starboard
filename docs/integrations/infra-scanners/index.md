# Infrastructure Scanners

Starboard creates security reports from a variety of tools and vendors and makes them available as custom resources.

These are currently integrated configuration checkers:

* CIS benchmark results per node provided by kube-bench
* Pen-testing results provided by kube-hunter


## Kube-bench

The CIS benchmark for Kubernetes provides prescriptive guidance for system and application administrators, security specialists, auditors, help desk, and platform deployment personnel who are responsible for establishing secure configuration for solutions that incorporate Kubernetes.

```
kubectl starboard scan ciskubebenchreports
kubectl get ciskubebenchreports -o wide
```

<details>
<summary>Result</summary>

```
NAME                   SCANNER      AGE     FAIL   WARN   INFO   PASS
k8s-ws-control-plane   kube-bench   3d14h   1      27     0      26
k8s-ws-worker          kube-bench   3d14h   1      27     0      19
k8s-ws-worker2         kube-bench   3d14h   1      27     0      19
```

</details>

## Kube-hunter

kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.

```
kubectl starboard scan kubehunterreports
kubectl get kubehunterreports -o wide
```
