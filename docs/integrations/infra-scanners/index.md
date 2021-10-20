# Infrastructure Scanners

Currently, these are the tools for infrastructure checking in Kubernetes:

* CIS benchmark results per node provided by [kube-bench](https://github.com/aquasecurity/kube-bench)
* Pen-testing results provided by [kube-hunter](https://github.com/aquasecurity/kube-hunter)


## Kube-bench

The CIS benchmark for Kubernetes provides prescriptive guidance for system and application administrators, security specialists, auditors, help desk, and platform deployment personnel who are responsible for establishing secure configuration for solutions that incorporate Kubernetes.

Currently, you can obtain the results using starboard operator and starboard client.

Here the scan results using starboard client (installed by krew).

> *scan ciskubebenchreports: Run the CIS Kubernetes Benchmark for each node of your cluster*
```
kubectl starboard scan ciskubebenchreports -v 3
```

Check the ciskubebenchreports generated:
```
kubectl get ciskubebenchreports -o wide
```

<details>
<summary>Result</summary>

```
NAME                   SCANNER      AGE     FAIL   WARN   INFO   PASS
k8s-local-control-plane   kube-bench   3d14h   1      27     0      26
k8s-local-worker          kube-bench   3d14h   1      27     0      19
k8s-local-worker2         kube-bench   3d14h   1      27     0      19
```
</details>

Generate the report HTML
```
k starboard get report nodes/k8s-local-worker > node01-report.html
```

```
open node01-report.html
```

![HTML Report](../../images/node01-report.png)

## Kube-hunter

kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.

Currently, you can obtain the results using **only** starboard client.

Here the scan results.

> *scan kubehunterreports: Hunt for security weaknesses in your Kubernetes cluster*
```
kubectl starboard scan kubehunterreports -v 3
```

Check the kubehunterreports generated:
```
kubectl get kubehunterreports -o wide
```

<details>
<summary>Result</summary>

```
NAME      SCANNER       AGE   HIGH   MEDIUM   LOW
cluster   kube-hunter   27h   0      0        1
```
</details>