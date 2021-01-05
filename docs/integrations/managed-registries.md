## Amazon Elastic Container Registry (ECR)

You must create an IAM OIDC identity provider for your cluster:

```
eksctl utils associate-iam-oidc-provider \
  --cluster <cluster_name> \
  --approve
```

Assuming that the operator is installed in the `<starboard_operator_namespace>`
namespace you can override the existing `starboard-operator` service account and
attach the IAM policy to grant it permission to pull images from the ECR:

```
eksctl create iamserviceaccount \
  --name starboard-operator \
  --namespace <starboard_operator_namespace> \
  --cluster <cluster_name> \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
  --approve \
  --override-existing-serviceaccounts
```
