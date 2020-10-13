#!/usr/bin/env bash

OLM_VERSION=0.15.1
MARKETPLACE_VERSION=4.5
OPERATOR_MARKETPLACE_VERSION="release-${MARKETPLACE_VERSION}"

curl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/${OLM_VERSION}/install.sh | bash -s ${OLM_VERSION}
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/01_namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/03_operatorsource.crd.yaml
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/04_service_account.yaml
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/05_role.yaml
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/06_role_binding.yaml
sleep 1
kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/07_upstream_operatorsource.cr.yaml
curl -sL https://raw.githubusercontent.com/operator-framework/operator-marketplace/${OPERATOR_MARKETPLACE_VERSION}/deploy/upstream/08_operator.yaml | \
sed -e "s;quay.io/openshift/origin-operator-marketplace:latest;quay.io/openshift/origin-operator-marketplace:${MARKETPLACE_VERSION};" | \
kubectl apply -f -
