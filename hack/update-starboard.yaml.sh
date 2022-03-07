#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_ROOT=$SCRIPT_ROOT/deploy/crd
STATIC_ROOT=$SCRIPT_ROOT/deploy/static

cat $CRD_ROOT/vulnerabilityreports.crd.yaml \
  $CRD_ROOT/configauditreports.crd.yaml \
  $CRD_ROOT/clusterconfigauditreports.crd.yaml \
  $CRD_ROOT/ciskubebenchreports.crd.yaml \
  $CRD_ROOT/clustercompliancereports.crd.yaml \
  $CRD_ROOT/clustercompliancedetailreports.crd.yaml \
  $STATIC_ROOT/01-starboard-operator.ns.yaml \
  $STATIC_ROOT/02-starboard-operator.rbac.yaml \
  $STATIC_ROOT/03-starboard-operator.config.yaml \
  $STATIC_ROOT/04-starboard-operator.policies.yaml \
  $STATIC_ROOT/05-starboard-operator.deployment.yaml > $STATIC_ROOT/starboard.yaml
