# Releasing

1. [ ] Checkout your fork and make sure it's up-to-date with the `upstream`
   ```console
   $ git remote -v
   origin     git@github.com:<your account>/starboard.git (fetch)
   origin     git@github.com:<your account>/starboard.git (push)
   upstream   git@github.com:aquasecurity/starboard.git (fetch)
   upstream   git@github.com:aquasecurity/starboard.git (push)
   ```
   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```
2. [ ] Prepare release by creating the PR with the following changes
   1. [ ] In `deploy/helm/Chart.yaml`
      1. [ ] Update the `version` property
      2. [ ] Update the `appVersion` property
   2. [ ] In `deploy/static/04-starbord-operator.deployment.yaml`
      1. [ ] Update the `app.kubernetes.io/version` labels
      2. [ ] Update tag in the operator's container image reference
   3. [ ] In `deploy/static/02-starboard-operator.rbac.yaml`
      1. [ ] Update the `app.kubernetes.io/version` labels
   4. [ ] In `deploy/static/02-starboard-operator.config.yaml`
      1. [ ] Update the `app.kubernetes.io/version` labels
   5. [ ] In `mkdocs.yaml`
      1. [ ] Update the `extra.var.prev_git_tag` property
      2. [ ] Update the `extra.var.chart_version` property
3. [ ] Review and merge the PR (make sure all tests are passing)
4. [ ] Update your fork again
   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```
5. [ ] Create an annotated git tag and push it to the `upstream`. This will trigger the `.github/workflow/release.yaml` workflow
   ```
   git tag -v0.13.1 -m 'Release v0.13.1'
   git push upstream v0.13.1
   ```
6. [ ] Verify that the `release` workflow has built and published the following artifacts
   1. [ ] Starboard CLI binary executables for various platforms on https://github.com/aquasecurity/starboard/releases/tag/v0.13.1
   2. [ ] Starboard container images published to DockerHub
      1. [ ] `docker.io/aquasec/starboard:0.13.1`
      2. [ ] `docker.io/aquasec/starboard-operator:0.13.1`
      3. [ ] `docker.io/aquasec/starboard-scanner-aqua:0.13.1`
   3. [ ] Starboard container images published to Amazon ECR Public Gallery
      1. [ ] `public.ecr.aws/aquasecurity/starboard:0.13.1`
      2. [ ] `public.ecr.aws/aquasecurity/starboard-operator:0.13.1`
      3. [ ] `public.ecr.aws/aquasecurity/starboard-scanner-aqua:0.13.1`
7. [ ] Publish the Helm chart by manually triggering the `.github/workflows/publish-helm-chart.yaml` workflow
8. [ ] Publish docs on https://aquasecurity.github.io/starboard/ by manually triggering the `.github/workflows/publish-docs.yaml` workflow
9. [ ] Submit Starboard Operator to OperatorHub and ArtifactHUB by opening the PR to the https://github.com/k8s-operatorhub/community-operators repository.
