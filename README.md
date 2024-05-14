# filer-sidecar-injector

This is forked off of the repo [kube-sidecar-injector](https://github.com/morvencao/kube-sidecar-injector) and was a repo used for [a tutorial at Medium](https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74) to create a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a nginx sidecar container into pod prior to persistence of the object.

## Forked for Filer usage
Specifically for use with Filers.

### Gotcha's
Make sure that the namespace you want injected has the `filer-sidecar-injection: enabled` label on it. This will then add the sidecar to pods that have the `notebook-name` label present.
Ensure that there is a secret whose name contains `filer-conn-secret` in the namespace with the following populated;
``` 
S3_ACCESS
S3_BUCKET
S3_URL
S3_SECRET
```
Is there the `NB_PREFIX environment variable present on the user container? We use the existence of the value to determine where to put the volume mount.

### Building and Deploying for testing
You will need acr access, 
```
az acr login -n k8scc01covidacr
docker build . -t k8scc01covidacr.azurecr.io/filer-sidecar:latest
docker push k8scc01covidacr.azurecr.io/filer-sidecar:latest
kubectl apply -f deploy/deployment.yaml
kubectl rollout restart deployments filer-sidecar-injector -n das
```
