# filer-sidecar-injector

This is forked off of the repo [kube-sidecar-injector](https://github.com/morvencao/kube-sidecar-injector) and was a repo used for [a tutorial at Medium](https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74) to create a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a nginx sidecar container into pod prior to persistence of the object.

## Forked for Filer usage
Specifically for use with Filers.

### Gotcha's
Make sure that the namespace you want injected has the `filer-sidecar-injection: enabled` label on it. This will then add the sidecar to pods that have the `notebook-name` label present.
