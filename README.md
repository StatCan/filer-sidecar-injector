# filer-sidecar-injector

This is forked off of the repo [kube-sidecar-injector](https://github.com/morvencao/kube-sidecar-injector) and was a repo used for [a tutorial at Medium](https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74) to create a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a nginx sidecar container into pod prior to persistence of the object.

## Forked for Filer usage
Specifically for use with Filers.

## Mutating the Pod
This webhook intercepts `pod` create requests and will `jsonpatch` the spec. Whether or not to mutate the pod spec happens in the `mutate` function. If the user namespace does not have an `existing-shares` configmap, or the pod does not have the `notebook-name` label present then it will not mutate and `inject` the filer sidecars.

## Creating the jsonpatch
This is all done in the `createPatch` function. The very first thing that is done is determine if the pod _already has a volume_. This is because we do not want to overwrite any existing volumes in the `jsonpatch` as adding a new entry is very different from appending one.
From there the `existing-shares` configmap is iterated through in order to create a new sidecar spec for each entry. 

### Getting the values to use in the json patch
For the sidecar spec we have to use the `filer-sidecar-injector-json` configmap object from the `das` namespace, this works as the model / structure that we will modify and inject into the `pod` spec. 

We also need to get the bucket url, name, secret and access key for the particular svm. The bucket url is taken from the `filers-list` cm in the `das` namespace that is read in at injector startup. The bucket name is taken from the `existing-shares` cm and is put through the same hashing function used when creating the bucket in order to mount to the correct one. The secret and access keys are read in from a secret in the user's namespace. If any of these key values are empty then the sidecar will skip as the mounting would just fail.

### Inserting the values
Using the json template that we deep copy (to avoid modifying the same one over and over again and thus only getting the last changes), we substitute the values in and call various `addX` or `updateX` functions whose only purpose is to return a `[]patchOperation`. These are self explanatory but we will note any exceptional cases below.

### updateWorkingVolumeMounts
This function adds a volume mount to the user container spec. To determine if we are modifying the correct container we use the `NB_PREFIX` environment variable which is present and if you are testing with a podspec ensure this variable is there. 

### updateUserEnvVars
The sidecar injector will also insert environment variables that users can leverage with the `minio client` or `mc`. These are inserted at the notebook container level so they may use them from within their notebook. This also relies on the `NB_PREFIX` environment variable.

### Extra Quirks
When retrieving the secrets, we need to replace any `_`'s with `-`'s as k8s resources do not like underscores, however, when creating the user environment variables those need to have underscores, as linux works better with underscores.

We also must limit the length of the names in the spec. There is a hard 64 character limit and currently to avoid collision we hash the name and use it. A better fix for this will be tracked in [BTIS-528](https://jirab.statcan.ca/browse/BTIS-528)

We built in a [retry on failure](https://github.com/StatCan/filer-sidecar-injector/pull/13) command for `goofys` as it is currently unclear why goofys sometimes fails to mount, but in general having it retry a few times seems to fix things with more investigation being done in [BTIS-523](https://jirab.statcan.ca/browse/BTIS-523)

### Building and Deploying for testing
Create a PR with the `auto-deploy` label, and after the image has successfully pushed to the ACR, go to the `netapp` application in das argocd and turn off autosync and update the `filer-sidecar-injector` image tag with the pushed image. Start up a notebook and ensure it patches correctly.