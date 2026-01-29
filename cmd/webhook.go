package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/barkimedes/go-deepcopy"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

const (
	admissionWebhookAnnotationInjectKey = "filer-injector-webhook.das-zone.statcan/inject"
)

const existingShares = "existing-shares"
const svmCmName = "filers-list"

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

type SvmInfo struct {
	Vserver string `json:"vserver"`
	Name    string `json:"name"`
	Uuid    string `json:"uuid"`
	Url     string `json:"url"`
}

// Use for easy adding of values
type M map[string]interface{}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type Config struct {
	Containers []corev1.Container `json:"containers"`
	Volumes    []corev1.Volume    `json:"volumes"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func loadConfig(configFile string) (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(metadata *metav1.ObjectMeta) bool {
	// Pod must have that label to get picked up
	if _, ok := metadata.Labels["notebook-name"]; !ok {
		infoLogger.Printf("Skip mutation since not a notebook pod")
		return false
	}
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
	default:
		required = true
	case "n", "not", "false", "off", "injected":
		required = false
	}

	infoLogger.Printf("Mutation policy for %v/%v: required:%v", metadata.Namespace, metadata.Name, required)
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string) (patch []patchOperation) {
	if target == nil || target[admissionWebhookAnnotationInjectKey] == "" {
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  "/metadata/annotations/filer-injector-webhook.das-zone.statcan~1inject",
			Value: "injected",
		})
	} else {
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  "/metadata/annotations/filer-injector-webhook.das-zone.statcan~1inject",
			Value: "injected",
		})
	}

	return patch
}

// This will ADD a volumeMount to the user container spec
func updateWorkingVolumeMounts(targetContainerSpec []corev1.Container, volumeName string, bucketMount string, filerName string, isFirst bool) (patch []patchOperation) {
	for key := range targetContainerSpec {
		// if there is an envVar that has NB_PREFIX in it then we are in the right one
		for envVars := range targetContainerSpec[key].Env {
			if targetContainerSpec[key].Env[envVars].Name == "NB_PREFIX" {
				var mapSlice []M
				valueA := M{"name": volumeName,
					"mountPath": "/home/jovyan/filers/" + filerName + "/" + bucketMount,
					"readOnly":  false, "mountPropagation": "HostToContainer"}
				mapSlice = append(mapSlice, valueA)
				if isFirst {
					patch = append(patch, patchOperation{
						Op: "add",
						// the path for only the first value
						Path:  "/spec/containers/0/volumeMounts",
						Value: mapSlice,
					})
				} else {
					patch = append(patch, patchOperation{
						Op: "add",
						// Now that there is one that has created an array, this can just go after it.
						Path:  "/spec/containers/0/volumeMounts/-",
						Value: valueA,
					})
				}
			}
		}
	}
	return patch
}

// This is to add env variables, this is similar to updateWorkingVolumeMounts
// except there is no `isFirst` because the container this is patching will always have
// an environment variable existing, so we need to just _append_
func updateUserEnvVars(targetContainerSpec []corev1.Container, variableName string, variableValue string) (patch []patchOperation) {
	// We only want to modify the container with NB_PREFIX in it, because that's the user container
	for key := range targetContainerSpec {
		for envVars := range targetContainerSpec[key].Env {
			if targetContainerSpec[key].Env[envVars].Name == "NB_PREFIX" {
				valueA := M{"name": variableName, "value": variableValue}
				// it will never be the first environment variable (NB_prefix will exist)
				patch = append(patch, patchOperation{
					Op:    "add",
					Path:  "/spec/containers/0/env/-",
					Value: valueA,
				})
			}
		}
	}
	return patch
}

// createPatch function handles the mutation patch creation
func createPatch(pod *corev1.Pod, sidecarConfigTemplate *Config, clientset *kubernetes.Clientset,
	svmShareList *corev1.ConfigMap, svmInfoMap map[string]SvmInfo) ([]byte, error) {
	var patch []patchOperation
	resourceRequest := map[corev1.ResourceName]resource.Quantity{
		"cpu":    resource.MustParse("0.1"),
		"memory": resource.MustParse("100Mi"),
	}
	resourceLimit := map[corev1.ResourceName]resource.Quantity{
		"cpu":    resource.MustParse("0.5"),
		"memory": resource.MustParse("10Gi"),
	}
	isFirstVol := true
	// We don't want to overwrite any mounted volumes
	if len(pod.Spec.Volumes) > 0 {
		isFirstVol = false
	}

	// shareList.Data is a map[string]string
	// https://goplay.tools/snippet/zUiIt23ZYVK
	var shareList []string
	for svmName := range svmShareList.Data {
		svmSecretName := strings.ReplaceAll(svmName, "_", "-") + "-conn-secret"
		// Retrieve the associated secret with the svm
		secret, err := clientset.CoreV1().Secrets(pod.Namespace).Get(context.Background(),
			svmSecretName, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			klog.Infof("Error, secret for svm:" + svmName + " was not found for ns:" + pod.Namespace +
				" so mounting will be skipped")
			continue
		}
		s3Url := string(svmInfoMap[svmName].Url)
		s3Access := string(secret.Data["S3_ACCESS"])
		s3Secret := string(secret.Data["S3_SECRET"])
		// Unmarshal to get list of wanted shares to mount
		err = json.Unmarshal([]byte(svmShareList.Data[svmName]), &shareList)
		if err != nil {
			klog.Infof("Error unmarshalling the share list for svm:" + svmName +
				" for ns:" + pod.Namespace + " so mounting will be skipped")
			continue
		}
		// must set ACCESS and SECRET keys as well as svm url in the patch
		patch = append(patch, updateUserEnvVars(pod.Spec.Containers, svmName+"_access", s3Access)...)
		patch = append(patch, updateUserEnvVars(pod.Spec.Containers, svmName+"_secret", s3Secret)...)
		patch = append(patch, updateUserEnvVars(pod.Spec.Containers, svmName+"_url", s3Url)...)
		shortenedNs := limitNs(pod.Namespace)
		// iterate through and do the patch
		for share := range shareList {
			// Deep copy to avoid changes in original sidecar config
			tempSidecarConfig, _ := deepcopy.Anything(sidecarConfigTemplate)
			sidecarConfig := tempSidecarConfig.(*Config)
			bucketMount := shareList[share]
			// Validation: Ensure bucketMount, S3_URL, S3_ACCESS, and S3_SECRET are present and not empty
			if bucketMount == "" || s3Url == "" || s3Access == "" || s3Secret == "" {
				warningLogger.Printf("Skipping secret %s in namespace %s: one or more required fields are empty (bucketMount: %s, S3_URL: %s, S3_ACCESS: %s, S3_SECRET: %s)",
					secret.Name, pod.Namespace, bucketMount, s3Url, s3Access, s3Secret)
				continue // Skip this secret if any of the necessary values are empty
			}

			hashedBucketName := hashBucketName(bucketMount)
			// Configure the sidecar container
			sidecarConfig.Containers[0].Args = []string{"-c", "for i in {1..5}; do /goofys --cheap --endpoint " + s3Url +
				" --http-timeout 1500s --dir-mode 0777 --file-mode 0777  --debug_fuse --debug_s3 -o allow_other -f " +
				hashedBucketName + " /tmp;echo '---- goofys command failed: trying again'; sleep 1; done;" +
				"echo 'goofys command failed 5 times sleeping'; sleep infinity"}

			filerBucketName := limitString(svmName, 5) + "-" + hashedBucketName
			sidecarConfig.Containers[0].Name = filerBucketName
			sidecarConfig.Containers[0].Env[0].Value = "fusermount3-proxy-" + filerBucketName + "-" + shortenedNs + "/fuse-csi-ephemeral.sock"
			sidecarConfig.Containers[0].Env[1].Value = s3Access
			sidecarConfig.Containers[0].Env[2].Value = s3Secret
			sidecarConfig.Containers[0].Env[3].Value = s3Url[8:] // want everything after https://
			sidecarConfig.Containers[0].Resources.Limits = resourceLimit
			sidecarConfig.Containers[0].Resources.Requests = resourceRequest

			fdPassingvolumeMountName := "fuse-fd-passing-" + filerBucketName + "-" + shortenedNs
			sidecarConfig.Containers[0].VolumeMounts[0].Name = fdPassingvolumeMountName
			sidecarConfig.Containers[0].VolumeMounts[0].MountPath = "fusermount3-proxy-" + filerBucketName + "-" + shortenedNs

			sidecarConfig.Volumes[0].Name = fdPassingvolumeMountName
			csiEphemeralVolumeountName := "fuse-csi-ephemeral-" + filerBucketName + "-" + shortenedNs
			sidecarConfig.Volumes[1].Name = csiEphemeralVolumeountName
			sidecarConfig.Volumes[1].CSI.VolumeAttributes["fdPassingEmptyDirName"] = fdPassingvolumeMountName

			// Add container to initContainers and volume to the patch
			patch = append(patch, addContainer(pod.Spec.InitContainers, sidecarConfig.Containers, "/spec/initContainers")...)
			// Add restartPolicy: Always to allow sidecar to terminate when main container completes
			patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)
			patch = append(patch, updateAnnotation(pod.Annotations)...)
			patch = append(patch, updateWorkingVolumeMounts(pod.Spec.Containers, csiEphemeralVolumeountName, bucketMount, svmName, isFirstVol)...)
			// Add the environment variables
			patch = append(patch, updateUserEnvVars(pod.Spec.Containers, svmName+"_"+cleanAndSanitizeName(bucketMount), hashedBucketName)...)
			isFirstVol = false // Update such that no longer the first value

		} // end shareList loop
	} // end loop through user configmap

	return json.Marshal(patch)
}

// Used for variable insertion, as dashes are no good but underscores are
func cleanAndSanitizeName(name string) string {
	// Define the allowed regex pattern: Alphanumeric and dashes
	name = strings.ReplaceAll(name, "/", "-")
	validNameRegex := regexp.MustCompile(`[^a-zA-Z0-9-]`)

	// Replace any character that does not match the allowed pattern with an empty string
	name = validNameRegex.ReplaceAllString(name, "")

	// Remove trailing dashes
	name = strings.TrimRight(name, "-")

	// Remove leading dashes
	name = strings.TrimLeft(name, "-")

	// Replace double dashes with a single dash
	pattern := regexp.MustCompile(`-+`)
	name = pattern.ReplaceAllString(name, "-")

	// Replace dashes with underscores
	name = strings.ReplaceAll(name, "-", "_")

	return name
}

// Function to ensure name uniqueness by appending an integer if the name already exists
func limitNs(ns string) string {
	stringSlice := strings.Split(ns, "-")
	return limitString(stringSlice[len(stringSlice)-1], 5) + limitString(stringSlice[0], 2)
}

// Helper function to limit string length
func limitString(input string, limit int) string {
	if len(input) > limit {
		return input[:limit]
	}
	return input
}

// Applies a hash function to the bucketname to make it S3 compliant
func hashBucketName(name string) string {
	h := fnv.New64a()
	h.Write([]byte(name))
	return strconv.FormatUint(h.Sum64(), 10)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *admissionv1.AdmissionReview, clientset *kubernetes.Clientset, svmInfoMap map[string]SvmInfo) *admissionv1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		warningLogger.Printf("Could not unmarshal raw object: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	infoLogger.Printf("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// Retrieves the configmap containing the list of shares. Must loop through this
	// Format is "filer1": '["share1", "share2"]'
	svmShareList, errorSvm := clientset.CoreV1().ConfigMaps(pod.Namespace).Get(context.Background(), existingShares, metav1.GetOptions{})

	// determine whether to perform mutation
	if k8serrors.IsNotFound(errorSvm) || !mutationRequired(&pod.ObjectMeta) {
		infoLogger.Printf("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, clientset, svmShareList, svmInfoMap)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	infoLogger.Printf("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	// Creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// Creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// Retrieve the das main configmap containing information on the svms (filers)
	// [{vserver: fld5filersvm..., url: https... }, ]
	svmInfoMap, err := getSvmInfoList(clientset)
	if err != nil {
		klog.Fatalf("Error retrieving SVM map: %s", err.Error())
	}

	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		warningLogger.Println("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		warningLogger.Printf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *admissionv1.AdmissionResponse
	ar := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		warningLogger.Printf("Can't decode body: %v", err)
		admissionResponse = &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar, clientset, svmInfoMap)
	}

	admissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
	}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		warningLogger.Printf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	infoLogger.Printf("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		warningLogger.Printf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func getSvmInfoList(client *kubernetes.Clientset) (map[string]SvmInfo, error) {
	klog.Infof("Getting filers list...")

	filerListCM, err := client.CoreV1().ConfigMaps(os.Getenv("POD_NAMESPACE")).Get(context.Background(), "filers-list", metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Error occured while getting the filers list: %v", err)
		return nil, err
	}

	var svmInfoList []SvmInfo
	err = json.Unmarshal([]byte(filerListCM.Data["filers"]), &svmInfoList)
	if err != nil {
		klog.Errorf("Error occured while unmarshalling the filers list: %v", err)
		return nil, err
	}

	//format the data into something a bit more usable
	filerList := map[string]SvmInfo{}
	for _, svm := range svmInfoList {
		filerList[svm.Vserver] = svm
	}

	return filerList, nil
}
