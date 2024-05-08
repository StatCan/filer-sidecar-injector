package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

const (
	admissionWebhookAnnotationInjectKey = "filer-injector-webhook.das-zone.statcan/inject"
	admissionWebhookAnnotationStatusKey = "filer-injector-webhook.das-zone.statcan/status"
)

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

// Test this out
type M map[string]interface{}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type ConfigYaml struct {
	Containers []corev1.Container `yaml:"containers"` // try ,inline, nope failed
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

// attempt json
type Config struct {
	Containers []corev1.Container `json:"containers"`
	// do i need to add an array struct? for like volumeMounts?
	Volumes []corev1.Volume `json:"volumes"`
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
	// infoLogger.Printf("Config Found:\n" + string(data))

	var cfg Config
	// TODO check what this yaml.unmarshal is doing.
	//if err := yaml.Unmarshal(data, &cfg); err != nil {
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// infoLogger.Printf("Printing out post json unmarshal")
	// infoLogger.Printf(cfg.Containers[0].String())
	// infoLogger.Printf("Printout post json unmarshal")
	// infoLogger.Printf(cfg.Volumes[0].String())
	// infoLogger.Printf(cfg.Volumes[1].String())
	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(metadata *metav1.ObjectMeta) bool {
	// TEMPORARY
	if metadata.Namespace == "jose-matsuda" {
		infoLogger.Printf(("jose-matsuda TESTING IMAGE"))
		return true
	}
	// Initially check for labels
	if _, ok := metadata.Labels["notebook-name"]; !ok {
		infoLogger.Printf("Skip mutation since not a notebook pod")
		return false
	}
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = true
		case "n", "not", "false", "off":
			required = false
		}
	}

	infoLogger.Printf("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
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

// This might be diff if only because of the {}
func addVolumeTest(bucketName string, isFirst bool) (patch []patchOperation) {
	// Instead of using a value from the configmap we know that this config will not change at all.
	// Have to add the emptyDir as well as the csiDriver volume
	if isFirst { // then we need to create the index, only applicable to first patch
		//emptyDir
		patch = append(patch, patchOperation{
			Op: "add",
			// the path for only the first value
			Path: "/spec/volumes",
			Value: map[string]string{
				"name": "fuse-fd-passing-" + bucketName, "emptyDir": "{}",
			},
		})
		// the csiDriver
		//:{"csi":{"driver":"meta-fuse-csi-plugin.csi.storage.pfn.io","readOnly":false,"volumeAttributes":{"fdPassingEmptyDirName":"fuse-fd-passing-4","fdPassingSocketName":"fuse-csi-ephemeral.sock"}}}},
		patch = append(patch, patchOperation{
			Op:   "add",
			Path: "/spec/volumes/-",
			Value: map[string]string{
				"name": "fuse-csi-ephemeral" + bucketName,
			},
		})
	} else {
		patch = append(patch, patchOperation{
			Op: "add",
			// the path for only the first value
			Path: "/spec/containers/0/volumeMounts/-",
			Value: map[string]string{
				"name": "fuse-csi-ephemeral-" + bucketName, "mountPath": "/home/jovyan/" + bucketName,
				"readOnly": "false", "mountPropagation": "HostToContainer",
			},
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

// This will always ADD a volumeMount to the user container spec, I hope
// error when creating "ex-pod.yaml": Internal error occurred:
// json: cannot unmarshal object into Go struct field Container.spec.containers.volumeMounts
// of type []v1.VolumeMount
func updateWorkingVolumeMounts(targetContainerSpec []corev1.Container, bucketName string, isFirst bool) (patch []patchOperation) {
	for key := range targetContainerSpec {
		// This is a big assumption on /home/jovyan
		// Also an assumption that the user container is the first one.
		// Am now slightly unsure if can affect the initial container, will see
		if targetContainerSpec[key].WorkingDir == "/home/jovyan" {
			// If it is the first one, we need to create the field
			var mapSlice []M
			valueA := M{"name": "fuse-csi-ephemeral-" + bucketName, "mountPath": "/home/jovyan/" + bucketName,
				"readOnly": false, "mountPropagation": "HostToContainer"}
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
					Path: "/spec/containers/0/volumeMounts/-",
					// Value: map[string]string{
					// 	"name": "fuse-csi-ephemeral-" + bucketName, "mountPath": "/home/jovyan/" + bucketName,
					// 	"readOnly": "false", "mountPropagation": "HostToContainer",
					// },
					Value: valueA,
				})
			}
		}
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, sidecarConfig *Config, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation
	// creates the in-cluster config,
	// taken directly from https://github.com/kubernetes/client-go/blob/master/examples/in-cluster-client-configuration/main.go
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	secretList, _ := clientset.CoreV1().Secrets(pod.Namespace).List(context.Background(), metav1.ListOptions{})
	isFirst := true
	// TBD if this loop functions how I want it to.
	for sec := range secretList.Items {
		// check for secrets having filer-conn-secret
		if strings.Contains(secretList.Items[sec].Name, "filer-conn-secret") {
			// "Modify" the retrieved sidecarConfig, must verify the keys
			// For some reason some values for the values are getting overwritten, as in
			// I get fuse-fd-passing-4 for the first secret found when it should be 3
			bucketName := string(secretList.Items[sec].Data["S3_BUCKET"])
			sidecarConfig.Containers[0].Name = bucketName + "-bucket-containers"
			sidecarConfig.Containers[0].Args = []string{"-c", "/goofys --cheap --endpoint " + string(secretList.Items[sec].Data["S3_URL"]) +
				" --http-timeout 1500s --dir-mode 0777 --file-mode 0777  --debug_fuse --debug_s3 -o allow_other -f " +
				bucketName + "/ /tmp"}
			sidecarConfig.Containers[0].Env[1].Value = string(secretList.Items[sec].Data["S3_ACCESS"])
			sidecarConfig.Containers[0].Env[2].Value = string(secretList.Items[sec].Data["S3_SECRET"])
			// this VolumeMounts also gets updated to 4 for some reason
			sidecarConfig.Containers[0].VolumeMounts[0].Name = ("fuse-fd-passing-" + bucketName)

			sidecarConfig.Volumes[0].Name = ("fuse-fd-passing-" + bucketName)
			sidecarConfig.Volumes[1].Name = ("fuse-csi-ephemeral-" + bucketName)
			// see this fdPassingEmptyDirName gets updated to 4 for some reason, but Volumes.Name does not
			sidecarConfig.Volumes[1].CSI.VolumeAttributes["fdPassingEmptyDirName"] = ("fuse-fd-passing-" + bucketName)

			patch = append(patch, addContainer(pod.Spec.Containers, sidecarConfig.Containers, "/spec/containers")...)
			patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)
			// patch = append(patch, addVolumeTest(bucketName, isFirst)...)
			patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
			patch = append(patch, updateWorkingVolumeMounts(pod.Spec.Containers, bucketName, isFirst)...)
			infoLogger.Printf("All patches appended for:" + secretList.Items[sec].Name)
			isFirst = false // update such that no longer the first value
		}
	} // Surely here is where we end the loop
	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
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

	// determine whether to perform mutation
	if !mutationRequired(&pod.ObjectMeta) {
		infoLogger.Printf("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, annotations)
	infoLogger.Printf("--- All patches created ---")
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
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
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
		admissionResponse = whsvr.mutate(&ar)
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
