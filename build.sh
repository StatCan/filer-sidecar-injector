az acr login -n k8scc01covidacr
docker build . -t k8scc01covidacr.azurecr.io/filer-sidecar:latest
docker push k8scc01covidacr.azurecr.io/filer-sidecar:latest
kubectl apply -f deploy/deployment.yaml
kubectl rollout restart deployments filer-sidecar-injector -n das
sleep 10
kubectl apply -f ex-pod.yaml
kubectl logs deployment/filer-sidecar-injector -n das > logs.txt