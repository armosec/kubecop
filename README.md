# kubecop 🚨🚔🚨
Kubecop is a first of it's kind KDR - Kubernetes Detection and Response tool. It is designed to be a simple, easy to use, and effective tool for detecting and responding to threats in your Kubernetes cluster at runtime!<br>
It is packed with an advanced rule engine that allows you to write rules that can detect and respond to threats in your cluster and more specifically in your workload itself🛡️.

## Development setup

Clone this repository then do the following:
```bash
make deploy-dev-pod # Deploying dev pod on your cluster
make install        # Build and deploy the binaries (installing them in the dev Pod)
make open-shell     # Open a shell on the development Pod
kubcop              # Running the kubecop in the development Pod
```

To test it, in a different shell install the application profile for Nginx and deploy Nginx
```bash
kubectl apply -f dev/nginx/nginx-app-profile.yaml
kubectl apply -f dev/nginx/nginx-deployment.yaml
```

and now open a shell on the Nginx Pod which will trigger un-whitelisted alert in the KubeCop
```bash
kubectl exec -it $(kubectl get pods -l app=nginx -o=jsonpath='{.items[0].metadata.name}') -- sh
```

you should get this on the KubeCon console:
```
&{nginx ad5d83bb20617b086ec8ec384ac76976d2ac4aa39d8380f2ae3b0080d205edc5 nginx-deployment-cbdccf466-jhvb7 default 1699770928201031673 0} - Alert exec call "/bin/sh" is not whitelisted by application profile```
