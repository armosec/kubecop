# kubecop 🚨🚔🚨
Kubecop is a first of it's kind KDR - Kubernetes Detection and Response tool. It is designed to be a simple, easy to use, and effective tool for detecting and responding to threats in your Kubernetes cluster at runtime!<br>
It is packed with an advanced rule engine that allows you to write rules that can detect and respond to threats in your cluster.

## Installation
To deploy kubecop locally you can use the following commands:
```bash
git clone https://github.com/armosec/kubecop.git
cd kubecop
docker build -t quay.io/benarmosec/kubecop:latest ./
kind load docker-image quay.io/benarmosec/kubecop:latest
kubectl apply -f deployment/deployment.yaml
```
