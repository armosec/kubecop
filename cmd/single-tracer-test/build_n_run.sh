#!/bin/bash
go build single-tracer.go || exit 1
kubectl apply -f ../../dev/dev-daemonset.yaml
POD_NAME=$(kubectl -n tracer-example get pods -l k8s-app=tracer-example -o jsonpath="{.items[0].metadata.name}")
kubectl cp single-tracer tracer-example/$POD_NAME:/bin/single-tracer
kubectl exec -n tracer-example -it $POD_NAME -- /bin/single-tracer