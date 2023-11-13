#!/bin/bash
set -e

# Check that we got a filename as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

export NAMESPACE=kapprofiler-dev-env
# for each pod in the namespace, copy the file to the pod
POD_LIST=$(kubectl -n $NAMESPACE get pods -l k8s-app=kapprofiler-dev-env -o jsonpath="{.items[*].metadata.name}")
for POD in $POD_LIST; do
    kubectl cp $1 $NAMESPACE/$POD:/bin/$1
done
# export POD=$(kubectl -n $NAMESPACE get pods -l k8s-app=kapprofiler-dev-env -o jsonpath="{.items[0].metadata.name}")

# kubectl cp $1 $NAMESPACE/$POD:/bin/$1