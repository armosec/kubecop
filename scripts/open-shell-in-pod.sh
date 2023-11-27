#!/bin/bash

export NAMESPACE=kapprofiler-dev-env

# for each pod in the namespace, run the command in the background and store the pid in cop_pids.txt file
POD_LIST=$(kubectl -n $NAMESPACE get pods -l k8s-app=kapprofiler-dev-env -o jsonpath="{.items[*].metadata.name}")

# Take the first pod from the list
POD_NAME=$(echo $POD_LIST | cut -d' ' -f1)

# If there are multiple pods, let the user choose one
if [ $(echo $POD_LIST | wc -w) -gt 1 ]; then
    echo "Multiple pods found in the namespace $NAMESPACE. Please choose one:"
    select POD_NAME in $POD_LIST; do
        break
    done
fi

kubectl exec -it $POD_NAME -n $NAMESPACE -- bash
