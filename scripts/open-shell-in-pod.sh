#!/bin/bash

export NAMESPACE=kapprofiler-dev-env
echo "" > cop_pids.txt

# for each pod in the namespace, run the command in the background and store the pid in cop_pids.txt file
POD_LIST=$(kubectl -n $NAMESPACE get pods -l k8s-app=kapprofiler-dev-env -o jsonpath="{.items[*].metadata.name}")
for POD in $POD_LIST; do
    echo "Running in $POD"
    kubectl exec -t $POD -n $NAMESPACE -- rm -f /tmp/execve-events.db
    kubectl exec -t $POD -n $NAMESPACE -- /bin/kubecop &
    echo $! >> cop_pids.txt
done

# export POD=$(kubectl -n $NAMESPACE get pods -l k8s-app=kapprofiler-dev-env -o jsonpath="{.items[0].metadata.name}")

# kubectl exec -it $POD -n $NAMESPACE -- /bin/kubecop