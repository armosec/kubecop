#/bin/bash

# This script is used to run system tests on a single machine.


kubectl port-forward svc/alertmanager-operated 9093:9093 -n monitoring &
ALERT_MANAGER_PORT_PID=$!
sleep 5
# Check that port forwarding is working.
if ! curl -s http://localhost:9093/api/v2/alerts > /dev/null ; then
  kill $ALERT_MANAGER_PORT_PID
  exit 1
fi
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &
PROMETHEUS_PORT_PID=$!
sleep 5
# Check that port forwarding is working if not delete the previous port forwarding.
if ! curl -s http://localhost:9090/api/v1/query?query=up  > /dev/null; then
  kill $ALERT_MANAGER_PORT_PID
  kill $PROMETHEUS_PORT_PID
  exit 1
fi

python3 system-tests/run.py
test_result=$?

kill $ALERT_MANAGER_PORT_PID
kill $PROMETHEUS_PORT_PID
exit $test_result