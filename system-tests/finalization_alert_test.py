from kubernetes_wrappers import Namespace, Workload, KubernetesObjects
import os
import time

def finalization_alert_test(test_framework):
    print("Running simple finalization alert test")

    # Create a namespace
    ns = Namespace(name=None)

    if ns:
        # Create a workload
        workload = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directoty(),"resources/nginx-deployment.yaml"))

        # Wait for the workload to be ready
        workload.wait_for_ready(timeout=120)

        # Wait for 160 seconds to allow the profiling process to end and do finalization
        time.sleep(160)

        # Exec into the nginx pod and create a file in the /tmp directory
        workload.exec_into_pod(command=["touch", "/tmp/nginx-test"])

        # Wait for the alert to be signaled
        time.sleep(5)

        # Get all the alert for the namespace
        alerts = test_framework.get_alerts(namespace=ns)

        # Validate that all alerts are signaled
        expected_alerts = [
            "Unexpected process launched"
        ]

        for alert in alerts:
            rule_name = alert['labels']['rule_name']
            if rule_name in expected_alerts:
                expected_alerts.remove(rule_name)

        assert len(expected_alerts) == 0, f"Expected alerts {expected_alerts} were not signaled"

