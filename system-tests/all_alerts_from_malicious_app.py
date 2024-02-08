from kubernetes_wrappers import Namespace, Workload, KubernetesObjects
import os
import time

def all_alerts_from_malicious_app(test_framework):
    # Create a namespace
    ns = Namespace(name=None)
    profiles_namespace_name = os.environ.get("STORE_NAMESPACE")
    profiles_namespace = None
    if profiles_namespace_name:
        profiles_namespace = Namespace(name=profiles_namespace_name)
        ns = Namespace(name='test-namespace')

    if ns:
        # Create application profile
        app_profile = None
        if profiles_namespace_name:
            app_profile = KubernetesObjects(namespace=profiles_namespace,object_file=os.path.join(test_framework.get_root_directoty(),"resources/malicious-job-app-profile-namespaced.yaml"))
        else:
            app_profile = KubernetesObjects(namespace=ns,object_file=os.path.join(test_framework.get_root_directoty(),"resources/malicious-job-app-profile.yaml"))

        # Create a workload
        workload = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directoty(),"resources/malicious-job.yaml"))

        # Wait for the workload to be ready
        workload.wait_for_ready(timeout=120)

        # Wait 125 seconds for the alerts to be generated
        print("Waiting 20 seconds for the alerts to be generated")
        time.sleep(20)

        # This application should have signaled all alerts types by now

        # Get all the alert for the namespace
        alerts = test_framework.get_alerts(namespace=ns)

        # Validate that all alerts are signaled
        expected_alerts = [
            "Unexpected process launched",
            "Unexpected file access",
            "Unexpected system call",
            "Unexpected capability used",
            "Unexpected domain request",
            "Unexpected Service Account Token Access",
            "Kubernetes Client Executed",
            "Exec from malicious source",
            "Kernel Module Load",
            "Exec Binary Not In Base Image",
            "Malicious SSH Connection",
            "Exec from mount",
            "Crypto Miner detected"
        ]

        for alert in alerts:
            rule_name = alert['labels']['rule_name']
            if rule_name in expected_alerts:
                expected_alerts.remove(rule_name)

        assert len(expected_alerts) == 0, f"Expected alerts {expected_alerts} were not signaled"







