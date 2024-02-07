import subprocess
import time
import os

from promtopic import save_plot_png, send_promql_query_to_prom
from pprof import pprof_recorder
from kubernetes_wrappers import Namespace

def load_10k_alerts_no_memory_leak(test_framework):
    print("Running load 10k alerts no memory leak test")

    # Create a namespace
    ns = Namespace(name=None)

    namespace = ns.name()
    
    profiles_namespace_name = os.environ.get("STORE_NAMESPACE")
    profiles_namespace = None
    if profiles_namespace_name:
        profiles_namespace = Namespace(name=profiles_namespace_name)
        ns = Namespace(name='test-namespace')
        namespace = ns.name()

    try:
        #  Install nginx profile in kubernetes by applying the nginx profile yaml
        if profiles_namespace_name:
            subprocess.check_call(["kubectl", "-n", profiles_namespace_name , "apply", "-f", os.path.join(test_framework.get_root_directoty(),"resources/nginx-app-profile-namespaced.yaml")])
        else:
            subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-app-profile.yaml"])
        # Install nginx in kubernetes by applying the nginx deployment yaml with pre-creating profile for the nginx pod
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])
        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])
        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        # Do an inital load on the nginx pod
        print("Starting first load on nginx pod")
        for i in range(10):
            subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "bash", "-c",
                                   "for i in {1..100}; do touch /tmp/nginx-test-$i; done"])
            if i % 5 == 0:
                print(f"Created file {(i+1)*100} times")

        # wait for 300 seconds for the GC to run, so the memory leak can be detected
        print("Waiting 300 seconds to have a baseline memory usage")
        time.sleep(300)

        # Start to record memory usage
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        pprof_recorder_obj = pprof_recorder('kubescape', kc_pod_name, 6060)
        pprof_recorder_obj.record_detached(duration=600, type="mem", filename="load_10k_alerts_no_memory_leak_mem.pprof")

        time_start = time.time()
        # Exec into the nginx pod and create a file in the /tmp directory in a loop
        for i in range(100):
            subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "bash", "-c",
                                   "for i in {1..100}; do touch /tmp/nginx-test-$i; done"])
            if i % 5 == 0:
                print(f"Created file {(i+1)*100} times")

        # wait for 300 seconds for the GC to run, so the memory leak can be detected
        print("Waiting 300 seconds to GC to run")
        time.sleep(300)

        # Get kubecop pod name
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query to get memory usage
        query = 'sum(container_memory_working_set_bytes{pod="%s"}) by (container)'%kc_pod_name
        timestamps, values = send_promql_query_to_prom("load_10k_alerts_no_memory_leak_mem", query, time_start,time_end=time.time())
        save_plot_png("load_10k_alerts_no_memory_leak_mem", values=values,timestamps=timestamps, metric_name='Memory Usage (bytes)')

        # validate that there is no memory leak, but tolerate 6mb memory leak
        assert int(values[-1]) <= int(values[0]) + 6000000, f"Memory leak detected in kubecop pod. Memory usage at the end of the test is {values[-1]} and at the beginning of the test is {values[0]}"


    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        # Delete the profiles if they were created
        if profiles_namespace:
            subprocess.run(["kubectl", "delete", "applicationprofile", f"pod-{nginx_pod_name}-test-namespace", "-n", profiles_namespace_name])
            subprocess.run(["kubectl", "delete", "applicationprofile", f"deployment-nginx-deployment-test-namespace", "-n", profiles_namespace_name])
        return 1

    # Delete the namespace
    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    if profiles_namespace:
        subprocess.run(["kubectl", "delete", "applicationprofile", f"pod-{nginx_pod_name}-test-namespace", "-n", profiles_namespace_name])
        subprocess.run(["kubectl", "delete", "applicationprofile", f"deployment-nginx-deployment-test-namespace", "-n", profiles_namespace_name])
    return 0




