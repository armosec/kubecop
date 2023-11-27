import subprocess
import time

from promtopic import send_promql_query_to_prom


def load_10k_alerts_no_memory_leak(namespace="kubecop-test"):
    print("Running load 10k alerts no memory leak test")

    try:        
        # create the namespace
        subprocess.check_call(["kubectl", "create", "namespace", namespace])
        #  Install nginx profile in kubernetes by applying the nginx profile yaml
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-app-profile.yaml"])
        # Install nginx in kubernetes by applying the nginx deployment yaml with pre-creating profile for the nginx pod
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])
        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])
        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")
        time_start = time.time()
        # Exec into the nginx pod 10k times        
        for i in range(10):
            subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "touch", "/tmp/nginx-test"])
            if i%1000 == 0:
                print("Executed %s times"%i)

             
        # wait for 60 seconds so the memory leak can be detected
        # time.sleep(60)

        # Get kubecop pod name
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True)
        # Build query to get memory usage
        query = 'sum(node_namespace_pod_container:container_memory_usage_bytes:sum{namespace="kubescape", pod=%s,cluster=""}) by (container)'%kc_pod_name        
        
        values = []
        while len(values) == 0:
            time.sleep(1)
            _, values = send_promql_query_to_prom("load_10k_alerts_no_memory_leak", query, time_start,time_end=time.time())
        # _, values = send_promql_query_to_prom(query, time_start,time_end=time.time())
        # validate that there is no memory leak
        assert values[-1] <= values[0], "Memory leak detected"
    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1
    
    # Delete the namespace
    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    return 0
        
        


    