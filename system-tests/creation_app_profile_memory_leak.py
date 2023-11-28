import subprocess
import time

from promtopic import save_plot_png, send_promql_query_to_prom


def install_app_no_application_profile_no_leak(namespace="kubecop-test"):
    print("Running install app no application profile test")

    try:
        time_start = time.time()
        # Create the namespace
        subprocess.check_call(["kubectl", "create", "namespace", namespace])

        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])

        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])

        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        print("Waiting 130 seconds for the final application profile to be created")
        time.sleep(130)

        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles", f"pod-{nginx_pod_name}", "-oyaml"], capture_output=True)
        assert get_proc.returncode == 0 and 'kapprofiler.kubescape.io/final: "true"' in get_proc.stdout.decode("utf-8"), f"final applicationprofile ({get_proc.returncode}) did not got created {get_proc.stdout.decode('utf-8')}"        

        # wait for 60 seconds for the GC to run, so the memory leak can be detected
        time.sleep(60)

        # Get kubecop pod name
        kc_pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query to get memory usage
        query = 'sum(container_memory_working_set_bytes{pod="%s", container="kubecop"}) by (container)'%kc_pod_name                
        timestamps, values = send_promql_query_to_prom("install_app_no_application_profile_no_leak_mem", query, time_start,time_end=time.time())
        save_plot_png("install_app_no_application_profile_no_leak_mem", values=values,timestamps=timestamps, metric_name='Memory Usage (bytes)')
        
        # validate that there is no memory leak, but tolerate 20mb memory leak
        assert values[-1] <= values[0] + 20000000, f"Memory leak detected in kubecop pod. Memory usage at the end of the test is {values[-1]} and at the beginning of the test is {values[0]}"        
        
        
    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1
    
    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    return 0

