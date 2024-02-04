import subprocess
import time
from kubernetes_wrappers import Namespace, Workload, KubernetesObjects

def kill_process_in_the_middle(test_framework):
    print("Running kill process in the middle test")

    # Create a namespace
    ns = Namespace(name=None)
    namespace = ns.name()


    # we want to kill the application before the kaprofile creation is complete
    # exec into the pod and kill the process
    try:
        subprocess.check_call(["kubectl", "create", "namespace", namespace])
        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])

        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])

        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        print("Waiting 80 seconds to see we are still not final") # 120 seconds is the time it takes for the profile to be marked as "final"
        time.sleep(80)
        # Exec into the nginx pod and kill the process
        subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "bash", "-c", "kill -9 1"])

        # check that the final app profile did not get created
        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles", f"pod-{nginx_pod_name}", "-oyaml"], capture_output=True)
        assert get_proc.returncode == 0 and 'kapprofiler.kubescape.io/final: "true"' not in get_proc.stdout.decode("utf-8"), f"applicationprofile ({get_proc.returncode}) did got created {get_proc.stdout.decode('utf-8')}"

        # check that the app profile did get created after 30 seconds
        print("Waiting 40 seconds to see we are final")
        time.sleep(40)
        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles", f"pod-{nginx_pod_name}", "-oyaml"], capture_output=True)
        assert get_proc.returncode == 0 and 'kapprofiler.kubescape.io/final: "true"' in get_proc.stdout.decode("utf-8"), f"final applicationprofile ({get_proc.returncode}) did not got created {get_proc.stdout.decode('utf-8')}"

        subprocess.check_call(["kubectl", "delete", "namespace", namespace])

    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1

    return 0


def kill_pod_in_the_middle(namespace="kubecop-test"):
    print("Running kill pod in the middle test")
    # we want to kill the application before the kaprofile creation is complete
    # we expect to get no applicationprofile created after any period of time

    try:
        # create the namespace
        subprocess.check_call(["kubectl", "create", "namespace", namespace])
        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])

        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])

        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        print("Waiting 80 seconds so we have no final profile")
        time.sleep(80)
        print(f"Deleting the pod {nginx_pod_name}")
        subprocess.check_call(["kubectl", "-n", namespace , "delete", "pod", nginx_pod_name])
        print("Watiting for the pod to be deleted")
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=delete", "pod", nginx_pod_name, "--timeout=120s"])

        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles", f"pod-{nginx_pod_name}", "-oyaml"], capture_output=True)
        assert get_proc.returncode == 1, f"applicationprofile ({get_proc.returncode})  still exists: {get_proc.stdout.decode('utf-8')}"
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])

    except Exception as e:
        print("Exception: ", e)
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1

    subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    return 0