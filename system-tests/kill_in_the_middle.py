import subprocess
import time


def kill_process_in_the_middle(namespace="kubecop-test"):
    print("Running kill process in the middle test")
    # we want to kill the application before the kaprofile creation is complete    
    # exec into the pod and kill the process
    try:
        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])

        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])

        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        print("Waiting 100 seconds to create load") # 120 seconds is the time it takes for the profile to be created
        time.sleep(100)
        # Exec into the nginx pod and kill the process
        subprocess.check_call(["kubectl", "-n", namespace , "exec", nginx_pod_name, "--", "kill", "-9", "1"])

        # check that the app profile did not get created
        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles"])
        assert get_proc.returncode == 0 and "nginx" not in get_proc.stdout.decode("utf-8"), "applicationprofile did got created"

        # check that the app profile did get created after 30 seconds
        time.sleep(30)
        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles"])
        assert get_proc.returncode == 0 and "nginx" in get_proc.stdout.decode("utf-8"), "applicationprofile did not got created"        
        
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
    
    except:
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1
    

def kill_pod_in_the_middle(namespace="kubecop-test"):
    print("Running kill pod in the middle test")
    # we want to kill the application before the kaprofile creation is complete    
    # exec into the pod and kill the process
    try:
        # Install nginx in kubernetes by applying the nginx deployment yaml without pre-creating the profile
        subprocess.check_call(["kubectl", "-n", namespace , "apply", "-f", "dev/nginx/nginx-deployment.yaml"])

        # Wait for nginx to be ready
        subprocess.check_call(["kubectl", "-n", namespace , "wait", "--for=condition=ready", "pod", "-l", "app=nginx", "--timeout=120s"])

        # Get the pod name of the nginx pod
        nginx_pod_name = subprocess.check_output(["kubectl", "-n", namespace , "get", "pod", "-l", "app=nginx", "-o", "jsonpath='{.items[0].metadata.name}'"]).decode("utf-8").strip("'")

        print("Waiting 100 seconds to create load") # 120 seconds is the time it takes for the profile to be created
        time.sleep(100)
        # Exec into the nginx pod and kill the process
        subprocess.check_call(["kubectl", "-n", namespace , "delete", "pod", nginx_pod_name])

        # check that the app profile did not get created
        get_proc = subprocess.run(["kubectl", "-n", namespace, "get", "applicationprofiles"])
        assert get_proc.returncode == 0 and "nginx" in get_proc.stdout.decode("utf-8"), "applicationprofile got created"
    
    except:
        # Delete the namespace
        subprocess.check_call(["kubectl", "delete", "namespace", namespace])
        return 1
    
    subprocess.check_call(["kubectl", "delete", "namespace", namespace])