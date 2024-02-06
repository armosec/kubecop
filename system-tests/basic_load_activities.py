from kubernetes_wrappers import Namespace, Workload, KubernetesObjects
import os
import time

def basic_load_activities(test_framework):
    print("Running basic load activities test")

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
            app_profile = KubernetesObjects(namespace=profiles_namespace,object_file=os.path.join(test_framework.get_root_directoty(),"resources/nginx-app-profile-namespaced.yaml"))
        else:
            app_profile = KubernetesObjects(namespace=ns,object_file=os.path.join(test_framework.get_root_directoty(),"resources/nginx-app-profile.yaml"))

        # Create a workload
        nginx = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directoty(),"resources/nginx-deployment.yaml"))

        # Wait for the workload to be ready
        nginx.wait_for_ready(timeout=120)

        # Create loader
        loader = Workload(namespace=ns,workload_file=os.path.join(test_framework.get_root_directoty(),"resources/locust-deployment.yaml"))

        # Wait for the workload to be ready
        loader.wait_for_ready(timeout=120)

        time_start = time.time()

        # Create a load of 5 minutes
        time.sleep(300)

        time_end= time.time()

        # Get the average CPU usage of KubeCop
        cpu_usage = test_framework.get_average_cpu_usage(namespace='kubescape', workload="kubecop", time_start=time_start, time_end=time_end)

        assert cpu_usage < 0.1, f"CPU usage of KubeCop is too high. CPU usage is {cpu_usage}"
