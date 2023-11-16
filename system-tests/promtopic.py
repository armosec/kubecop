import requests
import matplotlib.pyplot as plt
import sys
import os

# Function to execute PromQL query
def execute_promql_query(prometheus_url, query, time_start, time_end, steps):
    response = requests.get(f'{prometheus_url}/api/v1/query_range', params={'query': query,'start':time_start,'end':time_end,'step':steps})
    results = response.json()
    if results['status'] != 'success':
        raise Exception("Query failed")
    return results['data']['result']

def plotprom(test_case_name,time_start, time_end, steps):
    print("Ploting test %s from %s to %s" % (test_case_name, time_start, time_end))
    # Replace with your Prometheus URL and Query
    prometheus_url = 'http://localhost:9090'
    if 'PROMETHEUS_URL' in os.environ:
        prometheus_url = os.environ['PROMETHEUS_URL']

    query = '''sum(
        node_namespace_pod_container:container_cpu_usage_seconds_total:sum_irate{cluster="", namespace="kubescape"}
    * on(namespace,pod)
        group_left(workload, workload_type) namespace_workload_pod:kube_pod_owner:relabel{cluster="", namespace="kubescape", workload="kubecop", workload_type=~"daemonset"}
    ) by (pod)
    '''
    # Execute the query
    data = execute_promql_query(prometheus_url, query, time_start, time_end, steps)

    # Example of processing and plotting
    # This will vary greatly depending on the shape of your data
    timestamps = [item[0] for item in data[0]['values']]  # Assuming the first result and it's a time series
    values = [float(item[1]) for item in data[0]['values']]

    # Plotting
    plt.plot(timestamps, values)
    plt.title('KubeCop CPU Usage - %s'%test_case_name)
    plt.xlabel('Time (epoch)')
    plt.ylabel('CPU Usage (ms)')

    # Convert test case name to file name
    filename = test_case_name.replace(' ', '_').lower()

    # Save plot to an image file
    plt.savefig('%s.png'%filename)

if __name__ == "__main__":
    test_case_name = sys.argv[1]
    time_start = float(sys.argv[2])
    time_end = float(sys.argv[3])
    steps = int(time_end - time_start) - 1
    plotprom(time_start, time_end, steps)