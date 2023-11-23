import requests
import matplotlib.pyplot as plt
import sys
import os
import subprocess
from datetime import datetime


# Function to execute PromQL query
def execute_promql_query(prometheus_url, query, time_start, time_end, steps):
    #print("Query: %s" % query)
    #print("Start: %s" % time_start)
    #print("End: %s" % time_end)
    #print("Steps: %s" % steps)
    #print("Prometheus URL: %s" % prometheus_url)
    response = requests.get(f'{prometheus_url}/api/v1/query_range', params={'query': query,'start':time_start,'end':time_end,'step':steps})
    results = response.json()
    #print("Results: %s" % results)
    if results['status'] != 'success':
        print(results)
        raise Exception("Query failed")
    return results['data']['result']

def plotprom(test_case_name,time_start, time_end, steps = '1s'):
    print("Ploting test %s from %s to %s" % (test_case_name, time_start, time_end))
    # Replace with your Prometheus URL and Query
    prometheus_url = 'http://localhost:9090'
    if 'PROMETHEUS_URL' in os.environ:
        prometheus_url = os.environ['PROMETHEUS_URL']

    # Get kubecop pod name
    pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True)
    query = 'sum(node_namespace_pod_container:container_cpu_usage_seconds_total:sum_irate{namespace="kubescape", pod=%s,cluster=""}) by (container)'%pod_name

    # Execute the query
    data = execute_promql_query(prometheus_url, query, time_start, time_end, steps)

    # Example of processing and plotting
    # This will vary greatly depending on the shape of your data
    if len(data) == 0:
        print("No data found in prometheus when looking for %s" % test_case_name)
        return 1
    timestamps = [datetime.fromtimestamp(item[0]).strftime("%M:%S") for item in data[1]['values']]  # Assuming the first result and it's a time series
    values = [float(item[1]) for item in data[1]['values']]

    # Plotting
    plt.plot(timestamps, values)
    plt.title('KubeCop CPU Usage - %s'%test_case_name)
    plt.xlabel('Time (epoch)')
    plt.ylabel('CPU Usage (ms)')

    # Convert test case name to file name
    filename = test_case_name.replace(' ', '_').lower()

    # Save plot to an image file
    plt.savefig('%s.png'%filename)

    return 0

if __name__ == "__main__":
    test_case_name = sys.argv[1]
    time_start = float(sys.argv[2])
    time_end = float(sys.argv[3])
    plotprom(test_case_name=test_case_name, time_start=time_start, time_end=time_end)