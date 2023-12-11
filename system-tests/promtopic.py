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

def plotprom_cpu_usage(test_case_name,time_start, time_end, steps = '1s'):
    print("Ploting test %s from %s to %s" % (test_case_name, time_start, time_end))

    try:
        # Get kubecop pod name
        pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query
        query = 'sum(node_namespace_pod_container:container_cpu_usage_seconds_total:sum_irate{namespace="kubescape", pod="%s",container="kubecop"}) by (container)'%pod_name

        timestamps, values = send_promql_query_to_prom(test_case_name, query, time_start, time_end, steps)
        values = [float(item) for item in values]
        return save_plot_png(test_case_name+"_cpu", timestamps, values, metric_name='CPU Usage (ms)')
    except Exception as e:
        print("Exception: ", e)
        return 1

def get_average_cpu_usage(pod_name, time_start, time_end):
    # Build query
    query ='avg by(cpu, instance) (irate(container_cpu_usage_seconds_total{pod="%s"}[5m]))' % pod_name
    timestamps, values = send_promql_query_to_prom("get_average_cpu_usage", query, time_start, time_end)
    # Calculate average
    values = [float(item) for item in values]
    return sum(values)/len(values)

def plotprom_mem(test_case_name,time_start, time_end, steps = '1s'):
    print("Ploting test %s from %s to %s" % (test_case_name, time_start, time_end))

    try:
        # Get kubecop pod name
        pod_name = subprocess.check_output(["kubectl", "-n", "kubescape", "get", "pods", "-l", "app.kubernetes.io/name=kubecop", "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        # Build query
        query = 'sum(container_memory_working_set_bytes{pod="%s", container="kubecop"}) by (container)'%pod_name
        timestamps, values = send_promql_query_to_prom(test_case_name, query, time_start, time_end, steps)
        # values = [int(item) for item in values]
        return save_plot_png(test_case_name+"_mem", timestamps, values, metric_name='Memory Usage (bytes)')
    except Exception as e:
        print("Exception: ", e)
        return 1

def save_plot_png(test_case_name, timestamps, values, metric_name):
    plt.plot(timestamps, values)
    plt.title(f'KubeCop {metric_name} - {test_case_name}')
    plt.xlabel('Time (epoch)')
    plt.ylabel(metric_name)

    # Convert test case name to file name
    filename = test_case_name.replace(' ', '_').lower()

    # Save plot to an image file
    plt.savefig('%s.png'%filename)
    plt.clf()

    return 0

def send_promql_query_to_prom(test_case_name, query, time_start, time_end, steps = '1s'):
    # Get prometheus url
    prometheus_url = 'http://localhost:9090'
    if 'PROMETHEUS_URL' in os.environ:
        prometheus_url = os.environ['PROMETHEUS_URL']

    # Execute the query
    data = execute_promql_query(prometheus_url, query, time_start, time_end, steps)

    # Example of processing and plotting
    # This will vary greatly depending on the shape of your data
    assert len(data) > 0, "No data found in prometheus when looking for %s" % test_case_name
    timestamps = [datetime.fromtimestamp(item[0]).strftime("%M:%S") for item in data[0]['values']]  # Assuming the first result and it's a time series
    values = [item[1] for item in data[0]['values']]
    return timestamps, values


if __name__ == "__main__":
    test_case_name = sys.argv[1]
    time_start = float(sys.argv[2])
    time_end = float(sys.argv[3])
    plotprom_cpu_usage(test_case_name=test_case_name, time_start=time_start, time_end=time_end)