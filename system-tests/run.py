# General imports
import sys
import os
import requests
import subprocess
import time
from promtopic import plotprom_cpu_usage, plotprom_mem, get_average_cpu_usage

# Test cases imports
import kill_in_the_middle
import load_10k_alerts_no_memory
import creation_app_profile_memory_leak
from basic_alert_tests import basic_alert_test
from rule_binding_apply_test import rule_binding_apply_test
from all_alerts_from_malicious_app import all_alerts_from_malicious_app
from basic_load_activities import basic_load_activities
from finalization_alert_test import finalization_alert_test


alert_manager_url = "http://localhost:9093/"
prometheus_url = "http://localhost:9090/"

def filter_alerts_by_label(alerts, label_key, label_value):
    filtered_alerts = [alert for alert in alerts if label_key in alert['labels'] and alert['labels'][label_key] == label_value]
    return filtered_alerts

def get_active_alerts(alertmanager_url):
    endpoint = f"{alertmanager_url}/api/v2/alerts?active=true"
    try:
        response = requests.get(endpoint)
        response.raise_for_status()
        alerts = response.json()
        return alerts
    except requests.exceptions.HTTPError as errh:
        print(f"Http Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"OOps: Something Else: {err}")

    return None

TEST_CONFIG_STOP_ALL_ON_FAILURE = 'stop_all_on_failure'

test_cases = [
    (basic_alert_test, "Basic alert test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: True}),
    (rule_binding_apply_test, "Rule binding apply test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: True}),
    (finalization_alert_test, "Finalization alert test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: True}),
    (all_alerts_from_malicious_app, "All alerts from malicious app test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: True}),
    (basic_load_activities, "Basic load activities test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: False}),
    (load_10k_alerts_no_memory.load_10k_alerts_no_memory_leak, "Load 10k alerts no memory leak test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: False}),
    (creation_app_profile_memory_leak.install_app_no_application_profile_no_leak, "Install app no application profile no leak test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: False}),
    # (kill_in_the_middle.kill_process_in_the_middle, "Kill process in the middle test", {TEST_CONFIG_STOP_ALL_ON_FAILURE: False}),
]

class TestFramework:
    def __init__(self):
        toplevel = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], universal_newlines=True).strip()
        self.root_directory = os.path.join(toplevel, "system-tests")
        print("Root directory: %s" % self.root_directory)

    def get_root_directoty(self):
        return self.root_directory

    def get_alerts(self, namespace):
        # Get the active alerts
        alerts = get_active_alerts(alert_manager_url)
        if not alerts:
            print("Could not get alerts")
            return 1

        alerts = filter_alerts_by_label(alerts, "alertname", "KubeCopRuleViolated")
        alerts = filter_alerts_by_label(alerts, "namespace", namespace.name())

        return alerts

    def get_average_cpu_usage(self, namespace, workload, time_start, time_end):
        # Get kubecop pod name
        pod_name = subprocess.check_output(["kubectl", "-n", namespace, "get", "pods", "-l", "app.kubernetes.io/name=%s"%workload, "-o", "jsonpath='{.items[0].metadata.name}'"], universal_newlines=True).strip("'")
        return get_average_cpu_usage(pod_name, time_start, time_end)

def main():
    global alert_manager_url
    global prometheus_url
    if len(sys.argv) > 1:
        alert_manager_url = sys.argv[1]
    if len(sys.argv) > 2:
        prometheus_url = sys.argv[2]

    # Create a test framework object
    test_framework = TestFramework()

    print("Running tests")
    glob_result = 0
    result_summary = {}
    for test_case, test_case_name, test_config in test_cases:
        print("Running test %s" % test_case_name)
        # Save start time in epoch
        time_start = time.time()
        test_error_string = ''
        try:
            test_result = test_case(test_framework)
        except Exception as e:
            print("Exception: ", e)
            # Print the exception stack trace
            #import traceback
            #traceback.print_exc()
            test_error_string = str(e)
            test_result = 1
        # Save end time in epoch
        time_end = time.time()
        # Give two minutes for prometheus to scrape the data
        print("Waiting 60 seconds for prometheus to scrape the data")
        time.sleep(60)
        result = plotprom_cpu_usage(test_case_name, time_start, time_end)
        if result == 0:
            print("Ploting succeeded")
        else:
            print("Ploting failed")
        # plot memory usage
        result = plotprom_mem(test_case_name, time_start, time_end)
        if result == 0:
            print("Ploting memory usage succeeded")
        else:
            print("Ploting memory usage failed")

        if test_result == 0 or test_result == None:
            print("Test passed")
            result_summary[test_case_name] = 'Passed'
        else:
            print("Test failed")
            result_summary[test_case_name] = 'Failed (%s)' % test_error_string
            glob_result = 1
            if test_config.get(TEST_CONFIG_STOP_ALL_ON_FAILURE, False):
                print("Stopping tests due to failure in one of the required tests")
                break

    print("Test summary:")
    for test_case_name, test_case_result in result_summary.items():
        print(f"{test_case_name}: {test_case_result}")

    sys.exit(glob_result)


if __name__ == "__main__":
    exit(main())