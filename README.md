[![Version](https://img.shields.io/github/v/release/armosec/kubecop)](https://github.com/armosec/kubecop/releases)
[![build](https://github.com/armosec/kubecop/actions/workflows/release.yaml/badge.svg)](https://github.com/armosec/kubecop/actions/workflows/release.yaml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/armosec/kubecop)](https://goreportcard.com/report/github.com/armosec/kubecop)
[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/armosec/kubecop)
[![Twitter Follow](https://img.shields.io/twitter/follow/kubescape?style=social)](https://twitter.com/kubescape)

# KubeCop 🚨🚔🚢☸️🚨

KubeCop is a KDR - Kubernetes Detection and Response tool. It is designed to be a simple, low-footprint, easy-to-use, and effective tool for detecting and responding to threats in your Kubernetes cluster at runtime.

It is based on eBPF-based event monitoring on Kubernetes nodes and an advanced rule engine that allows you to write rules that can detect and respond to threats in your cluster and more specifically in your workload itself🛡️.

KubeCop supports two kinds of malicious behavior detections:
* Signature-based - detecting application behavior that resembles attack techniques
* Anomaly-based - identifying events that are not aligned with the baseline behavior of applications

KubeCop is capable of building an application baseline by itself and enforcing behavior. Application monitoring is based on the [Kapprofiler](https://github.com/kubescape/kapprofiler/) project

What do you get when you install KubeCop?

Hopefully nothing 😉

If you connect it to your AlertManager endpoint, you will be able to monitor your Kubernetes cluster for malicious events and get alerted if something happens!


![Design](/docs/images/kubecop-software-design.png)


## Detection capabilities

KubeCop leverages advanced eBPF (extended Berkeley Packet Filter) technology for comprehensive runtime security detection in Kubernetes environments. Its detection capabilities encompass a wide array of events including new process initiations, file activities, network operations, system call activities, and usage of Linux capabilities.

### Anomaly-based detection

A standout feature of KubeCop is its anomaly detection mechanism, which is grounded in application profiling. During a default learning period of 15 minutes (customizable by users, for production environments suggested to use at least 12 hours), KubeCop monitors applications for the aforementioned activities, subsequently building a detailed application profile. This profile, stored as a Kubernetes Custom Resource (CR), serves as a benchmark for normal behavior. Once the learning phase concludes and the profile is established, KubeCop validates application events coming from eBPF for deviations from this norm, triggering alerts upon detecting anomalies.

### Signature-based detection

Additionally, KubeCop is equipped with rules designed to identify well-known attack signatures. These rules are adept at uncovering various threats, such as unauthorized software executions that deviate from the original container image, detection of unpackers in memory, reverse shell activities, and more. Users have the flexibility to create 'Rule Bindings'—specific instructions that direct KubeCop on which rules should be applied to which Pods. This level of customization ensures that security measures are tailored to the unique needs of each Kubernetes deployment, enhancing the overall security posture and responsiveness of the system.

### Rules

See [here](/pkg/engine/rule/README.md) more about our rules

### Rule bindings

To learn more about binding rules to workloads, see [RuntimeRuleAlertBinding](pkg/rulebindingstore/README.md).

## Getting started

KubeCop deployment is installed and managed using Helm.

### Installation


#### Basic installation

To install KubeCop on your Kubernetes cluster, do the following steps:

```bash
git clone https://github.com/armosec/kubecop.git && cd kubecop
# Assuming AlertManager is running in service  "alertmanager-operated" in namespace "monitoring"
helm install kubecop chart/kubecop -n kubescape --create-namespace
```

You should be getting alerts after the learning period ends. Try `kubectl exec` on one of the Pods after the learning period!

#### Advanced parameter configurations

##### Finalization

The parameter `kubecop.recording.finalizationDuration` controls the learning period of the baseline behavior of workloads. The default setting is 15 minutes, but this is not a good value for production environments only for testing. For production environments we suggest at least 12 hour learning period (sometimes even 24 hours to cover daily recurring tasks) and set this to `12h`

##### Exporters

Exporters are the mechanisms in the system to send alerts to external endpoints from KubeCop engine.

They can be enabled with Helm (Stdout is on by default)

Currently supported:
* Alert manager
    * Enable: `kubecop.alertmanager.enabled`
    * Endpoint: `kubecop.alertmanager.endpoint` (example `localhost:9093`)
* Syslog (RFC 5424)
    * Enable: `kubecop.syslog.enabled`
    * Endpoint: `kubecop.syslog.endpoint` (example `localhost:514`)
    * Protocol: `kubecop.syslog.protocol` (example `udp`)
* Stdout (printing alerts to log)
* CSV (writing alerts to CSV file)
    * Enable: `kubecop.csv.enabled`
    * Path: `kubecop.csv.path` (example `/tmp/alerts.csv`)


Read more about them [here](/pkg/exporters/README.md)

#### Metrics export

KubeCop can export internal metrics to Prometheus. Internal metrics include:

* Number of alerts sent
* Number of events processed (exec, open, etc.)
* Number of application profile changes

These metrics can be useful to understand the load on the system how it behaves.

You can enable the exported with `kubecop.prometheusExporter.enabled=true`.

#### Bindings

KubeCop applies alert rules on Kubernetes workloads based on rule-binding configuration.

Rule-binding are simple objects (CRDs) very similar to existing Kubernetes binding objects like `RoleBinding` or `AdmissionPolicyBinding`. They have two major parts:
* Matching (to which object the rules are applied to)
* Rule list (what rules to apply to these objects)

The default Helm installation comes with a basic rule-binding object called `all-rules-all-pods` which effectively applies all the existing rules to all Pods except `kube-system` namespace and KubeCop itself.

The bindings should be adjusted according to the alert settings fitting the deployments.

### Requirements

KubeCop supports Linux nodes only (since it is eBPF based), it also requires `CAP_SYS_ADMIN` capability (but not `privilged:true`).
