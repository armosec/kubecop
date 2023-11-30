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

A standout feature of KubeCop is its anomaly detection mechanism, which is grounded in application profiling. During a default learning period of 15 minutes (customizable by users), KubeCop monitors applications for the aforementioned activities, subsequently building a detailed application profile. This profile, stored as a Kubernetes Custom Resource (CR), serves as a benchmark for normal behavior. Once the learning phase concludes and the profile is established, KubeCop validates application events coming from eBPF for deviations from this norm, triggering alerts upon detecting anomalies.

### Signature-based detection

Additionally, KubeCop is equipped with rules designed to identify well-known attack signatures. These rules are adept at uncovering various threats, such as unauthorized software executions that deviate from the original container image, detection of unpackers in memory, reverse shell activities, and more. Users have the flexibility to create 'Rule Bindings'—specific instructions that direct KubeCop on which rules should be applied to which Pods. This level of customization ensures that security measures are tailored to the unique needs of each Kubernetes deployment, enhancing the overall security posture and responsiveness of the system.

### Rules

See [here](/pkg/engine/rule/README.md) more about our rules

### Rule bindings

To learn more about binding rules to workloads, see [RuntimeRuleAlertBinding](pkg/rulebindingstore/README.md).

## Getting started

KubeCop deployment is installed and managed using Helm.

### Installation

To install KubeCop on your Kubernetes cluster, do the following steps:

```bash
git clone https://github.com/armosec/kubecop.git && cd kubecop
# Assuming AlertManager is running in service  "alertmanager-operated" in namespace "monitoring"
helm install kubecop chart/kubecop -n kubescape --create-namespace --set kubecop.alertmanager.enabled=true --set kubecop.alertmanager.endpoint="alertmanager-operated.monitoring.svc.cluster.local:9093"
```

You can change the "learning period" using the `kubecop.recording.finalizationDuration` Helm parameters (example values are "30s", "5m" or "1h").

You should be getting alerts after the learning period ends. Try `kubectl exec` on one of the Pods after the learning period!



### Requirements

KubeCop supports Linux nodes only (since it is eBPF based), it also requires `CAP_SYS_ADMIN` capability (but not `privilged:true`).

## Development setup
> **Note:** make sure to configure the [exportes](pkg/exporters/README.md) before running the KubeCop.

Clone this repository then do the following:
```bash
make deploy-dev-pod # Deploying dev pod on your cluster
make install        # Build and deploy the binaries (installing them in the dev Pod)
make open-shell     # Open a shell on the development Pods
```

To test it, in a different shell install the application profile for Nginx and deploy Nginx
```bash
kubectl apply -f dev/nginx/nginx-app-profile.yaml -f dev/nginx/nginx-deployment.yaml
```

and now open a shell on the Nginx Pod which will trigger un-whitelisted alert in the KubeCop
```bash
kubectl exec -it $(kubectl get pods -l app=nginx -o=jsonpath='{.items[0].metadata.name}') -- sh
```

you should get this on the KubeCop console:
```
&{nginx ad5d83bb20617b086ec8ec384ac76976d2ac4aa39d8380f2ae3b0080d205edc5 nginx-deployment-cbdccf466-jhvb7 default 1699770928201031673 0} - Alert exec call "/bin/sh" is not whitelisted by application profile```

## Tear down
```bash
make close-shell    # Close the shell on the development Pods
```

## Getting pprof samples from KubeCop

Run KubeCop with `_PPROF_SERVER=enable` (env variable)

Then pull the sample file and see results with these commands:
```bash
curl http://<KubeCopIP>:6060/debug/pprof/profile?seconds=120 -o pprof.pd.gz
go tool pprof -http=:8082 pprof.pd.gz
```

