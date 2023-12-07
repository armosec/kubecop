# runtime rule  alert binding 
In order to determine which rules should be applied to which workloads, we need to bind the rules to the workloads. This is done by creating a `RuntimeRuleAlertBinding` object that binds a `Rule` to certain pods.
This is a CRD needed to be created by the user. The `RuntimeRuleAlertBinding` object is inspired by K8s native policies and bindings, such as [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/#networkpolicy-resource) and [ValidatingAdmissionPolicyBinding](https://www.armosec.io/glossary/kubernetes-validation-admission-policies/) objects and so it contains the following fields:
- `namespaceSelector` - a [selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#resources-that-support-set-based-requirements) that selects the namespaces that the rule should be applied to. If not specified, the rule will be applied to all namespaces.
- `podSelector` - a [selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#resources-that-support-set-based-requirements) that selects the pods that the rule should be applied to. If not specified, the rule will be applied to all pods.
- `rules` - a list of rules that should be applied to the selected pods.

Each `rule` in the list contains the following fields:
- `ruleName` (mandatory) - the name of the rule to be applied.
- `severity` -(optional) the severity of the alert that will be generated if the rule is violated. Each rule has a default severity, but it can be overridden by the user.
- `parameters` - (optional) a list of parameters that can be passed to the rule. Each rule has a default set of parameters, but it can be overridden by the user.

## Example
The first step is to apply the `RuntimeRuleAlertBinding` CRD to the cluster:
```bash
kubectl apply -f chart/kubecop/crds/runtime-rule-binding.crd.yaml
```
The second step is to create the `RuntimeRuleAlertBinding` object:
```yaml
apiVersion: kubescape.io/v1
kind: RuntimeRuleAlertBinding
metadata:
  name: single-rule-for-app-nginx-default-ns
spec:
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: default
  podSelector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - nginx
  rules:
    - ruleName: "Unexpected process launched"

```

In the above example, we bind the rule `Unexpected process launched` to the pods in the namespace `default`. The rule will be applied to all the pods that are labeled with `app: nginx` in the namespace `default`.

## how does it work?
Once the user applies a change to a `RuntimeRuleAlertBinding` object or any container in the cluster is created/updated/deleted, the KubeCop will be notified and will update the rules that are applied to each pod. The KubeCop will then apply the rules to the pods and will generate alerts if needed.

So there are 2 flows that can trigger the KubeCop to apply the rules to the pods:
1. The user applies a change to a `RuntimeRuleAlertBinding` object. Those changes are handled by the [RuleBindingK8sStore](store.go#L195).
2. A container in the cluster is created/updated/deleted. Those changes usually handled by the [Engine](../engine/engine.go#L20).

In the 1st flow, the `RuleBindingK8sStore` will notify the subscribers (callback functions) about the change.
Then the subsciber will get list of pods it needs to apply the rules to.
For each pod, the subscriber will call `GetRulesForPod` to ask the `RuleBindingK8sStore` for the rules that should be applied to the pod.

In the 2nd flow, the watcher of the container, usually the [Engine](../engine/engine.go#L20), will call `GetRulesForPod` to ask the `RuleBindingK8sStore` for the rules that should be applied to the pod.

Then the caller of the `GetRulesForPod` will handle the rules for the pod.

If more than one `RuntimeRuleAlertBinding` object is applied to the pod, the rules will be aggregated together.