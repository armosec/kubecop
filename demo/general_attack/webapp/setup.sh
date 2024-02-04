#!/bin/bash

# Kill any existing port forwards
echo "[+] Killing any existing port forwards"
killall kubectl 2>/dev/null

# Apply the YAML file for the web app
echo "[+] Applying YAML file for the web app"
kubectl apply -f demo/general_attack/webapp/ping-app.yaml

# Wait for the web app to be ready
echo "[+] Waiting for the web app to be ready"
kubectl wait --for=condition=ready pod -l app=ping-app

# Port forward from port 80 to port localhost:8080
echo "[+] Port forwarding from port 80 to localhost:8080"
kubectl port-forward pod/ping-app 8080:80 2>&1 >/dev/null &

# Wait for the port forward to be ready
echo "[+] Waiting for the port forward to be ready"
sleep 1
echo "[+] The web app is ready"
