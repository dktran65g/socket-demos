# ArgoCD Cheat Sheet

## Minikube Setup

```bash
# Start minikube cluster
minikube start

# Open Kubernetes UI dashboard
minikube dashboard
```

## ArgoCD Installation

```bash
# Create argocd namespace
kubectl create namespace argocd

# Install ArgoCD from official manifest
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Verify installation
kubectl get all -n argocd
```

## Access ArgoCD UI

```bash
# Port forward to access ArgoCD web GUI
kubectl port-forward service/argocd-server -n argocd 8080:443

# Get admin password from secret
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Default credentials
# Username: admin
# Password: (output from above command)
```

## Verify Application Deployment

```bash
# Check deployed resources in dev namespace
kubectl get all -n dev

# Port forward to access the application
kubectl port-forward service/myhelmapp 8888:80 -n dev
```

## Extension Guard Demo

```bash
# 1. Start minikube
minikube start

# 2. Point Docker to minikube
eval $(minikube docker-env)

# 3. Build the Docker image (from socket-demos directory)
docker build -t extension-guard:latest ./extension-guard

# 4. Create namespace and deploy
kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install extension-guard ./extension-guard -n demo

# 5. Verify deployment
kubectl get all -n demo

# 6. Port forward to access
kubectl port-forward service/extension-guard 8081:81 -n demo

# 7. Open in browser
open http://localhost:8081
```
