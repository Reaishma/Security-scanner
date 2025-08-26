# Kubernetes Security Policy using Open Policy Agent (OPA)
# Enforces security best practices for Kubernetes resources

package kubernetes.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Default deny - all requests must be explicitly allowed
default allow = false

# Allow requests that pass all security checks
allow if {
    not violation[_]
}

# Security violations collection
violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsRoot == true
    msg := "Container must not run as root user"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := "Container must not run in privileged mode"
}

violation[msg] {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg := "Pod must run as non-root user"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := "Container must have read-only root filesystem"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := "Container must not allow privilege escalation"
}

# Network Policy Requirements
violation[msg] {
    input.kind == "Pod"
    input.metadata.namespace != "kube-system"
    not has_network_policy
    msg := "Pod must be covered by a NetworkPolicy"
}

has_network_policy {
    # This would need to be checked against existing NetworkPolicies
    # For demo purposes, assume pods with specific labels are covered
    input.metadata.labels["network-policy"] == "enabled"
}

# Resource Limits and Requests
violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits.memory
    msg := "Container must specify memory limits"
}

violation[msg] {
    input.kind == "Pod" 
    container := input.spec.containers[_]
    not container.resources.limits.cpu
    msg := "Container must specify CPU limits"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.requests.memory
    msg := "Container must specify memory requests"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.requests.cpu
    msg := "Container must specify CPU requests"
}

# Image Security
violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    endswith(container.image, ":latest")
    msg := "Container must not use 'latest' tag"
}

violation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not startswith(container.image, "registry.company.com/")
    not startswith(container.image, "gcr.io/company-project/")
    msg := "Container must use approved image registry"
}

# Service Account Security
violation[msg] {
    input.kind == "Pod"
    input.spec.automountServiceAccountToken == true
    input.spec.serviceAccountName == "default"
    msg := "Pod must not use default service account with automounted token"
}

# Ingress Security (for Ingress resources)
violation[msg] {
    input.kind == "Ingress"
    not input.spec.tls
    msg := "Ingress must specify TLS configuration"
}

violation[msg] {
    input.kind == "Ingress"
    not input.metadata.annotations["cert-manager.io/cluster-issuer"]
    msg := "Ingress must use cert-manager for TLS certificates"
}

# Service Security
violation[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-cert"]
    msg := "LoadBalancer service must specify SSL certificate"
}

violation[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"
    port := input.spec.ports[_]
    port.nodePort < 30000
    msg := "NodePort must be in the range 30000-32767"
}

# Deployment Security
violation[msg] {
    input.kind == "Deployment"
    input.spec.replicas < 2
    input.metadata.namespace != "kube-system"
    msg := "Deployment must have at least 2 replicas for high availability"
}

violation[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.fsGroup
    msg := "Deployment must specify fsGroup in security context"
}

# ConfigMap and Secret Security
violation[msg] {
    input.kind == "ConfigMap"
    contains(input.data[_], "password")
    msg := "ConfigMap must not contain passwords or secrets"
}

violation[msg] {
    input.kind == "ConfigMap"
    contains(input.data[_], "api_key")
    msg := "ConfigMap must not contain API keys"
}

violation[msg] {
    input.kind == "Secret"
    input.type != "Opaque"
    input.type != "kubernetes.io/tls"
    input.type != "kubernetes.io/service-account-token"
    msg := "Secret must use approved type"
}

# Namespace Security
violation[msg] {
    input.kind == "Namespace"
    not input.metadata.labels["security-policy"]
    msg := "Namespace must have security-policy label"
}

# Required Labels
required_labels := ["app", "version", "environment"]

violation[msg] {
    input.kind in ["Pod", "Deployment", "Service"]
    required_label := required_labels[_]
    not input.metadata.labels[required_label]
    msg := sprintf("Resource must have required label: %s", [required_label])
}

# Environment-specific policies
violation[msg] {
    input.kind == "Pod"
    input.metadata.labels.environment == "production"
    container := input.spec.containers[_]
    not container.livenessProbe
    msg := "Production pods must have liveness probe"
}

violation[msg] {
    input.kind == "Pod"
    input.metadata.labels.environment == "production"
    container := input.spec.containers[_]
    not container.readinessProbe
    msg := "Production pods must have readiness probe"
}