# Kubernetes RBAC Policy using Open Policy Agent (OPA)
# Enforces Role-Based Access Control best practices

package kubernetes.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Allow if no violations
allow if {
    not violation[_]
}

violation[msg] {
    input.kind == "ClusterRole"
    rule := input.rules[_]
    "*" in rule.verbs
    "*" in rule.resources
    msg := "ClusterRole must not grant wildcard permissions on all resources"
}

violation[msg] {
    input.kind == "ClusterRole"
    rule := input.rules[_]
    "create" in rule.verbs
    "pods/exec" in rule.resources
    msg := "ClusterRole must not allow pod exec creation"
}

violation[msg] {
    input.kind == "ClusterRole"
    rule := input.rules[_]
    "create" in rule.verbs
    "nodes/proxy" in rule.resources
    msg := "ClusterRole must not allow node proxy access"
}

violation[msg] {
    input.kind == "Role"
    rule := input.rules[_]
    "*" in rule.verbs
    "secrets" in rule.resources
    msg := "Role must not grant wildcard access to secrets"
}

violation[msg] {
    input.kind == "Role"
    input.metadata.namespace == "kube-system"
    not startswith(input.metadata.name, "system:")
    msg := "Custom roles in kube-system namespace must be prefixed with 'system:'"
}

# ClusterRoleBinding Security
violation[msg] {
    input.kind == "ClusterRoleBinding"
    subject := input.subjects[_]
    subject.kind == "User"
    subject.name == "system:anonymous"
    msg := "ClusterRoleBinding must not bind to anonymous user"
}

violation[msg] {
    input.kind == "ClusterRoleBinding"
    input.roleRef.name == "cluster-admin"
    subject := input.subjects[_]
    subject.kind == "ServiceAccount"
    subject.namespace != "kube-system"
    msg := "cluster-admin should not be bound to service accounts outside kube-system"
}

# ServiceAccount Security
violation[msg] {
    input.kind == "ServiceAccount"
    input.automountServiceAccountToken == true
    not input.metadata.annotations["kubernetes.io/enforce-mountable-secrets"]
    msg := "ServiceAccount with automounted token should restrict mountable secrets"
}

violation[msg] {
    input.kind == "ServiceAccount"
    input.metadata.namespace == "default"
    input.metadata.name != "default"
    msg := "Custom service accounts should not be created in default namespace"
}

# RoleBinding Security
violation[msg] {
    input.kind == "RoleBinding"
    subject := input.subjects[_]
    subject.kind == "Group"
    subject.name == "system:authenticated"
    msg := "RoleBinding should not bind to all authenticated users"
}

violation[msg] {
    input.kind == "RoleBinding"
    subject := input.subjects[_]
    subject.kind == "User"
    not contains(subject.name, "@")
    not startswith(subject.name, "system:")
    msg := "User subjects should use email format or system: prefix"
}

# PSP or Pod Security Standards
violation[msg] {
    input.kind == "PodSecurityPolicy"
    input.spec.privileged == true
    msg := "PodSecurityPolicy should not allow privileged containers"
}

violation[msg] {
    input.kind == "PodSecurityPolicy" 
    input.spec.allowPrivilegeEscalation == true
    msg := "PodSecurityPolicy should not allow privilege escalation"
}

violation[msg] {
    input.kind == "PodSecurityPolicy"
    input.spec.hostNetwork == true
    msg := "PodSecurityPolicy should not allow host network access"
}

violation[msg] {
    input.kind == "PodSecurityPolicy"
    input.spec.hostPID == true
    msg := "PodSecurityPolicy should not allow host PID access"
}

# Network Policy RBAC
violation[msg] {
    input.kind == "Role"
    rule := input.rules[_]
    "networkpolicies" in rule.resources
    "*" in rule.verbs
    input.metadata.namespace != "kube-system"
    msg := "Role should not grant wildcard access to NetworkPolicies outside kube-system"
}

# Admission Controller Configuration
violation[msg] {
    input.kind == "ValidatingAdmissionWebhook"
    not input.admissionReviewVersions
    msg := "ValidatingAdmissionWebhook must specify admissionReviewVersions"
}

violation[msg] {
    input.kind == "MutatingAdmissionWebhook"
    input.failurePolicy != "Fail"
    msg := "MutatingAdmissionWebhook should use 'Fail' as failure policy"
}

# CRD Security
violation[msg] {
    input.kind == "CustomResourceDefinition"
    not input.spec.versions[_].schema.openAPIV3Schema
    msg := "CustomResourceDefinition must define OpenAPI v3 schema"
}

# Secret Access Restrictions
high_privilege_verbs := ["create", "update", "patch", "delete"]

violation[msg] {
    input.kind == "Role"
    rule := input.rules[_]
    "secrets" in rule.resources
    verb := rule.verbs[_]
    verb in high_privilege_verbs
    not input.metadata.annotations["rbac.authorization.kubernetes.io/autoupdate"] == "false"
    msg := sprintf("Role with %s access to secrets should be manually managed", [verb])
}

# Prevent overly broad resource access
broad_resources := ["*", "pods/*", "services/*"]

violation[msg] {
    input.kind == "ClusterRole"
    rule := input.rules[_]
    resource := rule.resources[_]
    resource in broad_resources
    not startswith(input.metadata.name, "system:")
    msg := sprintf("ClusterRole should not use broad resource access: %s", [resource])
}

# Certificate and key management
violation[msg] {
    input.kind == "Role"
    rule := input.rules[_]
    "certificatesigningrequests" in rule.resources
    "approve" in rule.verbs
    not input.metadata.annotations["security.kubernetes.io/csr-approval-required"]
    msg := "Role with CSR approval should require additional authorization"
}
