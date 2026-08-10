{{/*
Render-time consistency guards.

These catch configurations that produce perfectly valid YAML but a broken
deployment -- the failure mode `helm lint` cannot see. Each guard turns a
silent runtime failure into a loud install-time error.

Invoked once from deployment.yaml (a template that always renders) so the
checks run on every `helm template` / `helm install` regardless of which
optional resources are enabled.
*/}}
{{- define "tic.guards" -}}

{{/* Prometheus scrape path: ServiceMonitor without a matching NetworkPolicy
     rule renders fine, then every scrape times out. */}}
{{- if and .Values.serviceMonitor.enabled .Values.networkPolicy.enabled }}
  {{- if not .Values.networkPolicy.ingressFromPrometheus.enabled }}
    {{- fail "\n\nserviceMonitor.enabled=true but networkPolicy.ingressFromPrometheus.enabled=false.\nThe ServiceMonitor would be created while the NetworkPolicy drops every scrape.\nSet networkPolicy.ingressFromPrometheus.enabled=true (and point its\nnamespaceSelector at your Prometheus namespace), or disable the ServiceMonitor.\n" }}
  {{- end }}
{{- end }}

{{/* TIC ships no API authentication (no bearer/API-key/OAuth2 dependency in
     src/tic/api/main.py). Exposing it through an Ingress publishes the upload
     and sweep endpoints to anyone who can reach the host. Rate limiting is not
     authentication. Require an explicit acknowledgement rather than silently
     serving an open API.

     Checked BEFORE the connectivity guard below: a misconfigured NetworkPolicy
     merely breaks the deployment, whereas an unacknowledged open API is a
     security decision the operator must make consciously. Guards abort on the
     first failure, so the security one has to come first to be reachable. */}}
{{- if .Values.ingress.enabled }}
  {{- if not .Values.security.acknowledgeNoAuth }}
    {{- fail "\n\ningress.enabled=true but TIC ships NO API authentication.\nEnabling the Ingress exposes POST /api/sweep (file upload + provider quota\nconsumption) with no credential check.\n\nPut an authenticating proxy in front (OIDC / mTLS / API key / reverse-proxy\nauth), then set security.acknowledgeNoAuth=true to confirm you have done so.\n" }}
  {{- end }}
{{- end }}

{{/* Ingress path: an Ingress routing to a pod whose NetworkPolicy drops the
     controller's traffic yields a 504 with no obvious cause. */}}
{{- if and .Values.ingress.enabled .Values.networkPolicy.enabled }}
  {{- if not .Values.networkPolicy.ingressFromIngressController.enabled }}
    {{- fail "\n\ningress.enabled=true but networkPolicy.ingressFromIngressController.enabled=false.\nThe Ingress would route to a pod that drops the controller's traffic.\nSet networkPolicy.ingressFromIngressController.enabled=true (and point its\nnamespaceSelector at your ingress controller's namespace), or disable the Ingress.\n" }}
  {{- end }}
{{- end }}

{{- end }}
