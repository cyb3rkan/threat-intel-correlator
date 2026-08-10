{{/*
Common labels.

MUST be a superset of tic.selectorLabels. Anything selecting this workload by
label -- the Service's spec.selector, the ServiceMonitor's spec.selector, the
NetworkPolicy's podSelector -- matches on selectorLabels, so a resource whose
metadata.labels omitted them would render valid YAML that silently selects
nothing (helm lint cannot catch that). Including selectorLabels here keeps
every current and future template consistent by construction.
*/}}
{{- define "tic.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "tic.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels -- immutable once a Deployment exists (spec.selector is a
read-only field). Never change these in a patch release; widening tic.labels is
safe, changing selectorLabels requires deleting the Deployment first.
*/}}
{{- define "tic.selectorLabels" -}}
app.kubernetes.io/name: tic
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{- define "tic.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
