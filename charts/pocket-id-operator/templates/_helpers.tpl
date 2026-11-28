{{/* Chart name, truncated to the 63-character label limit */}}
{{- define "pocket-id-operator.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Chart name and version for the helm.sh/chart label */}}
{{- define "pocket-id-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "pocket-id-operator.labels" -}}
helm.sh/chart: {{ include "pocket-id-operator.chart" . }}
{{ include "pocket-id-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Name and instance labels */}}
{{- define "pocket-id-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pocket-id-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
