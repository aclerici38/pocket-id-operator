{{/*
Chart name, truncated to 63 characters for Kubernetes compatibility.
*/}}
{{- define "pocket-id-instance.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Chart name and version as used by the helm.sh/chart label.
*/}}
{{- define "pocket-id-instance.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Resolved name of the PocketIDInstance.
*/}}
{{- define "pocket-id-instance.instanceName" -}}
{{- .Values.instance.name | default .Chart.Name }}
{{- end }}

{{/*
Selector labels placed on the PocketIDInstance and referenced by each
user/group/client's spec.instanceSelector, so this release's resources bind to
this release's instance (multiple instance releases with different names stay
isolated). Override with instance.selectorLabels; defaults to a single label
keyed by the instance name. Returns YAML (parse with fromYaml for a dict).
*/}}
{{- define "pocket-id-instance.selectorLabels" -}}
{{- if .Values.instance.selectorLabels -}}
{{- toYaml .Values.instance.selectorLabels -}}
{{- else -}}
pocketid.internal/instance: {{ include "pocket-id-instance.instanceName" . }}
{{- end -}}
{{- end }}

{{/*
Common recommended labels applied to every rendered resource.
Call with a context dict: {"root": $, "component": "<instance|user|usergroup|oidcclient>"}.

app.kubernetes.io/name is intentionally NOT emitted here: it is hardcoded to
"pocket-id" as a literal in each template so the value stays stable across
versions and is not accidentally changed via a helper (the operator selects the
instance Service on it). Everything else follows the recommended-labels spec.
*/}}
{{- define "pocket-id-instance.labels" -}}
helm.sh/chart: {{ include "pocket-id-instance.chart" .root }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: pocket-id
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- with .component }}
app.kubernetes.io/component: {{ . }}
{{- end }}
{{- with .root.Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- end }}
