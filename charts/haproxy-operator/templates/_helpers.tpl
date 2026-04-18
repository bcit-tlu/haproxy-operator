{{/*
Expand the name of the chart.
*/}}
{{- define "haproxy-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "haproxy-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "haproxy-operator.labels" -}}
helm.sh/chart: {{ include "haproxy-operator.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "haproxy-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "haproxy-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "haproxy-operator.name" . }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "haproxy-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "haproxy-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference with tag fallback to appVersion.
*/}}
{{- define "haproxy-operator.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
