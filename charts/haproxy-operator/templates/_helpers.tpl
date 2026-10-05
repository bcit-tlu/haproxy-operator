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

{{/*
Server-CA source resolution (bcit-tlu/haproxy-operator#39). Exactly one of
dataplane.serverCA.vaultPKI.enabled / .configMap.name / .secretKeyRef.name
may be set; unset → vaultPKI when vault.enabled, else a secretKeyRef-style
fallback to dataplane.tls.existingSecret's ca.crt (the static single-source
layout that predates this field).
*/}}
{{- define "haproxy-operator.serverCAKind" -}}
{{- $v := .Values.dataplane.serverCA -}}
{{- $count := 0 -}}
{{- $kind := "" -}}
{{- if $v.vaultPKI.enabled -}}{{- $count = add1 $count -}}{{- $kind = "vaultPKI" -}}{{- end -}}
{{- if $v.configMap.name -}}{{- $count = add1 $count -}}{{- $kind = "configMap" -}}{{- end -}}
{{- if $v.secretKeyRef.name -}}{{- $count = add1 $count -}}{{- $kind = "secretKeyRef" -}}{{- end -}}
{{- if gt $count 1 -}}
{{- fail "dataplane.serverCA accepts exactly one of vaultPKI.enabled, configMap.name, secretKeyRef.name" -}}
{{- end -}}
{{- if eq $count 0 -}}
{{- if .Values.vault.enabled -}}{{- $kind = "vaultPKI" -}}{{- else -}}{{- $kind = "secretKeyRef" -}}{{- end -}}
{{- end -}}
{{- if and (eq $kind "vaultPKI") (not .Values.vault.enabled) -}}
{{- fail "dataplane.serverCA.vaultPKI requires vault.enabled" -}}
{{- end -}}
{{- $kind -}}
{{- end }}

{{/*
Secret name carrying ca.crt when the server-CA source is a Secret —
explicit secretKeyRef.name, the vaultPKI destination, or the static
fallback to dataplane.tls.existingSecret.
*/}}
{{- define "haproxy-operator.serverCASecretName" -}}
{{- if .Values.dataplane.serverCA.secretKeyRef.name -}}
{{- .Values.dataplane.serverCA.secretKeyRef.name -}}
{{- else if eq (include "haproxy-operator.serverCAKind" .) "vaultPKI" -}}
{{- .Values.dataplane.serverCA.vaultPKI.secretName | default (printf "%s-server-ca" (include "haproxy-operator.fullname" .)) -}}
{{- else -}}
{{- .Values.dataplane.tls.existingSecret -}}
{{- end -}}
{{- end }}

{{/*
Key inside the source object holding the server CA PEM — the vaultPKI
destination always writes ca.crt; other sources honour their .key.
*/}}
{{- define "haproxy-operator.serverCAKey" -}}
{{- $kind := include "haproxy-operator.serverCAKind" . -}}
{{- if eq $kind "vaultPKI" -}}
ca.crt
{{- else if eq $kind "configMap" -}}
{{- .Values.dataplane.serverCA.configMap.key | default "ca.crt" -}}
{{- else -}}
{{- .Values.dataplane.serverCA.secretKeyRef.key | default "ca.crt" -}}
{{- end -}}
{{- end }}
