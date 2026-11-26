{{- define "agp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "agp.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agp.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{ include "agp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "agp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "agp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "agp.secretName" -}}
{{- default (printf "%s-secrets" (include "agp.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "agp.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Environment shared by the app and the migration job. */}}
{{- define "agp.env" -}}
envFrom:
  - configMapRef:
      name: {{ include "agp.fullname" . }}
  - secretRef:
      name: {{ include "agp.secretName" . }}
{{- end -}}
