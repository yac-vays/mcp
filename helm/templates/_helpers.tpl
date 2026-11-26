{{/*
Expand the name of the chart.
*/}}
{{- define "name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "fullname" -}}
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
Chart label value.
*/}}
{{- define "chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}


{{/*
External base URL (YAC_MCP_PUBLIC_URL): `publicUrl`, or derived from the first
ingress host (https if that host has a TLS entry), else localhost (only
useful with a port-forward). The gateway must be served
at the root of its host: the URL is the OAuth issuer and `{url}/mcp` the MCP
endpoint.
*/}}
{{- define "publicUrl" -}}
{{- if .Values.publicUrl -}}
{{- .Values.publicUrl | trimSuffix "/" -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts -}}
{{- $host := (index .Values.ingress.hosts 0).host -}}
{{- $scheme := "http" -}}
{{- range .Values.ingress.tls -}}
{{- if has $host .hosts -}}
{{- $scheme = "https" -}}
{{- end -}}
{{- end -}}
{{- printf "%s://%s" $scheme $host -}}
{{- else -}}
http://localhost:8080
{{- end -}}
{{- end }}

{{/*
The allowed changes as JSON list, checked at render time (`readOnly` was
replaced by `allow`).
*/}}
{{- define "allow" -}}
{{- if hasKey .Values "readOnly" -}}
{{- fail "readOnly was replaced by allow: a list of create, edit, delete, actions ([] = read-only)" -}}
{{- end -}}
{{- if not (kindIs "slice" .Values.allow) -}}
{{- fail "allow must be a list of create, edit, delete, actions" -}}
{{- end -}}
{{- range .Values.allow -}}
{{- if not (has . (list "create" "edit" "delete" "actions")) -}}
{{- fail (printf "allow: unknown operation %q (create, edit, delete, actions)" (toString .)) -}}
{{- end -}}
{{- end -}}
{{- .Values.allow | uniq | toJson -}}
{{- end -}}
