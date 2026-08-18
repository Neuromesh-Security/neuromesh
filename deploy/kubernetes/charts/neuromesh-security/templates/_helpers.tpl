{{- define "neuromesh.namespace" -}}
{{- .Values.namespace.name -}}
{{- end -}}

{{- define "neuromesh.imageRef" -}}
{{- $repo := .repository -}}
{{- $digest := .digest | default "" -}}
{{- $tag := .tag | default "" -}}
{{- if $digest -}}
{{ printf "%s@%s" $repo $digest }}
{{- else if $tag -}}
{{ printf "%s:%s" $repo $tag }}
{{- else -}}
{{- fail "image tag or digest is required" -}}
{{- end -}}
{{- end -}}
