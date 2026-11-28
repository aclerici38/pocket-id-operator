{{- /* Fail rather than let an upgrade delete resources the removed values rendered */ -}}
{{- $removed := list -}}
{{- $inst := .Values.instance -}}
{{- /* instance.enabled defaulted to true */ -}}
{{- if not (or (kindIs "invalid" $inst) (and (kindIs "map" $inst) (kindIs "bool" $inst.enabled) (not $inst.enabled))) -}}
{{- $removed = append $removed "instance" -}}
{{- end -}}
{{- if .Values.users }}{{ $removed = append $removed "users" }}{{ end -}}
{{- if .Values.userGroups }}{{ $removed = append $removed "userGroups" }}{{ end -}}
{{- if $removed -}}
{{- fail (printf "the %s value(s) were removed from this chart; move them under pocket-id-instance with the same names or this upgrade deletes those resources" (join ", " $removed)) -}}
{{- end -}}

{{- /* Also catch config that was deleted instead of moved */ -}}
{{- if and .Release.IsUpgrade (.Capabilities.APIVersions.Has "pocketid.internal/v1alpha1") -}}
{{- $sub := index .Values "pocket-id-instance" | default dict -}}
{{- $subInstance := $sub.instance | default dict -}}
{{- $instanceNames := list -}}
{{- if $subInstance.enabled }}{{ $instanceNames = append $instanceNames ($subInstance.name | default "pocket-id-instance") }}{{ end -}}
{{- $userNames := list -}}
{{- range $sub.users }}{{ $userNames = append $userNames .name }}{{ end -}}
{{- $groupNames := list -}}
{{- range $sub.userGroups }}{{ $groupNames = append $groupNames .name }}{{ end -}}
{{- $rendered := dict "PocketIDInstance" $instanceNames "PocketIDUser" $userNames "PocketIDUserGroup" $groupNames -}}
{{- $orphaned := list -}}
{{- range $kind, $names := $rendered -}}
{{- range (lookup "pocketid.internal/v1alpha1" $kind $.Release.Namespace "").items -}}
{{- $ann := .metadata.annotations | default dict -}}
{{- $chart := dig "metadata" "labels" "helm.sh/chart" "" . -}}
{{- if and (eq (get $ann "meta.helm.sh/release-name") $.Release.Name) (eq (get $ann "meta.helm.sh/release-namespace") $.Release.Namespace) (hasPrefix "pocket-id-operator-" $chart) (ne (get $ann "helm.sh/resource-policy") "keep") (not (has .metadata.name $names)) -}}
{{- $orphaned = append $orphaned (printf "%s/%s" $kind .metadata.name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $orphaned -}}
{{- fail (printf "this upgrade would delete %s, created by values removed from this chart; declare them under pocket-id-instance with the same names" (join ", " $orphaned)) -}}
{{- end -}}
{{- end -}}
