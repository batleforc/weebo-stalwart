{{/*
This operator's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
group: stalwart.weebo.io
versions: [v1alpha1]
# Every kind the operator watches (ClusterRole).
kinds:
  - stalwartinstances
  - stalwartlocalinstances
  - stalwartdomains
  - stalwartnamespacepolicies
  - stalwartserviceaccounts
  - stalwartaccounts
  - stalwartgroups
  - stalwartmailinglists
# The namespaced kinds: what a team may manage (rbac.namespacedExample),
# and the watch Role's (watch.namespace). StalwartInstance,
# StalwartDomain and StalwartNamespacePolicy, cluster-scoped, stay with
# cluster admins.
namespacedKinds:
  - stalwartlocalinstances
  - stalwartserviceaccounts
  - stalwartaccounts
  - stalwartgroups
  - stalwartmailinglists
# Sent to `/validate`: a StalwartDomain's own rules (deletionPolicy Orphan
# only, names); the namespaced kinds' rules and the
# StalwartNamespacePolicy allow-list (domains, names and aliases), and a
# StalwartServiceAccount's Vault targets (D15).
admitted:
  - stalwartdomains
  - stalwartserviceaccounts
  - stalwartaccounts
  - stalwartgroups
  - stalwartmailinglists
# The operator's own environment variables.
env: []
egress:
  - comment: Stalwart instances.
    rules: {{ toJson .Values.networkPolicy.egress.stalwart }}
# Alerts on the operator's own metrics, appended to the kit's.
alerts: []
{{- end -}}
