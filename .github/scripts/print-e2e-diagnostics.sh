#!/usr/bin/env bash
set -uo pipefail

# Prints what's needed to debug an e2e run from the Kind cluster it leaves behind (the
# suite runs with SKIP_CLEANUP, so the operator is still deployed): the operator's errors,
# pods, events, the remaining custom resources, and the logs of every container in the e2e
# namespaces, including restarted ones. Each section is a collapsible group in the job log,
# and pod logs get one group per container. Keeps going past failures, since a partial dump
# is still useful.

operator_ns=pocket-id-operator-system
namespaces=("$operator_ns" pocket-id-e2e-test pocket-id-e2e-users)

group() { echo "::group::$1"; }
endgroup() { echo "::endgroup::"; }

# The operator logs with zap's development console encoder: tab-separated, level in caps.
group "Operator errors (last 200)"
for pod in $(kubectl get pods -n "$operator_ns" -o name 2>/dev/null); do
  kubectl logs -n "$operator_ns" "$pod" --all-containers --timestamps 2>&1 | grep -P '\tERROR\t'
done | tail -n 200
endgroup

group "Pods"
kubectl get pods -A -o wide 2>&1
endgroup

group "Events"
kubectl get events -A --sort-by=.lastTimestamp 2>&1
endgroup

for resource in $(kubectl api-resources --api-group=pocketid.internal -o name 2>/dev/null); do
  group "Resources: ${resource%%.*}"
  kubectl get "$resource" -A -o yaml 2>&1
  endgroup
done

for ns in "${namespaces[@]}"; do
  for pod in $(kubectl get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    containers=$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null)
    for container in $containers; do
      group "Logs: $ns / $pod / $container"
      kubectl logs -n "$ns" "$pod" -c "$container" --timestamps 2>&1
      endgroup
      # Only a container that restarted has previous logs.
      if previous=$(kubectl logs -n "$ns" "$pod" -c "$container" --timestamps --previous 2>/dev/null); then
        group "Logs: $ns / $pod / $container (previous, before restart)"
        echo "$previous"
        endgroup
      fi
    done
  done
done

exit 0
