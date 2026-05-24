# Falco Operator v0.2.0 — Operational Validation

Hands-on validation of [Falco Operator v0.2.0](https://github.com/falcosecurity/falco-operator/releases/tag/v0.2.0)
on EKS, focused not on _whether Falco detects_ but on **whether the OCI artifact lifecycle is
operationally viable** — installation, rule distribution, hot reload, rollback, plugin lifecycle,
operator upgrade.

Cross-referenced with the official **KubeCon EU 2026 Falco Maintainers Track** talk
("In Falco's Nest: The Evolution of Cloud Native Runtime Security", Aldo Lacuku / Iacopo Rozzo,
2026-03-24) — facts confirmed against the maintainers' design intent where relevant.

This repository accompanies the Qiita article **[Falco Operator v0.2.0 徹底解説 — 何者で、何を変え、本番に耐えるのか](https://qiita.com/keitah/items/ca2a543ea2b500676250)** and contains:

- The custom Falco rules pushed as OCI artifacts during the validation (`rules/`)
- Sample CRD manifests for the patterns the official docs do not cover (`manifests/`)
- The EKS cluster definition used (`infra/`)
- A list of the 16 non-obvious operational findings encountered (see below)

## Environment

| Component | Value |
|---|---|
| Kubernetes | EKS 1.31.14 |
| Region | ap-northeast-1 |
| Nodes | 2 × t3.large (Amazon Linux 2023, kernel 6.1.170) |
| Falco Operator | v0.2.0 (released 2026-03-23) |
| Falco | 0.43.0 (modern eBPF probe) |
| OCI Registry | private ECR with auth Secret |

## Scenarios run

| # | Scenario | Result |
|---|---|---|
| 1 | Basic installation (Quickstart) | ✅ All 5 CRDs + 5 components |
| 2 | Runtime detection | ✅ Default rules fire, dual k8s/k8smeta enrichment |
| 3 | OCI Artifact rule distribution (private ECR) | ✅ (7 footguns discovered) |
| 4 | Rule hot reload via tag change | ❌ **Tag change does not trigger re-pull** |
| 5 | Broken rule rollback | ⚠️ Hot restart is graceful; cold start crashes → mixed-state DaemonSet |
| 6 | Metadata enrichment under scale | ✅ k8smeta populated within ~3 s even on fresh pods |
| 7 | False positive load (apt-get update × 10) | ✅ Zero alerts — default 25-rule set is surgical |
| 8 | Falcosidekick webhook routing | ✅ Delivered, no duplicates, both replicas active |
| 9 | Plugin lifecycle (`json` plugin add) | ✅ **5 s hot restart, no pod restart** |
| 10 | Operator upgrade (simulated via rollout-restart) | ✅ 11 s controller swap, Falco unaffected |

## 17 findings worth knowing before you try v0.2.0 in production

### Install-time gotchas
1. **install.yaml CRDs exceed kubectl's 262 KB annotation limit** — `kubectl apply -f install.yaml`
   fails for the `falcos` and `components` CRDs. Use `kubectl apply --server-side --force-conflicts`.
2. **EKS 1.31 dropped the in-tree EBS provisioner** — Quickstart's Redis StatefulSet sits in
   `Pending` until you install the `aws-ebs-csi-driver` addon and a `gp3` StorageClass
   (see `infra/gp3-storageclass.yaml`).

### Architecture worth understanding
3. **`artifact-operator` is a Kubernetes native sidecar** — declared as an `initContainer`
   with `restartPolicy: Always`, requiring Kubernetes 1.29+.
4. **CRDs split into two API groups** — `instance.falcosecurity.dev` (Falco, Component) vs
   `artifact.falcosecurity.dev` (Rulesfile, Plugin, Config). "What to run" vs "what to load."
5. The `k8smeta` plugin connects to `metacollector` with exponential backoff,
   ~30 s before the first event is received.
6. **Two enrichment paths populate independently**: standard `k8s.*` from container
   introspection and `k8smeta.*` from the metacollector plugin — both appear on the same alert.

### Private OCI registry (ECR) footguns
7. The `falco` ServiceAccount in the default install **has no RBAC to read Secrets** — the
   artifact-operator silently fails with `secrets is forbidden`.
   Fix: `manifests/rbac-falco-secrets.yaml`.
8. The Rulesfile `registry.auth.secretRef` expects an **`Opaque` Secret with `username` and
   `password` keys**, not `kubernetes.io/dockerconfigjson`. The error is unhelpful:
   `key "username" not found in secret`.
9. The artifact-operator adds a finalizer `artifact.falcosecurity.dev/secret-in-use` to any
   referenced Secret — `kubectl delete secret` then hangs in `Terminating`.
   Patch the finalizer out before recreating.
10. **ECR tokens expire every 12 hours.** The in-cluster Secret needs rotation
    (CronJob, IRSA + ECR helper, or an external operator).

### Writing custom rules
11. **`spawned_process` and `container` macros are not defined in the default OCI rules artifact.**
    The 25-rule default set is minimal — you must inline `evt.type=execve` and `container.id != host`
    in your own rules. Compare `rules/02-attempt-v2-buggy.yaml` (broken) vs
    `rules/03-marker-only.yaml` (working).
12. **`oras push` of a `.tar.gz` produces an artifact Falco cannot parse.**
    Use `falcoctl registry push --type rulesfile` instead — falcoctl generates the
    additional config-blob and dependency layers the artifact-operator expects.

### The operational gaps that bit hardest
13. **Hot reload is broken for rule tag changes.** Patching `spec.ociArtifact.image.tag` flips
    the Rulesfile status to `Programmed: True` within ~1 s but the artifact-operator does **not**
    re-pull. The on-disk rules file remains unchanged. Pod restart is required to pick up the new
    tag — and brings ~45 s of detection downtime. Filed upstream as
    [falco-operator#337](https://github.com/falcosecurity/falco-operator/issues/337).
14. Falco's **internal "hot restart"** mechanism falls back gracefully to the previously-loaded
    ruleset when a new rules file fails validation, emitting a Critical `Falco internal: hot restart failure`
    event — useful for monitoring.
15. **A broken rule on cold start kills the Falco container.** No fallback exists for pods that
    start fresh, so a rolling restart with a broken rule produces a **mixed-state DaemonSet**
    where some pods keep running on old rules and others CrashLoop — your nodes will silently
    have different detection coverage.
16. **Plugin lifecycle is asymmetric with rule lifecycle** — adding a Plugin CRD triggers Falco
    hot-restart and the plugin loads in ~5 s with no pod restart. The same machinery seemingly
    does not fire on Rulesfile tag changes (see #13).

### Org-level operational gotcha
17. **Enterprise Slack workspaces block self-service `Incoming Webhooks` install** — the most
    obvious Falcosidekick output (`SLACK_WEBHOOKURL`) requires admin approval. Plan the
    notification-pipeline ownership before you start, or use webhook.site / PagerDuty / Email
    while you wait.

## Reproducing the validation

```bash
# 1. EKS cluster
eksctl create cluster -f infra/eksctl-cluster.yaml
kubectl apply -f infra/gp3-storageclass.yaml

# 2. Falco Operator
kubectl apply --server-side --force-conflicts \
  -f https://github.com/falcosecurity/falco-operator/releases/download/v0.2.0/install.yaml
kubectl apply --server-side --force-conflicts \
  -f https://github.com/falcosecurity/falco-operator/releases/download/v0.2.0/quickstart.yaml

# 3. RBAC + ECR auth for private OCI rules
kubectl apply -f manifests/rbac-falco-secrets.yaml
ECR_TOKEN=$(aws ecr get-login-password --region <REGION>)
kubectl create secret generic ecr-auth -n falco \
  --from-literal=username=AWS --from-literal=password="$ECR_TOKEN"

# 4. Push custom rules and reference them
echo "$ECR_TOKEN" | falcoctl registry auth basic --username AWS --password-stdin \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
falcoctl registry push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/falco-rules:custom-v1 \
  --type rulesfile --version 0.0.1 --config /dev/null rules/03-marker-only.yaml
kubectl apply -f manifests/rulesfile-custom.yaml   # edit registry hostname first

# 5. (optional) add the json plugin and a webhook output
kubectl apply -f manifests/plugin-json.yaml
kubectl apply -f manifests/component-falcosidekick-webhook.yaml
```

## Triggers used in the validation

```bash
# Default rule — fires "Read sensitive file untrusted"
kubectl exec -n test <pod> -- cat /etc/shadow

# Default rule — fires "Netcat Remote Code Execution in Container" (needs alpine, nginx has no nc)
kubectl exec -n test <alpine-pod> -- nc -e /bin/sh 127.0.0.1 9999

# Custom marker rule — fires only when rules/03-marker-only.yaml is loaded
kubectl exec -n test <pod> -- /bin/falcomarker || true
```

## License

Apache 2.0 — see `LICENSE`.
