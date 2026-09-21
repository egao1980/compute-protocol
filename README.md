# compute-protocol

Lispy **CLOS** sandboxed compute API for [cl-stack](https://github.com/egao1980/cl-stack) — `run-sandboxed` / `with-sandbox`, wall-clock limits, network/mount policy.

| System | Role | Repo |
|--------|------|------|
| `compute-protocol` (`stack-compute`) | Protocol / API + colocated `native-process-backend` | this repo |
| `compute-protocol/capability` | `:compute` / `run-command` adapter | this repo |
| `compute-backend-podman` | Rootless podman (`podman run` argv) | [`egao1980/compute-backend-podman`](https://github.com/egao1980/compute-backend-podman) |

There is **no in-process CL sandbox**. Untrusted Lisp runs in a container image (`compute-backend-podman`). The colocated `native-process-backend` is **trusted-only**: it does not isolate (no network jail, no packet filter, no mount namespace, no cgroups). Isolation is a **backend property**. It still enforces wall-clock → `sandbox-timeout` (`extend-limit` / `abort-execution` / `abort`).

`sandbox-spec` `:network` is `:none` (default), `:allow`, or a `sandbox-network-policy` (`make-sandbox-network-policy` with `egress-rule` host+port list and optional `dns`). Native `:allow` and a policy object stay trusted-only — packets are not filtered. `native-deny-network-p` signals `sandbox-denied` for both `:allow` and a policy.

`:code` on the native backend signals `sandbox-denied` unless the spec sets `:allow-lisp t` (then `sbcl --script` or `ros --`).

```lisp
(asdf:load-system "compute-protocol")

(let ((backend (stack-compute:make-native-process-backend)))
  (stack-compute:run-sandboxed
   backend
   (stack-compute:make-sandbox-spec :command '("echo" "hi"))))

;; Capability projection
(asdf:load-system "compute-protocol/capability")
(let ((cap (stack-compute:make-compute-adapter
            :backend (stack-compute:make-native-process-backend))))
  (capability-protocol:run-command cap '("echo" "hi")))
```

`process-protocol:run` is used when `*process-backend*` is bound; otherwise UIOP. `process-protocol` is a soft dependency (not in `:depends-on`).

## License

MIT
