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

## Confinement (0.3.0, R4d)

A `confinement` says what one command may touch: `:writable` directories (the area), `:readable` paths, `:read :all` (minus `:deny-read`, default the credential dirs in `+default-deny-read+`) or `:read :system`, `:network :none` (default) / `:allow` / a policy, an environment scrub (`:env-mode :scrub`, `+default-env-allow+`), a private `TMPDIR`, limits. A `confining-backend` (`compute-backend-seatbelt`, `compute-backend-landlock`) reports `confinement-features` and turns it into a launch: `confine-command` → `confined-launch` (argv + complete env + directory) that any launcher runs — `run-confined`, the supervisor's `compute-executor`, a pty. Unsupported features fail closed (`confinement-unsupported`). `model-confinement-backend` is the reference model (`confinement-decide`), **not a sandbox**. Every backend runs `compute-protocol/confinement-suite` (`run-confinement-suite`). Brief: [cl-stack confinement.md](https://github.com/egao1980/cl-stack/blob/main/docs/capabilities/confinement.md).

Offline demo (policy object + native `sandbox-denied`; no packet filter):

```bash
sbcl --load examples/egress.lisp
```

## License

MIT
