(defpackage #:compute-protocol
  (:use #:cl)
  (:nicknames #:stack-compute)
  (:export #:compute-error
           #:compute-error-message
           #:compute-error-spec
           #:sandbox-timeout
           #:sandbox-timeout-limit
           #:sandbox-oom
           #:sandbox-oom-limit
           #:sandbox-denied
           #:sandbox-denied-policy
           #:extend-limit
           #:abort-execution

           #:compute-backend
           #:*compute-backend*

           #:sandbox-spec
           #:sandbox-spec-p
           #:make-sandbox-spec
           #:coerce-sandbox-spec
           #:sandbox-spec-command
           #:sandbox-spec-code
           #:sandbox-spec-runtime
           #:sandbox-spec-mounts
           #:sandbox-spec-env
           #:sandbox-spec-network
           #:sandbox-spec-cpu-limit
           #:sandbox-spec-memory-limit
           #:sandbox-spec-wall-clock
           #:sandbox-spec-allow-lisp-p
           #:sandbox-spec-artifacts
           #:sandbox-spec-confinement
           #:sandbox-spec-directory
           #:sandbox-spec-input
           #:+mount-modes+
           #:parse-mount
           #:mount-mode

           #:egress-rule
           #:egress-rule-p
           #:make-egress-rule
           #:egress-rule-host
           #:egress-rule-port

           #:sandbox-network-policy
           #:sandbox-network-policy-p
           #:make-sandbox-network-policy
           #:sandbox-network-policy-egress
           #:sandbox-network-policy-dns

           #:sandbox-result
           #:sandbox-result-p
           #:make-sandbox-result
           #:sandbox-result-exit-code
           #:sandbox-result-stdout
           #:sandbox-result-stderr
           #:sandbox-result-artifacts

           #:sandbox-session
           #:sandbox-session-p
           #:make-sandbox-session
           #:sandbox-session-backend
           #:sandbox-session-spec

           #:run-sandboxed
           #:open-sandbox
           #:close-sandbox
           #:with-sandbox
           #:sandbox-copy-to
           #:sandbox-copy-from
           #:sandbox-unsupported
           #:sandbox-unsupported-backend
           #:sandbox-unsupported-operation

           #:native-process-backend
           #:native-trusted-only-p
           #:native-deny-network-p
           #:native-deny-mounts-p
           #:make-native-process-backend
           #:use-native-process-backend

           #:compute-adapter
           #:compute-adapter-backend
           #:make-compute-adapter

           ;; R4d-0: confinement of one command
           #:invalid-confinement
           #:invalid-confinement-field
           #:invalid-confinement-value
           #:confinement-unsupported
           #:confinement-unsupported-backend
           #:confinement-unsupported-missing
           #:confinement-unavailable
           #:confinement-unavailable-backend
           #:confinement-unavailable-reason

           #:+confinement-features+
           #:+default-env-allow+
           #:+default-deny-read+
           #:+device-paths+

           #:confinement
           #:confinement-p
           #:make-confinement
           #:confinement-writable
           #:confinement-readable
           #:confinement-read
           #:confinement-deny-read
           #:confinement-network
           #:confinement-env-mode
           #:confinement-env-allow
           #:confinement-env
           #:confinement-tmp
           #:confinement-cpu-limit
           #:confinement-memory-limit
           #:confinement-file-size-limit
           #:confinement-process-limit
           #:confinement-wall-clock
           #:default-deny-read

           #:confining-backend
           #:model-confinement-backend
           #:make-model-confinement-backend
           #:model-backend-features
           #:confinement-features
           #:confinement-supports-p
           #:confinement-available-p
           #:backend-confine-argv

           #:confinement-requirements
           #:check-confinement
           #:physical-path
           #:resolve-confinement
           #:system-read-paths
           #:confinement-decide
           #:confinement-environment
           #:image-environment
           #:confinement-summary

           #:confined-launch
           #:confined-launch-p
           #:confined-launch-backend
           #:confined-launch-confinement
           #:confined-launch-argv
           #:confined-launch-env
           #:confined-launch-directory
           #:confined-launch-tmp
           #:confined-launch-released-p
           #:confine-command
           #:release-confined-launch
           #:with-confined-launch
           #:run-confined))

(in-package #:compute-protocol)
