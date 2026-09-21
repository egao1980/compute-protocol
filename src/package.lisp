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

           #:native-process-backend
           #:native-trusted-only-p
           #:native-deny-network-p
           #:native-deny-mounts-p
           #:make-native-process-backend
           #:use-native-process-backend

           #:compute-adapter
           #:compute-adapter-backend
           #:make-compute-adapter))

(in-package #:compute-protocol)
