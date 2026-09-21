;;;; Offline egress-policy demo — :none / :allow / host:port, native deny.
;;;; Native is trusted-only: a policy object is not a packet filter.
;;;;   sbcl --load examples/egress.lisp

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package :compute-protocol)
    (require :asdf)
    (asdf:load-system "compute-protocol")))

(defpackage #:compute-protocol/demo
  (:use #:cl #:compute-protocol)
  (:export #:run))

(in-package #:compute-protocol/demo)

(defun run (&optional (stream *standard-output*))
  "Print a host:port policy and a native sandbox-denied. Returns the condition."
  (let* ((rule (make-egress-rule :host "example.com" :port 443))
         (policy (make-sandbox-network-policy :egress (list rule) :dns "1.1.1.1"))
         (spec (make-sandbox-spec :command '("echo" "hi") :network policy))
         (backend (make-native-process-backend :deny-network-p t)))
    (format stream "~&; network policy host=~s port=~s dns=~s (native is trusted-only)~%"
            (egress-rule-host rule)
            (egress-rule-port rule)
            (sandbox-network-policy-dns policy))
    (assert (sandbox-network-policy-p (sandbox-spec-network spec)))
    (assert (native-trusted-only-p backend))
    (handler-case (run-sandboxed backend spec)
      (sandbox-denied (c)
        (format stream "~&; sandbox-denied policy=~s~%" (sandbox-denied-policy c))
        (assert (eq :network (sandbox-denied-policy c)))
        c))))

#+sbcl
(when (and *load-truename*
           (equal (pathname-name *load-truename*) "egress")
           (find "examples/egress.lisp" sb-ext:*posix-argv* :test #'search))
  (run)
  (uiop:quit 0))
