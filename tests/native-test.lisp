(in-package #:compute-protocol/tests)

(defun %unix-p ()
  (uiop:os-unix-p))

(deftest native-echo-hi
  (if (not (%unix-p))
      (skip "unix echo")
      (let* ((backend (compute-protocol:make-native-process-backend))
             (result (compute-protocol:run-sandboxed
                      backend
                      (compute-protocol:make-sandbox-spec
                       :command '("echo" "hi")))))
        (ok (compute-protocol:sandbox-result-p result))
        (ok (zerop (compute-protocol:sandbox-result-exit-code result)))
        (ok (search "hi" (compute-protocol:sandbox-result-stdout result))))))

(deftest native-timeout-signals
  (if (not (%unix-p))
      (skip "unix sleep")
      (ok (signals (compute-protocol:run-sandboxed
                    (compute-protocol:make-native-process-backend)
                    (compute-protocol:make-sandbox-spec
                     :command '("sleep" "5")
                     :wall-clock 0.2))
                   'compute-protocol:sandbox-timeout))))

(deftest native-network-allow
  (if (not (%unix-p))
      (skip "unix echo")
      (let ((result (compute-protocol:run-sandboxed
                     (compute-protocol:make-native-process-backend)
                     (compute-protocol:make-sandbox-spec
                      :command '("echo" "hi")
                      :network :allow))))
        (ok (search "hi" (compute-protocol:sandbox-result-stdout result))))))

(deftest native-network-denied
  (ok (signals (compute-protocol:run-sandboxed
                (compute-protocol:make-native-process-backend :deny-network-p t)
                (compute-protocol:make-sandbox-spec
                 :command '("echo" "hi")
                 :network :allow))
               'compute-protocol:sandbox-denied)))

(deftest native-network-policy-denied
  (ok (signals (compute-protocol:run-sandboxed
                (compute-protocol:make-native-process-backend :deny-network-p t)
                (compute-protocol:make-sandbox-spec
                 :command '("echo" "hi")
                 :network (compute-protocol:make-sandbox-network-policy
                           :egress (list (compute-protocol:make-egress-rule
                                          :host "example.com"
                                          :port 443)))))
               'compute-protocol:sandbox-denied)))

(deftest native-code-denied-without-allow-lisp
  (ok (signals (compute-protocol:run-sandboxed
                (compute-protocol:make-native-process-backend)
                (compute-protocol:make-sandbox-spec
                 :code "(write-string \"hi\")"
                 :runtime :sbcl))
               'compute-protocol:sandbox-denied)))

(deftest native-trusted-only-default
  (ok (compute-protocol:native-trusted-only-p
       (compute-protocol:make-native-process-backend))))

(deftest with-sandbox-reuses-spec
  (if (not (%unix-p))
      (skip "unix echo")
      (compute-protocol:with-sandbox
          (session (compute-protocol:make-native-process-backend)
                   (compute-protocol:make-sandbox-spec :command '("echo" "hi")))
        (ok (compute-protocol:sandbox-session-p session))
        (let ((result (compute-protocol:run-sandboxed session nil)))
          (ok (search "hi" (compute-protocol:sandbox-result-stdout result)))))))
