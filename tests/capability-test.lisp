(in-package #:compute-protocol/tests)

(deftest capability-run-command
  (if (not (uiop:os-unix-p))
      (skip "unix echo")
      (let* ((backend (compute-protocol:make-native-process-backend))
             (cap (compute-protocol:make-compute-adapter :backend backend))
             (result (capability-protocol:run-command cap '("echo" "hi"))))
        (ok (compute-protocol:sandbox-result-p result))
        (ok (search "hi" (compute-protocol:sandbox-result-stdout result)))
        (let ((bb (blackboard-protocol:make-blackboard)))
          (capability-protocol:register-capability bb cap)
          (ok (eq cap (capability-protocol:get-capability bb :compute)))
          (ok (capability-protocol:capability-supported-p bb :compute))
          (ok (search "hi"
                      (compute-protocol:sandbox-result-stdout
                       (capability-protocol:invoke-operation
                        cap 'capability-protocol:run-command '("echo" "hi")))))))))
