(in-package #:compute-protocol/tests)

(deftest timeout-extend-limit
  (if (not (uiop:os-unix-p))
      (skip "unix sleep")
      (let ((got nil))
        (handler-bind ((compute-protocol:sandbox-timeout
                        (lambda (c)
                          (declare (ignore c))
                          (invoke-restart 'compute-protocol:extend-limit 3))))
          (setf got (compute-protocol:run-sandboxed
                     (compute-protocol:make-native-process-backend)
                     (compute-protocol:make-sandbox-spec
                      :command '("sleep" "0.3")
                      :wall-clock 0.15))))
        (ok (compute-protocol:sandbox-result-p got))
        (ok (zerop (compute-protocol:sandbox-result-exit-code got))))))

(deftest timeout-abort-execution
  (if (not (uiop:os-unix-p))
      (skip "unix sleep")
      (let ((got :unset))
        (handler-bind ((compute-protocol:sandbox-timeout
                        (lambda (c)
                          (declare (ignore c))
                          (invoke-restart 'compute-protocol:abort-execution))))
          (setf got (compute-protocol:run-sandboxed
                     (compute-protocol:make-native-process-backend)
                     (compute-protocol:make-sandbox-spec
                      :command '("sleep" "5")
                      :wall-clock 0.15))))
        (ok (null got)))))

(deftest timeout-abort
  (if (not (uiop:os-unix-p))
      (skip "unix sleep")
      (let ((got :unset))
        (handler-bind ((compute-protocol:sandbox-timeout
                        (lambda (c)
                          (abort c))))
          (setf got (compute-protocol:run-sandboxed
                     (compute-protocol:make-native-process-backend)
                     (compute-protocol:make-sandbox-spec
                      :command '("sleep" "5")
                      :wall-clock 0.15))))
        (ok (null got)))))
