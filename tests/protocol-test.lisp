(in-package #:compute-protocol/tests)

(deftest spec-defaults
  (let ((s (compute-protocol:make-sandbox-spec :command '("echo" "x"))))
    (ok (compute-protocol:sandbox-spec-p s))
    (ok (eq :none (compute-protocol:sandbox-spec-network s)))
    (ok (eq :native (compute-protocol:sandbox-spec-runtime s)))
    (ok (null (compute-protocol:sandbox-spec-wall-clock s)))
    (ng (compute-protocol:sandbox-spec-allow-lisp-p s))))

(deftest spec-rejects-bad-network
  (ok (signals (compute-protocol:make-sandbox-spec :network :wifi)
               'compute-protocol:compute-error)))

(deftest coerce-command-list
  (let ((s (compute-protocol:coerce-sandbox-spec '("echo" "hi"))))
    (ok (equal '("echo" "hi") (compute-protocol:sandbox-spec-command s)))))

(deftest coerce-plist
  (let ((s (compute-protocol:coerce-sandbox-spec
            '(:command ("uname") :network :allow :wall-clock 2))))
    (ok (eq :allow (compute-protocol:sandbox-spec-network s)))
    (ok (= 2 (compute-protocol:sandbox-spec-wall-clock s)))))
