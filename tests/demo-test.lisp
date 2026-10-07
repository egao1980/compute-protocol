(in-package #:compute-protocol/tests)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (load (asdf:system-relative-pathname "compute-protocol" "examples/egress.lisp")))

(deftest egress-demo-runs
  (ok (typep (compute-protocol/demo:run (make-broadcast-stream))
             'compute-protocol:sandbox-denied)))
