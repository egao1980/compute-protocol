(defsystem "compute-protocol"
  :version "0.2.0"
  :description "CLOS sandboxed compute protocol for cl-stack (run-sandboxed + native trusted backend)"
  :author "egao1980"
  :license "MIT"
  :depends-on ()
  :properties (:cl-repo
               (:ci (:with ("compute-protocol/capability"))))
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol")
               (:file "native"))
  :in-order-to ((test-op (test-op "compute-protocol/tests"))))

(defsystem "compute-protocol/capability"
  :version "0.1.0"
  :description "capability-protocol :compute adapter over compute-protocol"
  :author "egao1980"
  :license "MIT"
  :depends-on ("compute-protocol" "capability-protocol")
  :serial t
  :pathname "src/capability"
  :components ((:file "adapter"))
  :in-order-to ((test-op (test-op "compute-protocol/tests"))))

(defsystem "compute-protocol/tests"
  :depends-on ("compute-protocol"
               "compute-protocol/capability"
               "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "protocol-test")
               (:file "native-test")
               (:file "capability-test")
               (:file "restarts-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
