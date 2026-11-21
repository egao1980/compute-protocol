(defsystem "compute-protocol"
  :version "0.3.1"
  :description "CLOS sandboxed compute protocol for cl-stack (run-sandboxed, native trusted backend, R4d confinement of one command)"
  :author "egao1980"
  :license "MIT"
  :depends-on ((:version "process-protocol" "0.4.1") "uiop")
  :properties (:cl-repo
               (:ci (:with ("compute-protocol/capability"))))
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol")
               (:file "native")
               (:file "confinement"))     ; R4d-0: confinement, model backend, launches
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

(defsystem "compute-protocol/confinement-suite"
  :version "0.3.1"
  :description "R4d confinement suite: probe laws every confining backend must keep (SBCL)"
  :author "egao1980"
  :license "MIT"
  :depends-on ((:version "compute-protocol" "0.3.0")
               (:version "process-protocol" "0.4.1")
               (:version "process-backend-uiop" "0.3.1")
               "sb-posix"
               "sb-bsd-sockets"
               "uiop")
  :serial t
  :pathname "src/suite"
  :components ((:file "package")
               (:file "suite")              ; cases, fixture, RUN-CONFINEMENT-SUITE
               (:file "probe")              ; CONFINEMENT-PROBE: subprocess + model methods
               (:static-file "probe-program.lisp"))
  :in-order-to ((test-op (test-op "compute-protocol/tests"))))

(defsystem "compute-protocol/tests"
  :depends-on ("compute-protocol"
               "compute-protocol/capability"
               (:feature :sbcl "compute-protocol/confinement-suite")
               (:version "process-backend-uiop" "0.3.1")
               "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "protocol-test")
               (:file "native-test")
               (:file "capability-test")
               (:file "restarts-test")
               (:file "demo-test")
               (:file "confinement-support")
               (:file "confinement-test")   ; R4d-0: the value, requirements, checks, model
               (:file "launch-test")        ; R4d-0: confine-command, release, run-confined
               (:file "suite-test" :if-feature (:and :sbcl (:not :win32))))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
