(defpackage #:compute-protocol/confinement-suite
  (:use #:cl)
  (:nicknames #:stack-compute-suite)
  (:local-nicknames (#:sc #:compute-protocol) (#:pp #:process-protocol))
  (:export #:+suite-cases+
           #:+probe-operations+
           #:case-requirements
           #:suite-case-names

           #:suite-fixture
           #:make-suite-fixture
           #:release-suite-fixture
           #:with-suite-fixture
           #:fixture-root
           #:fixture-area
           #:fixture-readonly
           #:fixture-outside
           #:fixture-secrets
           #:fixture-port
           #:suite-confinement

           #:confinement-probe
           #:probe-program-pathname
           #:probe-command

           #:run-confinement-suite))

(in-package #:compute-protocol/confinement-suite)
