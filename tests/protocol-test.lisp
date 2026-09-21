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

(deftest spec-accepts-network-policy
  (let* ((rule (compute-protocol:make-egress-rule :host "example.com" :port 443))
         (policy (compute-protocol:make-sandbox-network-policy
                  :egress (list rule)
                  :dns "1.1.1.1"))
         (s (compute-protocol:make-sandbox-spec
             :command '("echo" "x")
             :network policy)))
    (ok (compute-protocol:egress-rule-p rule))
    (ok (string= "example.com" (compute-protocol:egress-rule-host rule)))
    (ok (= 443 (compute-protocol:egress-rule-port rule)))
    (ok (compute-protocol:sandbox-network-policy-p policy))
    (ok (eq policy (compute-protocol:sandbox-spec-network s)))
    (ok (equal "1.1.1.1" (compute-protocol:sandbox-network-policy-dns policy)))
    (ok (eq rule (first (compute-protocol:sandbox-network-policy-egress policy))))))

(deftest coerce-command-list
  (let ((s (compute-protocol:coerce-sandbox-spec '("echo" "hi"))))
    (ok (equal '("echo" "hi") (compute-protocol:sandbox-spec-command s)))))

(deftest coerce-plist
  (let ((s (compute-protocol:coerce-sandbox-spec
            '(:command ("uname") :network :allow :wall-clock 2))))
    (ok (eq :allow (compute-protocol:sandbox-spec-network s)))
    (ok (= 2 (compute-protocol:sandbox-spec-wall-clock s)))))
