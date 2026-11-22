(in-package #:compute-protocol/tests)

;;; R4d-0: the reusable confinement suite (SBCL only: the probe program is
;;; this SBCL with --script). The model backend keeps every law; the
;;; TRUSTING-BACKEND (unconfined, claiming everything) must fail exactly the
;;; deny laws — that proves the probe program and the checks, with no kernel
;;; mechanism in this repo.

(defparameter *deny-cases*
  '(:outside-create :outside-modify :outside-delete :readonly-write :secret-read
    :outside-read-system :network-none :child-inherits :symlink-escape :dotdot-escape
    :hardlink-escape :rename-out :rename-in))

(defun %suite-names () (stack-compute-suite:suite-case-names))

(defvar *last-fixture-root* nil)

(deftest suite-cases-table
  (ok (= 21 (length stack-compute-suite:+suite-cases+)))
  (ok (equal '(:deny-read) (stack-compute-suite:case-requirements :secret-read)))
  (ok (equal '(:read-system) (stack-compute-suite:case-requirements :outside-read-system)))
  (ok (null (stack-compute-suite:case-requirements :symlink-escape)))
  (ok (subsetp *deny-cases* (%suite-names)))
  (ok (signals (stack-compute-suite:case-requirements :nope) 'error))
  (let ((argv (stack-compute-suite:probe-command)))
    (ok (string= "--script" (third (cdr argv))))
    (ok (probe-file (stack-compute-suite:probe-program-pathname)))))

(deftest suite-fixture-layout
  (stack-compute-suite:with-suite-fixture (f)
    (let ((root (stack-compute-suite:fixture-root f)))
      (ok (equal (%ns root) (%ns (physical-dir root))) "physical root")
      (ok (uiop:directory-exists-p (stack-compute-suite:fixture-area f)))
      (ok (uiop:directory-exists-p (stack-compute-suite:fixture-readonly f)))
      (ok (equal "original" (uiop:read-file-string
                             (merge-pathnames "victim" (stack-compute-suite:fixture-outside f)))))
      (ok (equal "secret" (uiop:read-file-string
                           (merge-pathnames "token" (stack-compute-suite:fixture-secrets f)))))
      (ok (integerp (stack-compute-suite:fixture-port f)))
      (ok (handler-case
              (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
                (unwind-protect
                     (progn (sb-bsd-sockets:socket-connect s #(127 0 0 1) (stack-compute-suite:fixture-port f)) t)
                  (sb-bsd-sockets:socket-close s)))
            (error () nil))
          "the listener accepts a connection from the image")
      (setf *last-fixture-root* root)))
  (ng (uiop:directory-exists-p *last-fixture-root*) "released: the tree is gone"))

(deftest-parametrize suite-confinement-shape
    ((features read)
     :ids ("deny-read" "read-system")
     ('(:filesystem :network-none :deny-read :read-system) :all)
     ('(:filesystem :network-none :read-system) :system))
  (stack-compute-suite:with-suite-fixture (f)
    (let* ((backend (compute-protocol:make-model-confinement-backend :features features))
           (c (stack-compute-suite:suite-confinement f backend)))
      (ok (equal (list (%ns (stack-compute-suite:fixture-area f)))
                 (mapcar #'%ns (compute-protocol:confinement-writable c))))
      (ok (equal (list (%ns (stack-compute-suite:fixture-readonly f))
                       (%ns (compute-protocol:physical-path
                             (stack-compute-suite:probe-program-pathname))))
                 (mapcar #'%ns (compute-protocol:confinement-readable c))))
      (ok (eq read (compute-protocol:confinement-read c)))
      (ok (equal (list (%ns (stack-compute-suite:fixture-secrets f)))
                 (mapcar #'%ns (compute-protocol:confinement-deny-read c))))
      (ok (eq :none (compute-protocol:confinement-network c)))
      (ok (eq :private (compute-protocol:confinement-tmp c)))
      (ok (equal "kept" (cdr (assoc "STACK_COMPUTE_SUITE_KEEP" (compute-protocol:confinement-env c)
                                    :test #'string=))))
      (ok (eq :allow (compute-protocol:confinement-network
                      (stack-compute-suite:suite-confinement f backend :network :allow)))))))

;;; #4: under READ :SYSTEM the probe program itself must be readable (a kernel
;;; backend that enforces the read set cannot otherwise open the script), while a
;;; path outside the read set stays denied: the probe's file is listed, not a tree.
(deftest suite-confinement-probe-readable-under-read-system
  (stack-compute-suite:with-suite-fixture (f)
    (let* ((backend (compute-protocol:make-model-confinement-backend
                     :features '(:filesystem :network-none :read-system)))
           (c (stack-compute-suite:suite-confinement f backend))
           (probe (stack-compute-suite:probe-program-pathname)))
      (ok (eq :system (compute-protocol:confinement-read c)))
      (ok (eq :allow (compute-protocol:confinement-decide c :read probe))
          "the probe program is readable")
      (ok (eq :allow (compute-protocol:confinement-decide
                      c :read (merge-pathnames "r" (stack-compute-suite:fixture-readonly f)))))
      (ok (eq :deny (compute-protocol:confinement-decide
                     c :read (merge-pathnames "victim" (stack-compute-suite:fixture-outside f))))
          "outside/victim stays unreadable")
      (ok (eq :deny (compute-protocol:confinement-decide
                     c :read (merge-pathnames "token" (stack-compute-suite:fixture-secrets f))))
          "secrets stay unreadable")
      (ok (eq :deny (compute-protocol:confinement-decide
                     c :read (merge-pathnames "suite.lisp" probe)))
          "the probe's file is listed, not its directory")
      (ok (eq :deny (compute-protocol:confinement-decide
                     c :write probe))
          "the probe program is not writable"))))

(deftest suite-confinement-needs-a-read-policy
  (stack-compute-suite:with-suite-fixture (f)
    (ok (signals (stack-compute-suite:suite-confinement
                  f (compute-protocol:make-model-confinement-backend :features '(:filesystem :network-none)))
                 'compute-protocol:confinement-unsupported))))

;;; The probe program, through an unconfined backend

(deftest probe-program-vocabulary
  (stack-compute-suite:with-suite-fixture (f)
    (let* ((backend (make-instance 'trusting-backend))
           (area (stack-compute-suite:fixture-area f))
           (c (stack-compute-suite:suite-confinement f backend))
           (results (stack-compute-suite:confinement-probe
                     backend c
                     `((:write "a.txt" "hi") (:read "a.txt") (:append "a.txt" "!")
                       (:getenv "STACK_COMPUTE_SUITE_KEEP") (:getenv "NOT_SET_ANYWHERE_R4D")
                       (:cwd) (:child (:write "b.txt" "x") (:getenv "STACK_COMPUTE_SUITE_KEEP"))
                       (:mkdir "d") (:rename "a.txt" "d/a.txt") (:delete "d/a.txt")
                       (:symlink "d" "d-link") (:hardlink "b.txt" "b2.txt")
                       (:connect "127.0.0.1" ,(stack-compute-suite:fixture-port f))
                       (:read "missing.txt")))))
      (ok (= 14 (length results)) "one result per op")
      (ok (equal '(:ok :ok :ok (:value "kept") (:value nil)) (subseq results 0 5)))
      (ok (equal (list :value (string-right-trim "/" (%ns area))) (sixth results)) ":cwd is the area (physical)")
      (ok (equal '(:child :ok (:value "kept")) (seventh results)) "a child process ran the nested ops")
      (ok (equal '(:ok :ok :ok :ok :ok :ok) (subseq results 7 13)))
      (ok (and (consp (nth 13 results)) (eq :error (first (nth 13 results)))) "ENOENT is an error, not a denial")
      (ok (eq :enoent (third (nth 13 results))) "ENOENT is tagged, so a law can read a hidden path")
      (ok (equal "x" (uiop:read-file-string (merge-pathnames "b2.txt" area))) "the hardlink exists")
      (ng (probe-file (merge-pathnames "d/a.txt" area)) "effects are real"))))

(deftest probe-model-in-process
  (stack-compute-suite:with-suite-fixture (f)
    (let* ((backend (compute-protocol:make-model-confinement-backend))
           (c (stack-compute-suite:suite-confinement f backend))
           (outside (%ns (stack-compute-suite:fixture-outside f)))
           (results (stack-compute-suite:confinement-probe
                     backend c
                     `((:write "in.txt" "x")
                       (:write ,(concatenate 'string outside "new") "x")
                       (:child (:write ,(concatenate 'string outside "child") "x") (:write "child.txt" "y"))
                       (:read ,(concatenate 'string (%ns (stack-compute-suite:fixture-secrets f)) "token"))
                       (:connect "127.0.0.1" ,(stack-compute-suite:fixture-port f))
                       (:getenv "STACK_COMPUTE_CONFINEMENT")))))
      (ok (equal '(:ok :denied (:child :denied :ok) :denied :denied (:value "model")) results))
      (ok (probe-file (merge-pathnames "in.txt" (stack-compute-suite:fixture-area f))) "allowed ops happen")
      (ok (probe-file (merge-pathnames "child.txt" (stack-compute-suite:fixture-area f))))
      (ng (probe-file (concatenate 'string outside "new")) "denied ops do not")
      (ng (probe-file (concatenate 'string outside "child"))))))

;;; The suite

(deftest suite-model-keeps-every-law
  (multiple-value-bind (failures ran skipped)
      (stack-compute-suite:run-confinement-suite (compute-protocol:make-model-confinement-backend))
    (ok (null failures) (format nil "no failures: ~s" failures))
    (ok (equal (%suite-names) ran) "every case ran, in order")
    (ok (null skipped))))

(deftest-parametrize suite-model-skips-unsupported
    ((features expected-skipped)
     :ids ("no-read-system-no-allow" "no-deny-read")
     ('(:filesystem :network-none :deny-read) '(:outside-read-system :network-allow))
     ('(:filesystem :network-none :read-system :network-allow) '(:secret-read :outside-read-all)))
  (multiple-value-bind (failures ran skipped)
      (stack-compute-suite:run-confinement-suite
       (compute-protocol:make-model-confinement-backend :features features))
    (ok (null failures) (format nil "no failures: ~s" failures))
    (ok (equal expected-skipped skipped))
    (ok (equal (remove-if (lambda (n) (member n expected-skipped)) (%suite-names)) ran))))

(deftest suite-needs-network-none
  (ok (signals (stack-compute-suite:run-confinement-suite
                (compute-protocol:make-model-confinement-backend
                 :features '(:filesystem :deny-read :read-system :network-allow)))
               'compute-protocol:confinement-unsupported)))

(deftest suite-catches-an-unconfined-backend
  (multiple-value-bind (failures ran skipped)
      (stack-compute-suite:run-confinement-suite (make-instance 'trusting-backend))
    (ok (equal (%suite-names) ran))
    (ok (null skipped))
    (ok (equal *deny-cases* (mapcar #'car failures))
        (format nil "exactly the deny laws fail: ~s" (mapcar #'car failures)))
    (ok (every (lambda (f) (stringp (cdr f))) failures) "each failure says why")))

(deftest-parametrize suite-subset
    ((cases)
     ('(:area-write :outside-create))
     ('(:env-scrubbed :tmpdir-private :cwd-area)))
  (multiple-value-bind (failures ran)
      (stack-compute-suite:run-confinement-suite (compute-protocol:make-model-confinement-backend)
                                                 :cases cases)
    (ok (null failures))
    (ok (equal cases ran))))

(deftest suite-restores-environment
  (stack-compute-suite:run-confinement-suite (compute-protocol:make-model-confinement-backend)
                                             :cases '(:env-scrubbed))
  (ok (member (uiop:getenv "STACK_COMPUTE_SUITE_SECRET") '(nil "") :test #'equal)
      "the image's environment is restored"))

(deftest suite-unavailable-backend
  (ok (signals (stack-compute-suite:run-confinement-suite (make-instance 'absent-backend))
               'compute-protocol:confinement-unavailable)))
