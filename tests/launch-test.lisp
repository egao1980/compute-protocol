(in-package #:compute-protocol/tests)

;;; R4d-0: CONFINE-COMMAND, RELEASE-CONFINED-LAUNCH, WITH-CONFINED-LAUNCH,
;;; RUN-CONFINED and RUN-SANDBOXED on a confining backend.

(defun %env-value (name launch)
  (cdr (assoc name (compute-protocol:confined-launch-env launch) :test #'string=)))

(defun %area-confinement (root &rest args)
  (apply #'compute-protocol:make-confinement :writable (list (sub root "area/"))
         :readable (list (sub root "ro/")) args))

(deftest confine-command-model
  (with-temp-tree (root "area/" "ro/")
    (let* ((backend (compute-protocol:make-model-confinement-backend))
           (launch (compute-protocol:confine-command backend (%area-confinement root) '("echo" "hi"))))
      (unwind-protect
           (let ((tmp (compute-protocol:confined-launch-tmp launch)))
             (ok (compute-protocol:confined-launch-p launch))
             (ok (eq backend (compute-protocol:confined-launch-backend launch)))
             (ok (equal '("echo" "hi") (compute-protocol:confined-launch-argv launch)) "the model runs argv as is")
             (ok (equal "model" (%env-value "STACK_COMPUTE_CONFINEMENT" launch)) "the backend's extra env")
             (ok (equal (%ns (sub root "area/")) (%ns (compute-protocol:confined-launch-directory launch)))
                 "the default directory is the first writable")
             (ok (and tmp (uiop:directory-exists-p tmp)) "a private temp directory exists")
             (ok (and tmp (equal (%ns tmp) (%ns (physical-dir tmp)))) "physical")
             (ok (and tmp (uiop:string-prefix-p (%ns (physical-dir (uiop:temporary-directory))) (%ns tmp)))
                 "under the system temp directory")
             (ok (and tmp (equal (%ns tmp) (%env-value "TMPDIR" launch))) "TMPDIR points at it")
             (ok (equal (list (%ns (sub root "area/")))
                        (mapcar #'%ns (compute-protocol:confinement-writable
                                       (compute-protocol:confined-launch-confinement launch))))
                 "the launch carries the resolved confinement")
             (ng (compute-protocol:confined-launch-released-p launch)))
        (compute-protocol:release-confined-launch launch)))))

(deftest confine-command-scrubs-environment
  (with-temp-tree (root "area/" "ro/")
    (let ((launch (compute-protocol:confine-command
                   (compute-protocol:make-model-confinement-backend)
                   (%area-confinement root :env '(("KEEP" . "1")))
                   '("true")
                   :env '(("EXTRA" . "2")))))
      (unwind-protect
           (let ((names (mapcar #'car (compute-protocol:confined-launch-env launch))))
             (ok (equal "1" (%env-value "KEEP" launch)) "confinement env")
             (ok (equal "2" (%env-value "EXTRA" launch)) ":env extra")
             (ok (every (lambda (n)
                          (or (member n '("KEEP" "EXTRA" "TMPDIR" "STACK_COMPUTE_CONFINEMENT") :test #'string=)
                              (some (lambda (pat)
                                      (if (char= #\* (char pat (1- (length pat))))
                                          (uiop:string-prefix-p (subseq pat 0 (1- (length pat))) n)
                                          (string= pat n)))
                                    compute-protocol:+default-env-allow+)))
                        names)
                 "nothing outside the allow list survives the scrub")
             (when (uiop:getenv "PATH")
               (ok (equal (uiop:getenv "PATH") (%env-value "PATH" launch)) "PATH kept")))
        (compute-protocol:release-confined-launch launch)))))

(deftest confine-command-backend-env-last
  (with-temp-tree (root "area/" "ro/")
    (let* ((backend (make-instance 'cleanup-backend))
           (launch (compute-protocol:confine-command
                    backend (%area-confinement root :env '(("CONFINED_BY" . "me"))) '("true")
                    :env '(("CONFINED_BY" . "extra")))))
      (unwind-protect
           (destructuring-bind (c argv directory tmp) (cleanup-backend-seen backend)
             (ok (equal "cleanup-backend" (%env-value "CONFINED_BY" launch)) "backend env is added last")
             (ok (equal '("true") argv) "the backend sees the original argv")
             (ok (equal (%ns (sub root "area/")) (%ns directory)))
             (ok (equal (%ns tmp) (%ns (compute-protocol:confined-launch-tmp launch))))
             (ok (eq c (compute-protocol:confined-launch-confinement launch)))
             (when (unix-p)
               (ok (equal '("/usr/bin/env" "true") (compute-protocol:confined-launch-argv launch))
                   "the launch argv is the backend's")))
        (compute-protocol:release-confined-launch launch)))))

(deftest-parametrize confine-command-tmp-modes
    ((mode)
     (:shared)
     (:none))
  (with-temp-tree (root "area/" "ro/")
    (let ((launch (compute-protocol:confine-command
                   (compute-protocol:make-model-confinement-backend)
                   (%area-confinement root :tmp mode :env-allow '("PATH"))
                   '("true"))))
      (unwind-protect
           (progn
             (ok (null (compute-protocol:confined-launch-tmp launch)) "no private directory")
             (ok (null (%env-value "TMPDIR" launch)) "TMPDIR not set (and scrubbed)"))
        (compute-protocol:release-confined-launch launch)))))

(deftest confine-command-directory
  (with-temp-tree (root "area/sub/" "ro/" "outside/")
    (let ((backend (compute-protocol:make-model-confinement-backend)))
      (let ((launch (compute-protocol:confine-command backend (%area-confinement root) '("true")
                                                      :directory (sub root "area/sub/"))))
        (unwind-protect
             (ok (equal (%ns (sub root "area/sub/")) (%ns (compute-protocol:confined-launch-directory launch))))
          (compute-protocol:release-confined-launch launch)))
      (let ((launch (compute-protocol:confine-command backend (%area-confinement root :read :system) '("true")
                                                      :directory (sub root "ro/"))))
        (unwind-protect
             (ok (equal (%ns (sub root "ro/")) (%ns (compute-protocol:confined-launch-directory launch)))
                 "a readable directory is a valid start directory")
          (compute-protocol:release-confined-launch launch)))
      (let ((e (handler-case
                   (progn (compute-protocol:confine-command backend (%area-confinement root :read :system)
                                                            '("true") :directory (sub root "outside/"))
                          nil)
                 (compute-protocol:invalid-confinement (e) e))))
        (ok e "an unreadable start directory is refused")
        (ok (and e (eq :directory (compute-protocol:invalid-confinement-field e))))))))

(deftest confine-command-no-writable
  (with-temp-tree (root "ro/")
    (let ((launch (compute-protocol:confine-command
                   (compute-protocol:make-model-confinement-backend)
                   (compute-protocol:make-confinement :readable (list (sub root "ro/")))
                   '("true"))))
      (unwind-protect
           (ok (equal (%ns (compute-protocol:confined-launch-tmp launch))
                      (%ns (compute-protocol:confined-launch-directory launch)))
               "no writable: start in the private temp directory")
        (compute-protocol:release-confined-launch launch)))))

(deftest confine-command-refuses-first
  (with-temp-tree (root "area/" "ro/")
    (let* ((backend (make-instance 'cleanup-backend :features '(:filesystem :network-none)))
           (e (handler-case
                  (progn (compute-protocol:confine-command backend (%area-confinement root :cpu-limit 1)
                                                           '("true"))
                         nil)
                (compute-protocol:confinement-unsupported (e) e))))
      (ok e "confinement-unsupported")
      (ok (null (cleanup-backend-seen backend)) "the backend was never asked to build a launch"))
    (let ((e (handler-case
                 (progn (compute-protocol:confine-command (compute-protocol:make-native-process-backend)
                                                          (%area-confinement root) '("true"))
                        nil)
               (compute-protocol:confinement-unavailable (e) e))))
      (ok e "native cannot confine"))))

(deftest release-confined-launch-once
  (with-temp-tree (root "area/" "ro/")
    (let* ((backend (make-instance 'cleanup-backend))
           (launch (compute-protocol:confine-command backend (%area-confinement root) '("true")))
           (tmp (compute-protocol:confined-launch-tmp launch)))
      (write-text (merge-pathnames "nested/file" tmp) "x")
      (ok (eq t (compute-protocol:release-confined-launch launch)))
      (ok (compute-protocol:confined-launch-released-p launch))
      (ng (uiop:directory-exists-p tmp) "the private tree is gone")
      (ok (equal '(:second :first) (cleanup-backend-calls backend)) "cleanups ran, in order")
      (ok (null (compute-protocol:release-confined-launch launch)) "second release → NIL")
      (ok (equal '(:second :first) (cleanup-backend-calls backend)) "and runs nothing"))))

(deftest release-confined-launch-failing-cleanup
  (with-temp-tree (root "area/" "ro/")
    (let* ((backend (make-instance 'cleanup-backend :fail-first t))
           (launch (compute-protocol:confine-command backend (%area-confinement root) '("true")))
           (tmp (compute-protocol:confined-launch-tmp launch)))
      (ok (eq t (compute-protocol:release-confined-launch launch)))
      (ok (equal '(:second :first) (cleanup-backend-calls backend)) "a failing cleanup does not stop the next")
      (ng (uiop:directory-exists-p tmp)))))

(deftest with-confined-launch-releases
  (with-temp-tree (root "area/" "ro/")
    (let* ((seen nil)
           (backend (compute-protocol:make-model-confinement-backend)))
      (catch 'out
        (compute-protocol:with-confined-launch (l backend (%area-confinement root) '("true"))
          (setf seen l)
          (throw 'out nil)))
      (ok (and seen (compute-protocol:confined-launch-released-p seen)) "released on a non-local exit")
      (ok (and seen (not (uiop:directory-exists-p (compute-protocol:confined-launch-tmp seen))))))))

;;; run-confined (Unix: /bin/sh)

(deftest run-confined-runs
  (if (not (unix-p))
      (skip "/bin/sh")
      (with-temp-tree (root "area/" "ro/")
        (let ((r (compute-protocol:run-confined
                  (compute-protocol:make-model-confinement-backend)
                  (%area-confinement root :env '(("KEEP" . "kept")))
                  (sh "printf '%s|%s|' \"$STACK_COMPUTE_CONFINEMENT\" \"$KEEP\"; pwd -P; echo err >&2; exit 3"))))
          (ok (compute-protocol:sandbox-result-p r))
          (ok (eql 3 (compute-protocol:sandbox-result-exit-code r)))
          (ok (equal (format nil "model|kept|~a~%" (string-right-trim "/" (%ns (sub root "area/"))))
                     (compute-protocol:sandbox-result-stdout r))
              "env and start directory reached the child")
          (ok (equal (format nil "err~%") (compute-protocol:sandbox-result-stderr r)))))))

(defun %can-setenv-p ()
  (ignore-errors
   (setf (uiop:getenv "CP_R4D_PROBE") "1")
   (equal "1" (uiop:getenv "CP_R4D_PROBE"))))

(deftest run-confined-scrubs-image-env
  (if (not (and (unix-p) (%can-setenv-p)))
      (skip "/bin/sh and (setf uiop:getenv)")
      (with-temp-tree (root "area/" "ro/")
        (let ((old (uiop:getenv "CP_R4D_SECRET")))
          (setf (uiop:getenv "CP_R4D_SECRET") "leak")
          (unwind-protect
               (let ((r (compute-protocol:run-confined
                         (compute-protocol:make-model-confinement-backend)
                         (%area-confinement root)
                         (sh "printf '%s' \"${CP_R4D_SECRET:-gone}\""))))
                 (ok (equal "gone" (compute-protocol:sandbox-result-stdout r))))
            (setf (uiop:getenv "CP_R4D_SECRET") (or old "")))))))

(deftest run-confined-input
  (if (not (unix-p))
      (skip "/bin/sh")
      (with-temp-tree (root "area/" "ro/")
        (let ((r (compute-protocol:run-confined
                  (compute-protocol:make-model-confinement-backend)
                  (%area-confinement root) (sh "cat") :input "abc")))
          (ok (equal "abc" (compute-protocol:sandbox-result-stdout r)))
          (ok (eql 0 (compute-protocol:sandbox-result-exit-code r)))))))

(deftest run-confined-wall-clock
  (if (not (unix-p))
      (skip "/bin/sh")
      (with-temp-tree (root "area/" "ro/")
        (let* ((backend (make-instance 'cleanup-backend))
               (start (get-internal-real-time))
               (signalled nil)
               (r (handler-bind ((compute-protocol:sandbox-timeout
                                   (lambda (c)
                                     (setf signalled (compute-protocol:sandbox-timeout-limit c))
                                     (invoke-restart 'compute-protocol:abort-execution))))
                    (compute-protocol:run-confined backend (%area-confinement root :wall-clock 1)
                                                   (sh "sleep 5")))))
          (ok (null r) "abort-execution → NIL")
          (ok (eql 1 signalled) "sandbox-timeout with the limit")
          (ok (< (/ (- (get-internal-real-time) start) internal-time-units-per-second) 4)
              "killed at the limit")
          (ok (member :first (cleanup-backend-calls backend)) "the launch was released")))))

(deftest run-confined-unavailable
  (with-temp-tree (root "area/" "ro/")
    (ok (signals (compute-protocol:run-confined (compute-protocol:make-native-process-backend)
                                                (%area-confinement root) '("true"))
                 'compute-protocol:confinement-unavailable))))

(deftest run-sandboxed-confining
  (with-temp-tree (root "area/" "ro/")
    (let ((backend (compute-protocol:make-model-confinement-backend))
          (c (%area-confinement root)))
      (when (unix-p)
        (let ((r (compute-protocol:run-sandboxed
                  backend (compute-protocol:make-sandbox-spec :command (sh "printf '%s' \"$X\"")
                                                              :env '(("X" . "y")) :confinement c))))
          (ok (equal "y" (compute-protocol:sandbox-result-stdout r)) "spec :env reaches the child")))
      (let ((e (handler-case (progn (compute-protocol:run-sandboxed
                                     backend (compute-protocol:make-sandbox-spec :command '("true")))
                                    nil)
                 (compute-protocol:invalid-confinement (e) e))))
        (ok e "a confining backend needs a confinement")
        (ok (and e (eq :confinement (compute-protocol:invalid-confinement-field e)))))
      (ok (signals (compute-protocol:run-sandboxed
                    backend (compute-protocol:make-sandbox-spec :code "(+ 1 2)" :confinement c))
                   'compute-protocol:sandbox-denied)
          ":code is refused"))))
