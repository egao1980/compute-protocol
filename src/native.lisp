(in-package #:compute-protocol)

;;; TRUSTED-ONLY. This backend does not isolate: no mount namespace, no
;;; network jail, no packet filter, no cgroup limits. Wall-clock is still
;;; enforced. A SANDBOX-NETWORK-POLICY is recorded on the spec only —
;;; native never filters host/port. Isolation is a backend property.

(defclass native-process-backend (compute-backend)
  ((trusted-only-p :initarg :trusted-only-p :reader native-trusted-only-p
                   :initform t)
   (deny-network-p :initarg :deny-network-p :reader native-deny-network-p
                   :initform nil)
   (deny-mounts-p :initarg :deny-mounts-p :reader native-deny-mounts-p
                  :initform nil))
  (:documentation
   "Trusted-only colocated backend. Does NOT isolate the child process.
TRUSTED-ONLY-P defaults to T. CPU/memory/network/mounts are not enforced
unless DENY-NETWORK-P / DENY-MOUNTS-P is set. :allow and a
SANDBOX-NETWORK-POLICY remain trusted-only: packets are not filtered.
DENY-NETWORK-P signals SANDBOX-DENIED for :allow and for a policy object.
Wall-clock is always honored."))

(defun make-native-process-backend (&key (trusted-only-p t)
                                      deny-network-p
                                      deny-mounts-p)
  (make-instance 'native-process-backend
                 :trusted-only-p trusted-only-p
                 :deny-network-p deny-network-p
                 :deny-mounts-p deny-mounts-p))

(defun use-native-process-backend (&rest args)
  (setf *compute-backend* (apply #'make-native-process-backend args)))

(defun %string-list (xs)
  (mapcar (lambda (x)
            (etypecase x
              (string x)
              (pathname (uiop:native-namestring x))
              (symbol (string x))
              (character (string x))
              (integer (princ-to-string x))))
          xs))

(defun %to-string (x)
  (cond
    ((stringp x) x)
    ((null x) "")
    ((and (vectorp x)
          (plusp (length x))
          (integerp (aref x 0)))
     (map 'string #'code-char x))
    ((and (vectorp x) (or (zerop (length x)) (characterp (aref x 0))))
     (coerce x 'string))
    (t (princ-to-string x))))

(defun %env-name (key)
  (etypecase key
    (string key)
    (symbol (symbol-name key))))

(defun %env-strings (alist)
  (when alist
    (mapcar (lambda (pair)
              (format nil "~a=~a" (%env-name (car pair)) (cdr pair)))
            alist)))

(defun %process-protocol-run ()
  "PROCESS-PROTOCOL:RUN when *PROCESS-BACKEND* is bound, else NIL."
  (let ((pkg (find-package '#:process-protocol)))
    (when pkg
      (let ((star (find-symbol "*PROCESS-BACKEND*" pkg))
            (run (find-symbol "RUN" pkg)))
        (when (and star run (boundp star) (symbol-value star) (fboundp run))
          run)))))

(defun %read-stream (stream)
  (if (and stream (open-stream-p stream))
      (uiop:slurp-stream-string stream)
      ""))

(defun %launch-and-wait (argv &key env timeout)
  "Run ARGV via UIOP. TIMEOUT seconds → first value :TIMEOUT."
  (let ((info (apply #'uiop:launch-program argv
                     (append (list :output :stream
                                   :error-output :stream)
                             (when env (list :environment env))))))
    (unwind-protect
         (let ((timed-out nil))
           (cond
             (timeout
              (let ((deadline (+ (get-internal-real-time)
                                 (max 1 (round (* timeout
                                                  internal-time-units-per-second))))))
                (loop while (uiop:process-alive-p info)
                      do (when (>= (get-internal-real-time) deadline)
                           (setf timed-out t)
                           (uiop:terminate-process info :urgent t)
                           (return))
                         (sleep 0.02))))
             (t
              (uiop:wait-process info)))
           (ignore-errors (uiop:wait-process info))
           (let ((code (or (ignore-errors (uiop:wait-process info)) -1))
                 (out (%read-stream (uiop:process-info-output info)))
                 (err (%read-stream (uiop:process-info-error-output info))))
             (values (if timed-out :timeout code) (or out "") (or err ""))))
      (when (ignore-errors (uiop:process-alive-p info))
        (ignore-errors (uiop:terminate-process info :urgent t))
        (ignore-errors (uiop:wait-process info))))))

(defun %run-uiop (argv &key env timeout)
  (let ((env-list (%env-strings env)))
    (if timeout
        ;; Poll + terminate so we can distinguish timeout from a real exit.
        ;; UIOP RUN-PROGRAM :TIMEOUT (when present) only yields an exit code.
        (%launch-and-wait argv :env env-list :timeout timeout)
        (multiple-value-bind (out err code)
            (apply #'uiop:run-program argv
                   (append (list :ignore-error-status t
                                 :output '(:string :stripped nil)
                                 :error-output '(:string :stripped nil))
                           (when env-list (list :environment env-list))))
          (values (or code 0) (or out "") (or err ""))))))

(defun %invoke-process (argv &key env timeout)
  "process-protocol:run when *process-backend* is bound and TIMEOUT is NIL,
else UIOP. Wall-clock is always enforced when TIMEOUT is set."
  (let ((run (and (null timeout) (%process-protocol-run))))
    (if run
        (multiple-value-bind (code out err)
            (apply run argv (append (when env (list :env (%env-strings env)))))
          (values code (%to-string out) (%to-string err)))
        (%run-uiop argv :env env :timeout timeout))))

(defun %check-native-policy (backend spec)
  (when (and (sandbox-spec-code spec)
             (not (sandbox-spec-allow-lisp-p spec)))
    (error 'sandbox-denied
           :spec spec
           :policy :lisp
           :message "native backend refuses :code unless :allow-lisp t"))
  (let ((network (sandbox-spec-network spec)))
    (when (and (native-deny-network-p backend)
               (or (eq network :allow)
                   (sandbox-network-policy-p network)))
      (error 'sandbox-denied
             :spec spec
             :policy :network
             :message "network is denied by native-process-backend")))
  (when (and (sandbox-spec-mounts spec)
             (native-deny-mounts-p backend))
    (error 'sandbox-denied
           :spec spec
           :policy :mount
           :message "mounts are denied by native-process-backend")))

(defun %lisp-argv (spec path)
  (let ((rt (sandbox-spec-runtime spec))
        (file (uiop:native-namestring path)))
    (cond
      ((eq rt :ros)
       (list "ros" "--" file))
      ((and (stringp rt)
            (or (string-equal rt "ros")
                (search "ros" rt :test #'char-equal)))
       (list rt "--" file))
      (t
       (list "sbcl" "--script" file)))))

(defun %spec-argv (spec)
  (cond
    ((sandbox-spec-command spec)
     (%string-list (sandbox-spec-command spec)))
    ((sandbox-spec-code spec)
     (error 'compute-error
            :spec spec
            :message "internal: code path must write a temp file first"))
    (t
     (error 'compute-error
            :spec spec
            :message "sandbox-spec needs :command or :code"))))

(defun %run-argv-with-limits (spec argv)
  (let ((limit (sandbox-spec-wall-clock spec))
        (env (sandbox-spec-env spec)))
    (tagbody
     retry
       (return-from %run-argv-with-limits
         (multiple-value-bind (code out err)
             (%invoke-process argv :env env :timeout limit)
           (if (eq code :timeout)
               (let ((extra
                      (restart-case
                          (error 'sandbox-timeout
                                 :spec spec
                                 :limit limit
                                 :message "wall-clock limit exceeded")
                        (compute-protocol:extend-limit (seconds)
                          :report "Extend the wall-clock limit and retry"
                          :interactive (lambda ()
                                         (format *query-io* "Additional seconds: ")
                                         (force-output *query-io*)
                                         (list (read *query-io*)))
                          seconds)
                        (compute-protocol:abort-execution ()
                          :report "Abort sandbox execution"
                          (return-from %run-argv-with-limits nil))
                        (abort ()
                          :report "Abort sandbox execution"
                          (return-from %run-argv-with-limits nil)))))
                 (setf limit (+ (or limit 0) extra))
                 (go retry))
               (make-sandbox-result
                :exit-code code
                :stdout out
                :stderr err
                :artifacts (sandbox-spec-artifacts spec))))))))

(defun %run-lisp-code (spec)
  (let ((code (sandbox-spec-code spec)))
    (uiop:with-temporary-file (:pathname path :stream stream :type "lisp" :keep t)
      (write-string code stream)
      (finish-output stream)
      (close stream)
      (unwind-protect
           (%run-argv-with-limits spec (%lisp-argv spec path))
        (ignore-errors (delete-file path))))))

(defmethod run-sandboxed ((backend native-process-backend) spec)
  (let ((spec (coerce-sandbox-spec spec)))
    (%check-native-policy backend spec)
    (cond
      ((sandbox-spec-command spec)
       (%run-argv-with-limits spec (%spec-argv spec)))
      ((sandbox-spec-code spec)
       (%run-lisp-code spec))
      (t
       (error 'compute-error
              :spec spec
              :message "sandbox-spec needs :command or :code")))))
