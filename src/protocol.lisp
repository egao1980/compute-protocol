(in-package #:compute-protocol)

;;; Sandboxed compute — CLOS protocol only.
;;; Isolation is a backend property. native-process-backend is trusted-only.

(defclass compute-backend () ())

(defvar *compute-backend* nil)

(defclass sandbox-spec ()
  ((command :initarg :command :reader sandbox-spec-command :initform nil)
   (code :initarg :code :reader sandbox-spec-code :initform nil)
   (runtime :initarg :runtime :reader sandbox-spec-runtime :initform :native)
   (mounts :initarg :mounts :reader sandbox-spec-mounts :initform nil)
   (env :initarg :env :reader sandbox-spec-env :initform nil)
   (network :initarg :network :reader sandbox-spec-network :initform :none)
   (cpu-limit :initarg :cpu-limit :reader sandbox-spec-cpu-limit :initform nil)
   (memory-limit :initarg :memory-limit :reader sandbox-spec-memory-limit :initform nil)
   (wall-clock :initarg :wall-clock :reader sandbox-spec-wall-clock :initform nil)
   (allow-lisp :initarg :allow-lisp :reader sandbox-spec-allow-lisp-p :initform nil)
   (artifacts :initarg :artifacts :reader sandbox-spec-artifacts :initform nil)
   (confinement :initarg :confinement :reader sandbox-spec-confinement :initform nil)
   (directory :initarg :directory :reader sandbox-spec-directory :initform nil)
   (input :initarg :input :reader sandbox-spec-input :initform nil))
  (:documentation
   "Command (list of strings) or CODE (string) plus RUNTIME
(:native, :sbcl, or an image string). NETWORK is :none (default), :allow,
or a SANDBOX-NETWORK-POLICY. Isolation is a backend property.
WALL-CLOCK is seconds; MEMORY-LIMIT is bytes. CONFINEMENT (0.3.0) is a
CONFINEMENT for a CONFINING-BACKEND, or NIL.
MOUNTS (0.4.0) is a list of mount designators, see PARSE-MOUNT: the mode is
:RO unless the designator says :RW.
DIRECTORY (0.4.0) is the command's working directory: a host path for the
native backend, a path inside the container for container backends. NIL keeps
the backend's default.
INPUT (0.4.0) is a string (UTF-8) or an octet vector written to the
command's standard input, which is then closed. NIL: no standard input."))

(defclass egress-rule ()
  ((host :initarg :host :reader egress-rule-host)
   (port :initarg :port :reader egress-rule-port))
  (:documentation
   "Allowed destination: HOST (string) and PORT (integer).
Host \"*\" is a wildcard for backends that match rules."))

(defun egress-rule-p (object)
  (typep object 'egress-rule))

(defun make-egress-rule (&key host port)
  (check-type host string)
  (check-type port integer)
  (make-instance 'egress-rule :host host :port port))

(defclass sandbox-network-policy ()
  ((egress :initarg :egress :reader sandbox-network-policy-egress :initform nil)
   (dns :initarg :dns :reader sandbox-network-policy-dns :initform nil))
  (:documentation
   "Declarative egress list plus optional DNS. Backends interpret this;
native-process-backend does not filter packets (trusted-only)."))

(defun sandbox-network-policy-p (object)
  (typep object 'sandbox-network-policy))

(defun make-sandbox-network-policy (&key egress dns)
  (when egress
    (check-type egress list)
    (dolist (rule egress)
      (unless (egress-rule-p rule)
        (error 'compute-error
               :message (format nil "egress entries must be egress-rule, got ~s" rule)))))
  (make-instance 'sandbox-network-policy :egress egress :dns dns))

(defun sandbox-spec-p (object)
  (typep object 'sandbox-spec))

(defun %valid-sandbox-network-p (network)
  (or (member network '(:none :allow))
      (sandbox-network-policy-p network)))

(defparameter +mount-modes+ '(:ro :rw)
  "Mount modes a mount designator may name. :RO is the default.")

(defun %mount-path-p (x)
  (or (stringp x) (pathnamep x) (and x (symbolp x) (not (keywordp x)))))

(defun parse-mount (mount)
  "Split the mount designator MOUNT → (values SOURCE DESTINATION MODE).
Designators: PATH (same path on both sides), (SOURCE DESTINATION),
\(SOURCE . DESTINATION) or (SOURCE DESTINATION MODE) with MODE one of
+MOUNT-MODES+. SOURCE is a host path; DESTINATION is a path in the sandbox
\(the same host path for the native backend). MODE defaults to :RO. Anything
else signals COMPUTE-ERROR."
  (flet ((bad (why)
           (error 'compute-error
                  :message (format nil "invalid mount designator ~s: ~a" mount why))))
    (cond
      ((%mount-path-p mount)
       (values mount mount :ro))
      ((and (consp mount) (%mount-path-p (car mount)) (%mount-path-p (cdr mount)))
       (values (car mount) (cdr mount) :ro))
      ((and (consp mount) (consp (cdr mount))
            (%mount-path-p (first mount)) (%mount-path-p (second mount)))
       (let ((rest (cddr mount)))
         (cond
           ((null rest) (values (first mount) (second mount) :ro))
           ((and (null (cdr rest)) (member (car rest) +mount-modes+))
            (values (first mount) (second mount) (car rest)))
           (t (bad (format nil "mode must be one of ~s" +mount-modes+))))))
      (t (bad "expected PATH, (SOURCE DESTINATION [MODE]) or (SOURCE . DESTINATION)")))))

(defun mount-mode (mount)
  "The mode (:RO or :RW) of the mount designator MOUNT."
  (nth-value 2 (parse-mount mount)))

(defun %octets-p (x)
  (and (vectorp x)
       (not (stringp x))
       (every (lambda (b) (typep b '(unsigned-byte 8))) x)))

(defun make-sandbox-spec (&key command code (runtime :native) mounts env
                            (network :none) cpu-limit memory-limit wall-clock
                            allow-lisp artifacts confinement directory input)
  (when command
    (check-type command list))
  (when code
    (check-type code string))
  (unless (%valid-sandbox-network-p network)
    (error 'compute-error
           :message (format nil "network must be :none, :allow, or sandbox-network-policy, got ~s"
                            network)))
  (check-type mounts list)
  (mapc #'parse-mount mounts)
  (unless (or (null directory) (stringp directory) (pathnamep directory))
    (error 'compute-error
           :message (format nil "directory must be a string or pathname, got ~s" directory)))
  (unless (or (null input) (stringp input) (%octets-p input))
    (error 'compute-error
           :message (format nil "input must be a string or an octet vector, got ~s"
                            (type-of input))))
  (make-instance 'sandbox-spec
                 :directory directory
                 :input input
                 :command command
                 :code code
                 :runtime runtime
                 :mounts mounts
                 :env env
                 :network network
                 :cpu-limit cpu-limit
                 :memory-limit memory-limit
                 :wall-clock wall-clock
                 :allow-lisp allow-lisp
                 :artifacts artifacts
                 :confinement confinement))

(defun %command-strings (items)
  (loop for x in items
        collect (if (stringp x) x (princ-to-string x))))

(defun coerce-sandbox-spec (spec)
  "Accept a SANDBOX-SPEC, keyword plist, or command list."
  (etypecase spec
    (sandbox-spec spec)
    (null (make-sandbox-spec))
    (cons
     (if (keywordp (car spec))
         (apply #'make-sandbox-spec spec)
         (make-sandbox-spec :command (%command-strings spec))))))

(defclass sandbox-result ()
  ((exit-code :initarg :exit-code :reader sandbox-result-exit-code)
   (stdout :initarg :stdout :reader sandbox-result-stdout :initform "")
   (stderr :initarg :stderr :reader sandbox-result-stderr :initform "")
   (artifacts :initarg :artifacts :reader sandbox-result-artifacts :initform nil)))

(defun sandbox-result-p (object)
  (typep object 'sandbox-result))

(defun make-sandbox-result (&key exit-code (stdout "") (stderr "") artifacts)
  (make-instance 'sandbox-result
                 :exit-code exit-code
                 :stdout (or stdout "")
                 :stderr (or stderr "")
                 :artifacts artifacts))

(defclass sandbox-session ()
  ((backend :initarg :backend :reader sandbox-session-backend)
   (spec :initarg :spec :reader sandbox-session-spec))
  (:documentation
   "Warm-session handle. Holds BACKEND+SPEC. Native sessions do not start a container."))

(defun sandbox-session-p (object)
  (typep object 'sandbox-session))

(defun make-sandbox-session (&key backend spec)
  (make-instance 'sandbox-session
                 :backend backend
                 :spec (coerce-sandbox-spec spec)))

(defgeneric run-sandboxed (backend spec)
  (:documentation
   "Run SPEC on BACKEND → SANDBOX-RESULT.
BACKEND may be a SANDBOX-SESSION (reuses the session backend/spec).
SPEC may be a SANDBOX-SPEC, keyword plist, command list, or NIL on a session."))

(defgeneric open-sandbox (backend spec)
  (:documentation "Open a reusable SANDBOX-SESSION for BACKEND+SPEC."))

(defgeneric close-sandbox (session)
  (:documentation "Release SESSION resources. Native is a no-op."))

(defmethod open-sandbox (backend spec)
  (make-sandbox-session :backend backend :spec spec))

(defmethod close-sandbox (session)
  (declare (ignore session))
  nil)

(defmethod run-sandboxed ((session sandbox-session) spec)
  (run-sandboxed (sandbox-session-backend session)
                 (if spec
                     (coerce-sandbox-spec spec)
                     (sandbox-session-spec session))))

(defmacro with-sandbox ((session backend spec) &body body)
  "Bind SESSION to a warm sandbox for BACKEND+SPEC. Native sessions hold spec only."
  (let ((backend-var (gensym "BACKEND"))
        (spec-var (gensym "SPEC")))
    `(let* ((,backend-var ,backend)
            (,spec-var (coerce-sandbox-spec ,spec))
            (,session (open-sandbox ,backend-var ,spec-var)))
       (unwind-protect
            (progn ,@body)
         (close-sandbox ,session)))))

;;; 0.4.0: file copy between the host and a session (optional; a backend
;;; without it signals SANDBOX-UNSUPPORTED).

(defgeneric sandbox-copy-to (session host-path sandbox-path)
  (:documentation "Copy HOST-PATH (a file or directory on the host) to SANDBOX-PATH inside
SESSION's sandbox. → SANDBOX-PATH. The default method signals
SANDBOX-UNSUPPORTED (operation :COPY-TO)."))

(defgeneric sandbox-copy-from (session sandbox-path host-path)
  (:documentation "Copy SANDBOX-PATH inside SESSION's sandbox to HOST-PATH on the host.
→ HOST-PATH. The default method signals SANDBOX-UNSUPPORTED (operation
:COPY-FROM)."))

(defun %unsupported (session operation)
  (error 'sandbox-unsupported
         :backend (if (sandbox-session-p session)
                      (sandbox-session-backend session)
                      session)
         :operation operation
         :message (format nil "no ~(~a~) method for ~s" operation
                          (class-name (class-of session)))))

(defmethod sandbox-copy-to (session host-path sandbox-path)
  (declare (ignore host-path sandbox-path))
  (%unsupported session :copy-to))

(defmethod sandbox-copy-from (session sandbox-path host-path)
  (declare (ignore sandbox-path host-path))
  (%unsupported session :copy-from))
