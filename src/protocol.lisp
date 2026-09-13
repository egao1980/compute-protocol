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
   (artifacts :initarg :artifacts :reader sandbox-spec-artifacts :initform nil))
  (:documentation
   "Command (list of strings) or CODE (string) plus RUNTIME
(:native, :sbcl, or an image string). NETWORK is :none (default) or :allow.
WALL-CLOCK is seconds; MEMORY-LIMIT is bytes."))

(defun sandbox-spec-p (object)
  (typep object 'sandbox-spec))

(defun make-sandbox-spec (&key command code (runtime :native) mounts env
                            (network :none) cpu-limit memory-limit wall-clock
                            allow-lisp artifacts)
  (when command
    (check-type command list))
  (when code
    (check-type code string))
  (unless (member network '(:none :allow))
    (error 'compute-error
           :message (format nil "network must be :none or :allow, got ~s" network)))
  (make-instance 'sandbox-spec
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
                 :artifacts artifacts))

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
