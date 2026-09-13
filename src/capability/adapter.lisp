(in-package #:compute-protocol)

(defclass compute-adapter (capability-protocol:compute-capability)
  ((backend :initarg :backend :accessor compute-adapter-backend :initform nil))
  (:documentation "Implements :compute RUN-COMMAND via RUN-SANDBOXED."))

(defun make-compute-adapter (&key backend)
  (make-instance 'compute-adapter :backend backend))

(defun %adapter-backend (cap)
  (or (compute-adapter-backend cap)
      *compute-backend*
      (error 'compute-error
             :message "compute adapter has no backend — pass :backend or bind *compute-backend*")))

(defun %argv-list (argv)
  (%string-list (if (listp argv) argv (list argv))))

(defmethod capability-protocol:run-command ((cap compute-adapter) argv &key spec)
  (run-sandboxed
   (%adapter-backend cap)
   (if spec
       (let ((s (coerce-sandbox-spec spec)))
         (if (sandbox-spec-command s)
             s
             (make-sandbox-spec
              :command (%argv-list argv)
              :code (sandbox-spec-code s)
              :runtime (sandbox-spec-runtime s)
              :mounts (sandbox-spec-mounts s)
              :env (sandbox-spec-env s)
              :network (sandbox-spec-network s)
              :cpu-limit (sandbox-spec-cpu-limit s)
              :memory-limit (sandbox-spec-memory-limit s)
              :wall-clock (sandbox-spec-wall-clock s)
              :allow-lisp (sandbox-spec-allow-lisp-p s)
              :artifacts (sandbox-spec-artifacts s))))
       (make-sandbox-spec :command (%argv-list argv)))))
