;;;; The confinement suite's probe (run as: sbcl --core … --script probe-program.lisp).
;;;; Reads one list of ops (compute-protocol/confinement-suite +PROBE-OPERATIONS+)
;;;; from stdin with *READ-EVAL* NIL and prints one list of results to stdout.
;;;; Only SBCL contribs (sb-posix, sb-bsd-sockets); no ASDF, no init files.
;;;;
;;;; --script reads and evaluates one form at a time, so the contribs are required
;;;; by separate forms before any form names their symbols. The confined
;;;; environment has no SBCL_HOME: when REQUIRE cannot find a contrib, it is loaded
;;;; from contrib/ next to the core.

(defun probe-require (module)
  (handler-case (require module)
    (error (e)
      (let ((fasl (merge-pathnames
                   (make-pathname :directory '(:relative "contrib")
                                  :name (string-downcase (string module)) :type "fasl")
                   (make-pathname :name nil :type nil :version nil
                                  :defaults sb-ext:*core-pathname*))))
        (if (probe-file fasl)
            (load fasl)
            (error e))))))

(probe-require :sb-posix)

(probe-require :sb-bsd-sockets)

(defparameter *probe-denied-errnos*
  (list sb-posix:eacces sb-posix:eperm sb-posix:erofs sb-posix:exdev)
  "errno values that mean the confinement refused the operation.")

(defmacro probe-with-errno-mapping (&body body)
  "BODY's effect → :OK, :DENIED for a refusal errno, else (:ERROR \"…\")."
  `(handler-case (progn ,@body :ok)
     (sb-posix:syscall-error (e)
       (if (member (sb-posix:syscall-errno e) *probe-denied-errnos*)
           :denied
           (list :error (princ-to-string e))))
     (error (e) (list :error (princ-to-string e)))))

(defun probe-fd-stream (path flags direction)
  (sb-sys:make-fd-stream (sb-posix:open path flags #o644)
                         :input (eq direction :input) :output (eq direction :output)
                         :element-type 'character :external-format :utf-8 :auto-close t))

(defun probe-put-file (path text flag)
  (probe-with-errno-mapping
    (let ((s (probe-fd-stream path (logior sb-posix:o-wronly sb-posix:o-creat flag) :output)))
      (unwind-protect (write-string text s) (close s)))))

(defun probe-get-file (path)
  (probe-with-errno-mapping
    (let ((s (probe-fd-stream path sb-posix:o-rdonly :input)))
      (unwind-protect (loop while (read-line s nil)) (close s)))))

(defun probe-remove-entry (path)
  ;; rmdir for a directory: unlink(2) of a directory is EPERM on macOS, which
  ;; would read as a denial.
  (probe-with-errno-mapping
    (if (sb-posix:s-isdir (sb-posix:stat-mode (sb-posix:lstat path)))
        (sb-posix:rmdir path)
        (sb-posix:unlink path))))

(defun probe-connect-to (host port)
  (handler-case
      (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
        (unwind-protect
             (progn (sb-bsd-sockets:socket-connect s (sb-bsd-sockets:make-inet-address host) port)
                    :ok)
          (ignore-errors (sb-bsd-sockets:socket-close s))))
    (error () :denied)))

(defun probe-print-form (form stream)
  ;; sb-posix returns base strings: *PRINT-READABLY* NIL keeps them "…", not #A(…).
  (with-standard-io-syntax
    (let ((*print-readably* nil))
      (prin1 form stream)
      (terpri stream)
      (finish-output stream))))

(defun probe-read-form (stream)
  (with-standard-io-syntax
    (let ((*read-eval* nil))
      (read stream))))

(defun probe-run-child (ops)
  "OPS in a child process: this probe again, the environment inherited."
  (let ((process (sb-ext:run-program sb-ext:*runtime-pathname*
                                     (list "--core" (sb-ext:native-namestring sb-ext:*core-pathname*)
                                           "--script" (sb-ext:native-namestring *load-truename*))
                                     :input :stream :output :stream :error nil :wait nil)))
    (unwind-protect
         (progn
           (probe-print-form ops (sb-ext:process-input process))
           (close (sb-ext:process-input process))
           (cons :child (probe-read-form (sb-ext:process-output process))))
      (sb-ext:process-wait process)
      (sb-ext:process-close process))))

(defun probe-perform (op)
  (destructuring-bind (kind &rest args) op
    (ecase kind
      (:write (probe-put-file (first args) (second args) sb-posix:o-trunc))
      (:append (probe-put-file (first args) (second args) sb-posix:o-append))
      (:read (probe-get-file (first args)))
      (:mkdir (probe-with-errno-mapping (sb-posix:mkdir (first args) #o755)))
      (:delete (probe-remove-entry (first args)))
      (:rename (probe-with-errno-mapping (sb-posix:rename (first args) (second args))))
      (:symlink (probe-with-errno-mapping (sb-posix:symlink (first args) (second args))))
      (:hardlink (probe-with-errno-mapping (sb-posix:link (first args) (second args))))
      (:connect (probe-connect-to (first args) (second args)))
      (:getenv (list :value (sb-posix:getenv (first args))))
      (:cwd (list :value (sb-posix:getcwd)))
      (:child (probe-run-child args)))))

(probe-print-form (mapcar (lambda (op)
                      (handler-case (probe-perform op)
                        (error (e) (list :error (princ-to-string e)))))
                    (probe-read-form *standard-input*))
            *standard-output*)
