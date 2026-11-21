(in-package #:compute-protocol/confinement-suite)

(defgeneric confinement-probe (backend confinement ops &key directory)
  (:documentation "Run OPS (see +PROBE-OPERATIONS+) confined by CONFINEMENT on BACKEND
→ one result per op, in order. Default method: CONFINE-COMMAND (DIRECTORY passed on)
of PROBE-COMMAND, ops printed to the probe's stdin, results READ from its stdout
\(*READ-EVAL* NIL), the launch released. Method on MODEL-CONFINEMENT-BACKEND: in this
image, each op decided with CONFINEMENT-DECIDE (the launch's tmp passed as :TMP);
allowed ops are performed for real, :CHILD ops are decided the same way (children
inherit), environment ops read the launch's environment."))

;;; The subprocess probe

(defparameter *probe-timeout* 60
  "Seconds one probe run may take before it counts as a broken backend.")

(defun %print-form (form)
  "FORM printed readably for the probe (strings may be base strings: no #A syntax)."
  (with-standard-io-syntax
    (let ((*print-readably* nil))
      (prin1-to-string form))))

(defun %read-results (text)
  (with-standard-io-syntax
    (let ((*read-eval* nil))
      (read-from-string text))))

(defmethod confinement-probe (backend confinement ops &key directory)
  (sc:with-confined-launch (launch backend confinement (probe-command) :directory directory)
    (multiple-value-bind (code out err)
        (pp:run (sc:confined-launch-argv launch)
                :env (sc:confined-launch-env launch)
                :env-mode :replace
                :directory (sc:confined-launch-directory launch)
                :process-group t
                :input (%print-form ops)
                :output :string
                :error-output :string
                :timeout *probe-timeout*)
      (let ((results (and (eql code 0) (ignore-errors (%read-results out)))))
        (unless (and (listp results) (= (length results) (length ops)))
          (error "confinement probe failed (exit ~a): ~a~@[ — stdout ~s~]"
                 code (string-trim '(#\Space #\Newline) err)
                 (and (eql code 0) out)))
        results))))

;;; The model's in-process probe: every op is decided with CONFINEMENT-DECIDE on the
;;; launch's resolved confinement; allowed ops are performed here with sb-posix (the
;;; same calls and errno mapping as probe-program.lisp). The image does not chdir:
;;; relative paths are taken relative to the launch's start directory.
;;; Content ops (:write :append :read, a hardlink's target) are decided on the path
;;; with every symlink followed; entry ops (:mkdir :delete, both sides of :rename, the
;;; link of :symlink and :hardlink) on the entry itself (physical parent + name).

(defparameter *denied-errnos*
  (list sb-posix:eacces sb-posix:eperm sb-posix:erofs sb-posix:exdev))

(defmacro %with-errno-mapping (&body body)
  `(handler-case (progn ,@body :ok)
     (sb-posix:syscall-error (e)
       (if (member (sb-posix:syscall-errno e) *denied-errnos*)
           :denied
           (list :error (princ-to-string e))))
     (error (e) (list :error (princ-to-string e)))))

(defun %fd-stream (path flags direction)
  (sb-sys:make-fd-stream (sb-posix:open path flags #o644)
                         :input (eq direction :input) :output (eq direction :output)
                         :element-type 'character :external-format :utf-8 :auto-close t))

(defun %posix-put (path text flag)
  (%with-errno-mapping
    (let ((s (%fd-stream path (logior sb-posix:o-wronly sb-posix:o-creat flag) :output)))
      (unwind-protect (write-string text s) (close s)))))

(defun %posix-get (path)
  (%with-errno-mapping
    (let ((s (%fd-stream path sb-posix:o-rdonly :input)))
      (unwind-protect (loop while (read-line s nil)) (close s)))))

(defun %posix-remove (path)
  (%with-errno-mapping
    (if (sb-posix:s-isdir (sb-posix:stat-mode (sb-posix:lstat path)))
        (sb-posix:rmdir path)
        (sb-posix:unlink path))))

(defun %connect (host port)
  (handler-case
      (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
        (unwind-protect
             (progn (sb-bsd-sockets:socket-connect s (sb-bsd-sockets:make-inet-address host) port)
                    :ok)
          (ignore-errors (sb-bsd-sockets:socket-close s))))
    (error () :denied)))

(defun %launch-dir-ns (launch)
  (%ns (uiop:ensure-directory-pathname (sc:confined-launch-directory launch))))

(defun %absolute (launch path)
  "PATH (a native namestring) made absolute against the launch's start directory."
  (if (and (plusp (length path)) (char= #\/ (char path 0)))
      path
      (concatenate 'string (%launch-dir-ns launch) path)))

(defun %entry (path)
  "The directory entry PATH names: its parent physical, its last name as written."
  (let* ((trimmed (string-right-trim "/" path))
         (i (position #\/ trimmed :from-end t))
         (name (subseq trimmed (1+ i))))
    (if (member name '("" "." "..") :test #'string=)
        path                            ; not an entry name: decide on the path itself
        (concatenate 'string
                     (%ns (uiop:ensure-directory-pathname
                           (sc:physical-path (subseq trimmed 0 (1+ i)))))
                     name))))

(defun %op-checks (launch op)
  "→ the (operation target) decisions OP needs, all of which must allow."
  (flet ((abs* (p) (%absolute launch p)))
    (destructuring-bind (kind &rest args) op
      (ecase kind
        ((:write :append) `((:write ,(abs* (first args)))))
        (:read `((:read ,(abs* (first args)))))
        ((:mkdir :delete) `((:write ,(%entry (abs* (first args))))))
        (:rename `((:write ,(%entry (abs* (first args))))
                   (:write ,(%entry (abs* (second args))))))
        (:symlink `((:write ,(%entry (abs* (second args))))))
        (:hardlink `((:write ,(abs* (first args)))
                     (:write ,(%entry (abs* (second args))))))
        (:connect `((:connect ,(cons (first args) (second args)))))))))

(defun %allowed-p (launch op)
  (every (lambda (check)
           (eq :allow (sc:confinement-decide (sc:confined-launch-confinement launch)
                                             (first check) (second check)
                                             :tmp (sc:confined-launch-tmp launch))))
         (%op-checks launch op)))

(defun %perform (launch op)
  "Perform an allowed OP for real (absolute paths) → its result."
  (flet ((abs* (p) (%absolute launch p)))
    (destructuring-bind (kind &rest args) op
      (ecase kind
        (:write (%posix-put (abs* (first args)) (second args) sb-posix:o-trunc))
        (:append (%posix-put (abs* (first args)) (second args) sb-posix:o-append))
        (:read (%posix-get (abs* (first args))))
        (:mkdir (%with-errno-mapping (sb-posix:mkdir (abs* (first args)) #o755)))
        (:delete (%posix-remove (abs* (first args))))
        (:rename (%with-errno-mapping (sb-posix:rename (abs* (first args)) (abs* (second args)))))
        ;; A symlink's target is stored as written, resolved against the link's directory.
        (:symlink (%with-errno-mapping (sb-posix:symlink (first args) (abs* (second args)))))
        (:hardlink (%with-errno-mapping (sb-posix:link (abs* (first args)) (abs* (second args)))))
        (:connect (%connect (first args) (second args)))))))

(defun %model-op (launch op)
  (handler-case
      (destructuring-bind (kind &rest args) op
        (case kind
          (:getenv (list :value (cdr (assoc (first args) (sc:confined-launch-env launch)
                                            :test #'string=))))
          (:cwd (list :value (string-right-trim "/" (%launch-dir-ns launch))))
          (:child (cons :child (mapcar (lambda (o) (%model-op launch o)) args)))
          (t (if (%allowed-p launch op)
                 (%perform launch op)
                 :denied))))
    (error (e) (list :error (princ-to-string e)))))

(defmethod confinement-probe ((backend sc:model-confinement-backend) confinement ops &key directory)
  (sc:with-confined-launch (launch backend confinement (probe-command) :directory directory)
    (mapcar (lambda (op) (%model-op launch op)) ops)))
