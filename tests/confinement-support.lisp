(in-package #:compute-protocol/tests)

;;; R4d-0 test support: temp trees and two test backends.
;;;
;;; TRUSTING-BACKEND claims every feature and runs the argv unchanged: it is
;;; an unconfined backend lying about itself. The suite must catch it (every
;;; deny case fails, every allow case passes) — that is how the suite and the
;;; probe program are tested without a kernel mechanism.
;;; CLEANUP-BACKEND is a model backend whose BACKEND-CONFINE-ARGV prefixes the
;;; argv and registers cleanups, so launches can be checked end to end.

(defclass trusting-backend (compute-protocol:confining-backend) ())

(defmethod compute-protocol:confinement-features ((b trusting-backend))
  (copy-list compute-protocol:+confinement-features+))

(defmethod compute-protocol:confinement-available-p ((b trusting-backend))
  (values t nil))

(defmethod compute-protocol:backend-confine-argv ((b trusting-backend) confinement argv directory tmp)
  (declare (ignore confinement directory tmp))
  (values (copy-list argv) nil nil))

(defclass cleanup-backend (compute-protocol:model-confinement-backend)
  ((calls :initform '() :accessor cleanup-backend-calls)
   (seen :initform nil :accessor cleanup-backend-seen
         :documentation "(confinement argv directory tmp) of the last BACKEND-CONFINE-ARGV.")
   (fail-first :initarg :fail-first :initform nil :reader cleanup-backend-fail-first)))

(defmethod compute-protocol:backend-confine-argv ((b cleanup-backend) confinement argv directory tmp)
  (setf (cleanup-backend-seen b) (list confinement argv directory tmp))
  (values (if (uiop:os-unix-p) (list* "/usr/bin/env" argv) (copy-list argv))
          (list (cons "CONFINED_BY" "cleanup-backend"))
          (list (lambda ()
                  (push :first (cleanup-backend-calls b))
                  (when (cleanup-backend-fail-first b) (error "first cleanup fails")))
                (lambda () (push :second (cleanup-backend-calls b))))))

(defclass absent-backend (compute-protocol:confining-backend) ())

(defmethod compute-protocol:confinement-available-p ((b absent-backend))
  (values nil "absent on purpose"))

(defun unix-p () (uiop:os-unix-p))

(defun physical-dir (p)
  (uiop:ensure-directory-pathname (truename p)))

(defun make-temp-tree (&rest subdirs)
  "A new physical temp directory with SUBDIRS (strings) created in it. → the root."
  (let ((root (physical-dir
               (ensure-directories-exist
                (uiop:ensure-directory-pathname
                 (merge-pathnames (format nil "cp-r4d-test-~36r-~36r/" (get-universal-time) (random (expt 36 6)))
                                  (uiop:temporary-directory)))))))
    (dolist (d subdirs)
      (ensure-directories-exist (merge-pathnames (uiop:ensure-directory-pathname d) root)))
    root))

(defmacro with-temp-tree ((var &rest subdirs) &body body)
  `(let ((,var (make-temp-tree ,@subdirs)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

(defun sub (root rel)
  (merge-pathnames (uiop:parse-unix-namestring rel) root))

(defun write-text (path text)
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :if-exists :supersede)
    (write-string text s))
  path)

(defun real-failure-p (c)
  "An ERROR that is not the contract's stub."
  (not (search "R4d-0 pending" (princ-to-string c))))

(defun sh (script)
  (list "/bin/sh" "-c" script))
