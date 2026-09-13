(in-package #:compute-protocol)

(define-condition compute-error (error)
  ((message :initarg :message :reader compute-error-message :initform nil)
   (spec :initarg :spec :reader compute-error-spec :initform nil))
  (:report (lambda (c s)
             (format s "compute error~@[: ~a~]" (compute-error-message c)))))

(define-condition sandbox-timeout (compute-error)
  ((limit :initarg :limit :reader sandbox-timeout-limit :initform nil))
  (:report (lambda (c s)
             (format s "sandbox wall-clock limit~@[ ~a s~] exceeded~@[: ~a~]"
                     (sandbox-timeout-limit c)
                     (compute-error-message c)))))

(define-condition sandbox-oom (compute-error)
  ((limit :initarg :limit :reader sandbox-oom-limit :initform nil))
  (:report (lambda (c s)
             (format s "sandbox memory limit~@[ ~a bytes~] exceeded~@[: ~a~]"
                     (sandbox-oom-limit c)
                     (compute-error-message c)))))

(define-condition sandbox-denied (compute-error)
  ((policy :initarg :policy :reader sandbox-denied-policy :initform nil))
  (:report (lambda (c s)
             (format s "sandbox denied~@[ (~a)~]~@[: ~a~]"
                     (sandbox-denied-policy c)
                     (compute-error-message c)))))
