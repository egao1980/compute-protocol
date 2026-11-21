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

;;; R4d-0: confinement conditions.

(define-condition invalid-confinement (compute-error)
  ((field :initarg :field :reader invalid-confinement-field :initform nil)
   (value :initarg :value :reader invalid-confinement-value :initform nil))
  (:report (lambda (c s)
             (format s "invalid confinement~@[ ~(~a~)~]: ~s~@[ — ~a~]"
                     (invalid-confinement-field c)
                     (invalid-confinement-value c)
                     (compute-error-message c))))
  (:documentation "A CONFINEMENT field (or a launch argument checked against one) is
not acceptable. FIELD is the keyword of the field, VALUE what was given."))

(define-condition confinement-unsupported (sandbox-denied)
  ((backend :initarg :backend :reader confinement-unsupported-backend :initform nil)
   (missing :initarg :missing :reader confinement-unsupported-missing :initform nil))
  (:report (lambda (c s)
             (format s "~a cannot enforce ~{~(~s~)~^, ~}"
                     (let ((b (confinement-unsupported-backend c)))
                       (if b (class-name (class-of b)) "the backend"))
                     (confinement-unsupported-missing c))))
  (:documentation "The backend cannot enforce every feature the confinement needs
\(CONFINEMENT-REQUIREMENTS minus CONFINEMENT-FEATURES). MISSING lists them in
+CONFINEMENT-FEATURES+ order. Fail closed: nothing ran. Restart USE-VALUE
\(another confinement, checked again)."))

(define-condition confinement-unavailable (compute-error)
  ((backend :initarg :backend :reader confinement-unavailable-backend :initform nil)
   (reason :initarg :reason :reader confinement-unavailable-reason :initform nil))
  (:report (lambda (c s)
             (format s "~a cannot confine here~@[: ~a~]"
                     (let ((b (confinement-unavailable-backend c)))
                       (if b (class-name (class-of b)) "the backend"))
                     (confinement-unavailable-reason c))))
  (:documentation "The backend cannot confine anything on this machine (wrong OS,
missing sandbox-exec / kernel feature, not a confining backend). REASON is a string."))
