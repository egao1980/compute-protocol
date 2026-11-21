(in-package #:compute-protocol/confinement-suite)

(defgeneric confinement-probe (backend confinement ops &key directory)
  (:documentation "Run OPS (see +PROBE-OPERATIONS+) confined by CONFINEMENT on BACKEND
→ one result per op, in order. Default method: CONFINE-COMMAND (DIRECTORY passed on)
of PROBE-COMMAND, ops printed to the probe's stdin, results READ from its stdout
\(*READ-EVAL* NIL), the launch released. Method on MODEL-CONFINEMENT-BACKEND: in this
image, each op decided with CONFINEMENT-DECIDE (the launch's tmp passed as :TMP);
allowed ops are performed for real, :CHILD ops are decided the same way (children
inherit), environment ops read the launch's environment."))

(defmethod confinement-probe (backend confinement ops &key directory)
  (declare (ignore backend confinement ops directory))
  (%r4d0-pending 'confinement-probe))

(defmethod confinement-probe ((backend sc:model-confinement-backend) confinement ops &key directory)
  (declare (ignore confinement ops directory))
  (%r4d0-pending 'confinement-probe/model))
