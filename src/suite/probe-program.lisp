;;;; The confinement suite's probe (run as: sbcl --core … --script probe-program.lisp).
;;;; Reads one list of ops (compute-protocol/confinement-suite +PROBE-OPERATIONS+)
;;;; from stdin with *READ-EVAL* NIL and prints one list of results to stdout.
;;;; Only SBCL contribs (sb-posix, sb-bsd-sockets); no ASDF, no init files.
;;;;
;;;; R4d-0 stub: the implementation replaces the body below.

(format *error-output* "R4d-0 pending: probe-program~%")
(sb-ext:exit :code 70 :abort t)
