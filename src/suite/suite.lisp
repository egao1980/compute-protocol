(in-package #:compute-protocol/confinement-suite)

;;; The R4d confinement suite. Every confining backend runs it in its own
;;; tests: (run-confinement-suite backend) → (values failures ran skipped),
;;; and FAILURES must be NIL. A case whose requirements the backend does not
;;; enforce (CONFINEMENT-FEATURES) is skipped, never failed. The laws are
;;; about effects on disk and on the network, not about a mechanism: a write
;;; that is refused must leave the file system unchanged.
;;;
;;; Given: the cases and their requirements, the probe vocabulary, the fixture
;;; class and readers, WITH-SUITE-FIXTURE, PROBE-PROGRAM-PATHNAME,
;;; PROBE-COMMAND. Stubbed (%R4D0-PENDING): MAKE-SUITE-FIXTURE,
;;; RELEASE-SUITE-FIXTURE, SUITE-CONFINEMENT, RUN-CONFINEMENT-SUITE, the
;;; CONFINEMENT-PROBE methods and the probe program's body.

(defun %r4d0-pending (what)
  (error "R4d-0 pending: ~a" what))

(defparameter +suite-cases+
  '((:area-write () "write a new file in the area → :ok, content on disk")
    (:area-tree-ops () "mkdir, rename and delete inside the area → :ok")
    (:outside-create () "create a file outside every writable dir → :denied, absent")
    (:outside-modify () "append to outside/victim → :denied, content unchanged")
    (:outside-delete () "delete outside/victim → :denied, still there")
    (:readonly-write () "write a READABLE file → :denied, unchanged")
    (:readonly-read () "read a READABLE file → :ok")
    (:secret-read (:deny-read) "read secrets/token under READ :ALL + DENY-READ → :denied")
    (:outside-read-all () "READ :ALL: read outside/victim → :ok (skipped when the base is READ :SYSTEM)")
    (:outside-read-system (:read-system) "READ :SYSTEM: outside/victim → :denied; ro and area → :ok")
    (:network-none (:network-none) "connect to the fixture's loopback listener → :denied")
    (:network-allow (:network-allow) "NETWORK :ALLOW: the same connect → :ok")
    (:child-inherits () "a child process: write outside → :denied, write in the area → :ok")
    (:symlink-escape () "area/link → outside: creating it :ok, writing through it → :denied, nothing outside")
    (:dotdot-escape () "write area/../outside/x → :denied, absent")
    (:hardlink-escape () "hardlink outside/victim into the area, append through it → victim unchanged")
    (:rename-out () "rename an area file to outside → :denied, still in the area")
    (:rename-in () "rename outside/victim into the area → :denied, still outside")
    (:env-scrubbed () "a variable not in ENV-ALLOW is gone; CONFINEMENT-ENV is set; PATH kept")
    (:tmpdir-private () "TMPDIR is the launch's private dir, writable; gone after release")
    (:cwd-area () "the default directory is the area"))
  "(name requirements description) per case, in run order. Requirements are features
beyond :FILESYSTEM (and :NETWORK-NONE, which every base confinement needs).")

(defun suite-case-names ()
  (mapcar #'first +suite-cases+))

(defun case-requirements (name)
  "The features case NAME needs beyond the base confinement's."
  (let ((entry (assoc name +suite-cases+)))
    (unless entry (error "unknown confinement suite case ~s" name))
    (second entry)))

(defparameter +probe-operations+
  '(:write :append :read :mkdir :delete :rename :symlink :hardlink
    :connect :getenv :cwd :child)
  "The probe vocabulary. An op is a list; its result:
  (:write path text) (:append path text) (:read path) (:mkdir path) (:delete path)
  (:rename from to) (:symlink target link) (:hardlink target link)
      → :OK, :DENIED (EACCES, EPERM, EROFS, EXDEV) or (:ERROR \"…\") for any other failure
  (:connect host port) → :OK when a TCP connection was made, else :DENIED
  (:getenv name) → (:VALUE string-or-nil)
  (:cwd) → (:VALUE the physical current directory as getcwd(3) gives it, no trailing /)
  (:child op …) → (:CHILD result …): the ops run in a child process the probe spawned
Relative paths are relative to the probe's current directory.")

(defclass suite-fixture ()
  ((root :initarg :root :reader fixture-root
         :documentation "Physical temp directory holding everything below.")
   (area :initarg :area :reader fixture-area :documentation "root/area/ — WRITABLE; holds f and f2.")
   (readonly :initarg :readonly :reader fixture-readonly :documentation "root/ro/ — READABLE; holds r.")
   (outside :initarg :outside :reader fixture-outside
            :documentation "root/outside/ — neither; holds victim = \"original\".")
   (secrets :initarg :secrets :reader fixture-secrets
            :documentation "root/secrets/ — DENY-READ; holds token = \"secret\".")
   (port :initarg :port :reader fixture-port :documentation "A listening TCP port on 127.0.0.1.")
   (listener :initarg :listener :initform nil :accessor %fixture-listener))
  (:documentation "The files and the listener one suite run works on. Fresh per case."))

(defun make-suite-fixture (&key root)
  "Create the fixture under ROOT (default: a new directory in the system temp
directory), physical paths, and open the loopback listener."
  (declare (ignore root))
  (%r4d0-pending 'make-suite-fixture))

(defun release-suite-fixture (fixture)
  "Close the listener and delete ROOT's tree (also files a failed case left)."
  (declare (ignore fixture))
  (%r4d0-pending 'release-suite-fixture))

(defmacro with-suite-fixture ((var &rest keys) &body body)
  `(let ((,var (make-suite-fixture ,@keys)))
     (unwind-protect (progn ,@body)
       (release-suite-fixture ,var))))

(defun suite-confinement (fixture backend &key read network)
  "The case's confinement: WRITABLE (area), READABLE (ro), ENV (STACK_COMPUTE_SUITE_KEEP
= \"kept\"), TMP :PRIVATE, NETWORK NETWORK (default :NONE). READ (default: :ALL with
DENY-READ (secrets) when BACKEND supports :DENY-READ, else :SYSTEM with DENY-READ
\(secrets) — not listed, so unreadable — when it supports :READ-SYSTEM, else
CONFINEMENT-UNSUPPORTED)."
  (declare (ignore fixture backend read network))
  (%r4d0-pending 'suite-confinement))

(defun run-confinement-suite (backend &key (cases (suite-case-names)) root)
  "Run CASES against BACKEND, each on a fresh fixture (under ROOT when given) with
SUITE-CONFINEMENT and CONFINEMENT-PROBE. → (values failures ran skipped): FAILURES a
list of (case . message), RAN and SKIPPED lists of case names in CASES order. The
image's environment gets STACK_COMPUTE_SUITE_SECRET=leak for the run (restored after).
An unavailable backend → CONFINEMENT-UNAVAILABLE."
  (declare (ignore backend cases root))
  (%r4d0-pending 'run-confinement-suite))

;;; The probe program

(defun probe-program-pathname ()
  "The probe script (probe-program.lisp in this system's directory)."
  (asdf:system-relative-pathname "compute-protocol/confinement-suite"
                                 "src/suite/probe-program.lisp"))

(defun probe-command ()
  "argv running the probe with this SBCL: runtime --core core --script probe-program.lisp.
The ops come on stdin as one printed list; the results go to stdout as one list."
  (list (uiop:native-namestring sb-ext:*runtime-pathname*)
        "--core" (uiop:native-namestring sb-ext:*core-pathname*)
        "--script" (uiop:native-namestring (probe-program-pathname))))
