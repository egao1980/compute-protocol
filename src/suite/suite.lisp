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
;;; PROBE-COMMAND. Implemented (R4d-0a): MAKE-SUITE-FIXTURE,
;;; RELEASE-SUITE-FIXTURE, SUITE-CONFINEMENT, RUN-CONFINEMENT-SUITE and the
;;; per-case ops and checks (%RUN-CASE), the CONFINEMENT-PROBE methods
;;; (probe.lisp) and the probe program (probe-program.lisp).

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

(defun %ns (pathname)
  (uiop:native-namestring pathname))

(defun %random-hex ()
  (format nil "~(~16,'0x~)" (random (expt 16 16) (make-random-state t))))

(defun %suite-root-p (pathname)
  (let ((name (car (last (pathname-directory pathname)))))
    (and (stringp name) (uiop:string-prefix-p "stack-compute-suite-" name))))

(defun %write-file (path text)
  (with-open-file (s path :direction :output :if-exists :supersede :if-does-not-exist :create)
    (write-string text s))
  path)

(defun %open-listener ()
  "A TCP socket listening on 127.0.0.1 (an ephemeral port). Nothing accepts: a connect
completes into the backlog. → (values socket port)."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-bind ((error (lambda (c)
                            (declare (ignore c))
                            (ignore-errors (sb-bsd-sockets:socket-close socket)))))
      (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
      (sb-bsd-sockets:socket-bind socket #(127 0 0 1) 0)
      (sb-bsd-sockets:socket-listen socket 16)
      (values socket (nth-value 1 (sb-bsd-sockets:socket-name socket))))))

(defun make-suite-fixture (&key root)
  "Create the fixture under ROOT (default: a new directory in the system temp
directory), physical paths, and open the loopback listener."
  (let* ((parent (sc:physical-path
                  (uiop:ensure-directory-pathname (or root (uiop:temporary-directory)))))
         (dir (loop for candidate = (merge-pathnames
                                     (format nil "stack-compute-suite-~a/" (%random-hex))
                                     (uiop:ensure-directory-pathname parent))
                    unless (uiop:directory-exists-p candidate)
                      return (ensure-directories-exist candidate)))
         (top (uiop:ensure-directory-pathname (truename dir)))
         (done nil))
    (flet ((subdir (name) (ensure-directories-exist (merge-pathnames name top))))
      (unwind-protect
           (let ((area (subdir "area/"))
                 (readonly (subdir "ro/"))
                 (outside (subdir "outside/"))
                 (secrets (subdir "secrets/")))
             (%write-file (merge-pathnames "f" area) "f")
             (%write-file (merge-pathnames "f2" area) "f2")
             (%write-file (merge-pathnames "r" readonly) "readonly")
             (%write-file (merge-pathnames "victim" outside) "original")
             (%write-file (merge-pathnames "token" secrets) "secret")
             (multiple-value-bind (listener port) (%open-listener)
               (prog1 (make-instance 'suite-fixture
                                     :root top :area area :readonly readonly
                                     :outside outside :secrets secrets
                                     :port port :listener listener)
                 (setf done t))))
        (unless done
          (uiop:delete-directory-tree top :validate #'%suite-root-p :if-does-not-exist :ignore))))))

(defun release-suite-fixture (fixture)
  "Close the listener and delete ROOT's tree (also files a failed case left)."
  (let ((listener (%fixture-listener fixture)))
    (when listener
      (setf (%fixture-listener fixture) nil)
      (ignore-errors (sb-bsd-sockets:socket-close listener))))
  (uiop:delete-directory-tree (fixture-root fixture)
                              :validate #'%suite-root-p :if-does-not-exist :ignore)
  t)

(defmacro with-suite-fixture ((var &rest keys) &body body)
  `(let ((,var (make-suite-fixture ,@keys)))
     (unwind-protect (progn ,@body)
       (release-suite-fixture ,var))))

(defun suite-confinement (fixture backend &key read network)
  "The case's confinement: WRITABLE (area), READABLE (ro and the probe program's own
file, physical, so the probe runs under READ :SYSTEM; its directory stays unlisted),
ENV (STACK_COMPUTE_SUITE_KEEP = \"kept\"), TMP :PRIVATE, NETWORK NETWORK (default :NONE). READ (default: :ALL with
DENY-READ (secrets) when BACKEND supports :DENY-READ, else :SYSTEM with DENY-READ
\(secrets) — not listed, so unreadable — when it supports :READ-SYSTEM, else
CONFINEMENT-UNSUPPORTED)."
  (let ((read (or read
                  (cond ((sc:confinement-supports-p backend :deny-read) :all)
                        ((sc:confinement-supports-p backend :read-system) :system)
                        (t (error 'sc:confinement-unsupported
                                  :backend backend :missing '(:deny-read :read-system)))))))
    (sc:make-confinement :writable (list (fixture-area fixture))
                         :readable (list (fixture-readonly fixture)
                                         (sc:physical-path (probe-program-pathname)))
                         :read read
                         :deny-read (list (fixture-secrets fixture))
                         :network (or network :none)
                         :env '(("STACK_COMPUTE_SUITE_KEEP" . "kept"))
                         :tmp :private)))

;;; The cases. Each runs its ops through CONFINEMENT-PROBE on a fresh fixture and
;;; checks the effects; a check returns NIL (kept) or a string (the broken law).
;;; Writes are judged by their effect only (a refusal may be EPERM, EACCES or
;;; EROFS); reads and connects have no effect on disk, so their result is the law.

(defun %results-match-p (pattern results)
  (and (listp results)
       (= (length pattern) (length results))
       (every (lambda (want got)
                (cond ((eq want :_) t)
                      ((and (consp want) (consp got)) (%results-match-p want got))
                      (t (equal want got))))
              pattern results)))

(defun %expect (results pattern)
  (unless (%results-match-p pattern results)
    (format nil "results: want ~s, got ~s" pattern results)))

(defun %file-text (path)
  (and (uiop:file-exists-p path)
       (uiop:read-file-string path)))

(defun %expect-text (path text)
  (let ((got (%file-text path)))
    (unless (equal got text)
      (format nil "~a: want ~s, got ~s" path text got))))

(defun %expect-absent (path)
  (when (or (uiop:file-exists-p path)
            (uiop:directory-exists-p (uiop:ensure-directory-pathname path)))
    (format nil "~a: should not exist" path)))

(defun %expect-present (path)
  (unless (uiop:file-exists-p path)
    (format nil "~a: should exist" path)))

(defun %no-writable (confinement)
  "CONFINEMENT without WRITABLE (the start directory is then the private temp dir)."
  (let ((c confinement))
    (sc:make-confinement :writable '()
                         :readable (sc:confinement-readable c)
                         :read (sc:confinement-read c)
                         :deny-read (sc:confinement-deny-read c)
                         :network (sc:confinement-network c)
                         :env-mode (sc:confinement-env-mode c)
                         :env-allow (sc:confinement-env-allow c)
                         :env (sc:confinement-env c)
                         :tmp (sc:confinement-tmp c))))

(defun %check-tmpdir-private (results)
  (destructuring-bind (&optional cwd tmpdir write read) results
    (let ((cwd (and (consp cwd) (second cwd)))
          (tmpdir (and (consp tmpdir) (second tmpdir)))
          (system-tmp (%ns (sc:physical-path (uiop:ensure-directory-pathname
                                              (uiop:temporary-directory))))))
      (cond ((not (and (stringp cwd) (stringp tmpdir)))
             (format nil "results: want (:value dir) for :cwd and TMPDIR, got ~s" results))
            ((not (equal cwd (string-right-trim "/" tmpdir)))
             (format nil "the start directory ~s is not TMPDIR ~s" cwd tmpdir))
            ((not (and (uiop:string-prefix-p system-tmp tmpdir)
                       (search "stack-compute-" tmpdir :start2 (length system-tmp))))
             (format nil "TMPDIR ~s is not a stack-compute- directory under ~s" tmpdir system-tmp))
            ((not (and (eq write :ok) (eq read :ok)))
             (format nil "TMPDIR is not writable: ~s" results))
            ((uiop:directory-exists-p (uiop:parse-native-namestring
                                       (concatenate 'string (string-right-trim "/" tmpdir) "/")))
             (format nil "TMPDIR ~s still exists after the launch was released" tmpdir))))))

(defun %run-case (name fixture backend)
  "Run case NAME on FIXTURE → NIL, or a string saying which law broke."
  (let ((a (%ns (fixture-area fixture)))
        (o (%ns (fixture-outside fixture)))
        (r (%ns (fixture-readonly fixture)))
        (s (%ns (fixture-secrets fixture)))
        (port (fixture-port fixture)))
    (labels ((a (x) (concatenate 'string a x))
             (o (x) (concatenate 'string o x))
             (r (x) (concatenate 'string r x))
             (s (x) (concatenate 'string s x))
             (probe (ops &rest keys)
               (confinement-probe backend (apply #'suite-confinement fixture backend keys) ops))
             (check (&rest messages)
               (find-if #'identity messages)))
      (ecase name
        (:area-write
         (let ((res (probe `((:write ,(a "new.txt") "hello")))))
           (check (%expect res '(:ok)) (%expect-text (a "new.txt") "hello"))))
        (:area-tree-ops
         (let ((res (probe `((:mkdir ,(a "d")) (:rename ,(a "f") ,(a "d/g")) (:delete ,(a "d/g"))))))
           (check (%expect res '(:ok :ok :ok))
                  (%expect-absent (a "f"))
                  (%expect-absent (a "d/g"))
                  (unless (uiop:directory-exists-p (a "d/")) (format nil "~a: should exist" (a "d/"))))))
        (:outside-create
         (probe `((:write ,(o "new") "x")))
         (%expect-absent (o "new")))
        (:outside-modify
         (probe `((:append ,(o "victim") "x")))
         (%expect-text (o "victim") "original"))
        (:outside-delete
         (probe `((:delete ,(o "victim"))))
         (%expect-text (o "victim") "original"))
        (:readonly-write
         (probe `((:write ,(r "r") "x")))
         (%expect-text (r "r") "readonly"))
        (:readonly-read
         (%expect (probe `((:read ,(r "r")))) '(:ok)))
        (:secret-read
         (%expect (probe `((:read ,(s "token")))) '(:denied)))
        (:outside-read-all
         (%expect (probe `((:read ,(o "victim")))) '(:ok)))
        (:outside-read-system
         (%expect (probe `((:read ,(o "victim")) (:read ,(r "r")) (:read ,(a "f"))) :read :system)
                  '(:denied :ok :ok)))
        (:network-none
         (%expect (probe `((:connect "127.0.0.1" ,port))) '(:denied)))
        (:network-allow
         (%expect (probe `((:connect "127.0.0.1" ,port)) :network :allow) '(:ok)))
        (:child-inherits
         (let ((res (probe `((:child (:write ,(o "child") "x") (:write ,(a "child") "y"))))))
           (check (%expect res '((:child :_ :ok)))
                  (%expect-absent (o "child"))
                  (%expect-text (a "child") "y"))))
        (:symlink-escape
         (let ((res (probe `((:symlink ,(string-right-trim "/" o) ,(a "link"))
                             (:write ,(a "link/x") "x")))))
           (check (%expect res '(:ok :_))
                  (%expect-absent (o "x")))))
        (:dotdot-escape
         (probe `((:write ,(a "../outside/x") "x")))
         (%expect-absent (o "x")))
        (:hardlink-escape
         (probe `((:hardlink ,(o "victim") ,(a "hl")) (:append ,(a "hl") "x")))
         (%expect-text (o "victim") "original"))
        (:rename-out
         (probe `((:rename ,(a "f") ,(o "f"))))
         (check (%expect-present (a "f")) (%expect-absent (o "f"))))
        (:rename-in
         (probe `((:rename ,(o "victim") ,(a "v"))))
         (check (%expect-text (o "victim") "original") (%expect-absent (a "v"))))
        (:env-scrubbed
         (let ((res (probe '((:getenv "STACK_COMPUTE_SUITE_SECRET")
                             (:getenv "STACK_COMPUTE_SUITE_KEEP")
                             (:getenv "PATH")))))
           (check (%expect res '((:value nil) (:value "kept") :_))
                  (when (and (uiop:getenv "PATH")
                             (not (and (consp (third res)) (stringp (second (third res))))))
                    (format nil "PATH was not kept: ~s" (third res))))))
        (:tmpdir-private
         (%check-tmpdir-private
          (confinement-probe backend (%no-writable (suite-confinement fixture backend))
                             '((:cwd) (:getenv "TMPDIR") (:write "t.txt" "x") (:read "t.txt")))))
        (:cwd-area
         (%expect (probe '((:cwd))) `((:value ,(string-right-trim "/" a)))))))))

(defun run-confinement-suite (backend &key (cases (suite-case-names)) root)
  "Run CASES against BACKEND, each on a fresh fixture (under ROOT when given) with
SUITE-CONFINEMENT and CONFINEMENT-PROBE. → (values failures ran skipped): FAILURES a
list of (case . message), RAN and SKIPPED lists of case names in CASES order. The
image's environment gets STACK_COMPUTE_SUITE_SECRET=leak for the run (restored after).
An unavailable backend → CONFINEMENT-UNAVAILABLE."
  (multiple-value-bind (available reason) (sc:confinement-available-p backend)
    (unless available
      (error 'sc:confinement-unavailable
             :backend backend
             :reason (if (stringp reason) reason "the backend cannot confine here"))))
  (dolist (name cases) (case-requirements name))   ; an unknown case is the caller's error
  ;; The base confinement must be enforceable: refusals escape here, before any case.
  (let* ((base-read (with-suite-fixture (f :root root)
                      (sc:confinement-read
                       (sc:check-confinement backend (suite-confinement f backend)))))
         (features (sc:confinement-features backend))
         (old (sb-posix:getenv "STACK_COMPUTE_SUITE_SECRET"))
         (failures '())
         (ran '())
         (skipped '()))
    (sb-posix:setenv "STACK_COMPUTE_SUITE_SECRET" "leak" 1)
    (unwind-protect
         (dolist (name cases)
           (if (or (not (subsetp (case-requirements name) features))
                   (and (eq name :outside-read-all) (eq base-read :system)))
               (push name skipped)
               (let ((message (handler-case
                                  (with-suite-fixture (f :root root)
                                    (%run-case name f backend))
                                (error (e)
                                  (format nil "~a: ~a" (type-of e) e)))))
                 (push name ran)
                 (when message
                   (push (cons name message) failures)))))
      (if old
          (sb-posix:setenv "STACK_COMPUTE_SUITE_SECRET" old 1)
          (sb-posix:unsetenv "STACK_COMPUTE_SUITE_SECRET")))
    (values (nreverse failures) (nreverse ran) (nreverse skipped))))

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
