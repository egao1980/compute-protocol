(in-package #:compute-protocol)

;;; R4d-0 — confinement of one command (brief: cl-stack
;;; docs/capabilities/confinement.md). A CONFINEMENT is a value: which
;;; directories a command may write, what it may read, its network, its
;;; environment and its limits. A CONFINING-BACKEND turns it into a launch
;;; (CONFINE-COMMAND → CONFINED-LAUNCH: argv + env + directory) that any
;;; launcher runs — process-protocol, a pty, the supervisor. The kernel
;;; mechanism (Seatbelt, Landlock, namespaces) is the backend's; the policy,
;;; its checks, the environment scrub and the reference decision model
;;; (CONFINEMENT-DECIDE) are here.
;;;
;;; Given: constants, the CONFINEMENT class with its constructor and
;;; validation, DEFAULT-DENY-READ, the backend classes and capability GFs,
;;; the model backend's capability methods and BACKEND-CONFINE-ARGV, the
;;; CONFINED-LAUNCH class, WITH-CONFINED-LAUNCH. Implemented here (R4d-0a):
;;; everything else in this file.

;;; Constants

(defparameter +confinement-features+
  '(:filesystem :read-system :deny-read
    :network-none :network-allow :network-ports :network-hosts
    :cpu-limit :memory-limit :file-size-limit :process-limit)
  "Every feature a confinement can need, in the order CONFINEMENT-REQUIREMENTS
and CONFINEMENT-UNSUPPORTED-MISSING list them.
  :FILESYSTEM     writes only under WRITABLE (every confinement needs it)
  :READ-SYSTEM    READ :SYSTEM — reads only under WRITABLE, READABLE, SYSTEM-READ-PATHS
  :DENY-READ      READ :ALL with a non-empty DENY-READ (subtracting from read-all)
  :NETWORK-NONE   NETWORK :NONE      :NETWORK-ALLOW  NETWORK :ALLOW
  :NETWORK-PORTS  a policy whose egress rules all have host \"*\" (port allowlist)
  :NETWORK-HOSTS  a policy naming a host (needs a filtering proxy)
  :CPU-LIMIT :MEMORY-LIMIT :FILE-SIZE-LIMIT :PROCESS-LIMIT  the limit is set")

(defparameter +default-env-allow+
  (append '("HOME" "LANG" "LC_*" "LOGNAME" "PATH" "SHELL" "TERM" "TZ" "USER")
          (when (uiop:os-windows-p)
            '("APPDATA" "COMSPEC" "LOCALAPPDATA" "NUMBER_OF_PROCESSORS" "OS" "PATHEXT"
              "PROCESSOR_ARCHITECTURE" "PROGRAMDATA" "SYSTEMDRIVE" "SYSTEMROOT" "TEMP"
              "TMP" "USERPROFILE" "WINDIR")))
  "Names kept by ENV-MODE :SCRUB. A name ending in * keeps every variable with
that prefix. On Windows the names a process needs to start are kept too, and names
compare case-insensitively.")

(defparameter +default-deny-read+
  '(".ssh/" ".aws/" ".gnupg/" ".netrc" ".config/gh/" ".docker/" ".kube/"
    ".azure/" ".config/gcloud/" ".npmrc" ".pypirc" ".git-credentials")
  "Credential locations under the user's home that DENY-READ :DEFAULT hides.")

(defparameter +device-paths+
  '("/dev/null" "/dev/zero" "/dev/random" "/dev/urandom" "/dev/tty")
  "Unix device files every confinement may read and write (no other writes
outside WRITABLE). Ignored on Windows.")

;;; The policy value

(defclass confinement ()
  ((writable :initarg :writable :reader confinement-writable :initform nil
             :documentation "Absolute directory pathnames, read-write with everything below.")
   (readable :initarg :readable :reader confinement-readable :initform nil
             :documentation "Absolute pathnames (files or directories), read-only.")
   (read :initarg :read :reader confinement-read :initform :all
         :documentation ":ALL (everything readable except DENY-READ) or :SYSTEM
\(only WRITABLE, READABLE, SYSTEM-READ-PATHS, the launch tmp and +DEVICE-PATHS+).")
   (deny-read :initarg :deny-read :reader confinement-deny-read :initform nil
              :documentation "Absolute pathnames never read nor written, whatever else allows it.")
   (network :initarg :network :reader confinement-network :initform :none
            :documentation ":NONE, :ALLOW or a SANDBOX-NETWORK-POLICY.")
   (env-mode :initarg :env-mode :reader confinement-env-mode :initform :scrub
             :documentation ":SCRUB (keep ENV-ALLOW names only) or :INHERIT.")
   (env-allow :initarg :env-allow :reader confinement-env-allow :initform nil)
   (env :initarg :env :reader confinement-env :initform nil
        :documentation "Alist (name . value) applied after the scrub; a NIL value unsets.")
   (tmp :initarg :tmp :reader confinement-tmp :initform :private
        :documentation ":PRIVATE (a fresh writable temp directory per launch, TMPDIR points
at it, removed on release), :SHARED (the system temp directory is writable),
:NONE (no temp directory).")
   (cpu-limit :initarg :cpu-limit :reader confinement-cpu-limit :initform nil
              :documentation "CPU seconds, or NIL.")
   (memory-limit :initarg :memory-limit :reader confinement-memory-limit :initform nil
                 :documentation "Bytes of address space, or NIL.")
   (file-size-limit :initarg :file-size-limit :reader confinement-file-size-limit :initform nil
                    :documentation "Bytes per written file, or NIL.")
   (process-limit :initarg :process-limit :reader confinement-process-limit :initform nil
                  :documentation "Processes, or NIL.")
   (wall-clock :initarg :wall-clock :reader confinement-wall-clock :initform nil
               :documentation "Seconds. Enforced by the launcher (RUN-CONFINED, the
supervisor), never a backend feature."))
  (:documentation "What one command may touch. Immutable; build with MAKE-CONFINEMENT."))

(defun confinement-p (object)
  (typep object 'confinement))

(defmethod print-object ((c confinement) stream)
  (print-unreadable-object (c stream :type t)
    (format stream "~{~a~^ ~} read ~(~s~) network ~(~s~)"
            (mapcar #'uiop:native-namestring (confinement-writable c))
            (confinement-read c)
            (let ((n (confinement-network c))) (if (keywordp n) n :policy)))))

(defun %invalid (field value message)
  (error 'invalid-confinement :field field :value value :message message))

(defun %absolute-pathname (field x &key directory)
  "X (string or pathname) as an absolute pathname; DIRECTORY forces directory form."
  (let ((p (etypecase x
             (pathname x)
             (string (if (zerop (length x))
                         (%invalid field x "empty path")
                         (uiop:parse-native-namestring x))))))
    (unless (uiop:absolute-pathname-p p)
      (%invalid field x "not an absolute path"))
    (if directory (uiop:ensure-directory-pathname p) p)))

(defun %path-list (field xs &key directory)
  (unless (listp xs)
    (%invalid field xs "not a list"))
  (mapcar (lambda (x)
            (unless (or (stringp x) (pathnamep x))
              (%invalid field x "not a string or pathname"))
            (%absolute-pathname field x :directory directory))
          xs))

(defun default-deny-read (&optional (home (user-homedir-pathname)))
  "+DEFAULT-DENY-READ+ merged with HOME, as absolute pathnames."
  (mapcar (lambda (rel) (merge-pathnames (uiop:parse-unix-namestring rel) home))
          +default-deny-read+))

(defun %limit (field x &key real)
  (cond ((null x) nil)
        ((and real (realp x) (plusp x)) x)
        ((and (integerp x) (plusp x)) x)
        (t (%invalid field x (if real "not a positive number" "not a positive integer")))))

(defun make-confinement (&key writable readable (read :all) (deny-read :default)
                           (network :none) (env-mode :scrub)
                           (env-allow +default-env-allow+) env (tmp :private)
                           cpu-limit memory-limit file-size-limit process-limit
                           wall-clock)
  "A CONFINEMENT. WRITABLE: directories (read-write). READABLE: paths (read-only).
READ :ALL | :SYSTEM. DENY-READ: paths, or :DEFAULT (DEFAULT-DENY-READ). NETWORK
:NONE | :ALLOW | SANDBOX-NETWORK-POLICY. ENV-MODE :SCRUB | :INHERIT. ENV-ALLOW:
names (\"LC_*\" = prefix). ENV: alist overrides. TMP :PRIVATE | :SHARED | :NONE.
Limits: positive integers (WALL-CLOCK: positive seconds) or NIL. Paths must be
absolute; they are resolved (symlinks) at launch, not here. Anything else →
INVALID-CONFINEMENT naming the field."
  (unless (member read '(:all :system)) (%invalid :read read "want :all or :system"))
  (unless (%valid-sandbox-network-p network)
    (%invalid :network network "want :none, :allow or a sandbox-network-policy"))
  (unless (member env-mode '(:scrub :inherit)) (%invalid :env-mode env-mode "want :scrub or :inherit"))
  (unless (member tmp '(:private :shared :none)) (%invalid :tmp tmp "want :private, :shared or :none"))
  (unless (and (listp env-allow) (every #'stringp env-allow))
    (%invalid :env-allow env-allow "want a list of strings"))
  (unless (and (listp env)
               (every (lambda (e) (and (consp e) (stringp (car e))
                                       (or (null (cdr e)) (stringp (cdr e)))))
                      env))
    (%invalid :env env "want an alist of (name . value-or-nil)"))
  (make-instance 'confinement
                 :writable (%path-list :writable writable :directory t)
                 :readable (%path-list :readable readable)
                 :read read
                 :deny-read (if (eq deny-read :default)
                                (default-deny-read)
                                (%path-list :deny-read deny-read))
                 :network network
                 :env-mode env-mode
                 :env-allow (copy-list env-allow)
                 :env (copy-alist env)
                 :tmp tmp
                 :cpu-limit (%limit :cpu-limit cpu-limit)
                 :memory-limit (%limit :memory-limit memory-limit)
                 :file-size-limit (%limit :file-size-limit file-size-limit)
                 :process-limit (%limit :process-limit process-limit)
                 :wall-clock (%limit :wall-clock wall-clock :real t)))

;;; Backends and their capabilities

(defclass confining-backend (compute-backend) ()
  (:documentation "A backend that confines commands: CONFINEMENT-FEATURES,
CONFINEMENT-AVAILABLE-P and BACKEND-CONFINE-ARGV are its protocol. RUN-SANDBOXED
on it runs the spec's :COMMAND under the spec's :CONFINEMENT."))

(defgeneric confinement-features (backend)
  (:documentation "The subset of +CONFINEMENT-FEATURES+ BACKEND enforces on this machine.
Non-confining backends (native, podman today): NIL.")
  (:method ((backend t)) (declare (ignore backend)) nil))

(defun confinement-supports-p (backend feature)
  "True when BACKEND enforces FEATURE."
  (and (member feature (confinement-features backend)) t))

(defgeneric confinement-available-p (backend)
  (:documentation "→ (values available-p reason). REASON (a string) says why not.")
  (:method ((backend t))
    (declare (ignore backend))
    (values nil "not a confining backend")))

(defgeneric backend-confine-argv (backend confinement argv directory tmp)
  (:documentation "The backend's part of CONFINE-COMMAND. CONFINEMENT is resolved
\(RESOLVE-CONFINEMENT) and already checked; ARGV a list of strings; DIRECTORY the
physical start directory; TMP the launch's private temp directory or NIL.
→ (values argv extra-env cleanups): the argv to exec instead (e.g. a sandbox-exec
prefix), an alist added to the environment last, and a list of functions of no
arguments that RELEASE-CONFINED-LAUNCH calls (temp profile files …)."))

(defclass model-confinement-backend (confining-backend)
  ((features :initarg :features :reader model-backend-features
             :initform (copy-list +confinement-features+)))
  (:documentation "THE REFERENCE MODEL, NOT A SANDBOX. Claims FEATURES and runs the argv
unchanged (adds STACK_COMPUTE_CONFINEMENT=model to the environment). Its use is
tests: launch plumbing, the environment scrub, the supervisor's compute executor,
and the confinement suite's in-process probe, which decides every operation with
CONFINEMENT-DECIDE (see compute-protocol/confinement-suite)."))

(defun make-model-confinement-backend (&key (features +confinement-features+))
  (make-instance 'model-confinement-backend :features (copy-list features)))

(defmethod confinement-features ((backend model-confinement-backend))
  (copy-list (model-backend-features backend)))

(defmethod confinement-available-p ((backend model-confinement-backend))
  (values t nil))

(defmethod backend-confine-argv ((backend model-confinement-backend) confinement argv directory tmp)
  (declare (ignore confinement directory tmp))
  (values (copy-list argv) (list (cons "STACK_COMPUTE_CONFINEMENT" "model")) nil))

;;; The policy, checked and decided

(defun confinement-requirements (confinement)
  "The features CONFINEMENT needs, in +CONFINEMENT-FEATURES+ order: :FILESYSTEM always;
:READ-SYSTEM for READ :SYSTEM; :DENY-READ for READ :ALL with a non-empty DENY-READ;
one network feature (:NETWORK-NONE, :NETWORK-ALLOW, or for a policy :NETWORK-HOSTS
when any rule names a host other than \"*\", else :NETWORK-PORTS); each limit that is set."
  (let* ((c confinement)
         (network (confinement-network c))
         (need (list :filesystem
                     (case network
                       (:none :network-none)
                       (:allow :network-allow)
                       (t (if (some (lambda (rule) (string/= "*" (egress-rule-host rule)))
                                    (sandbox-network-policy-egress network))
                              :network-hosts
                              :network-ports))))))
    (when (eq (confinement-read c) :system) (push :read-system need))
    (when (and (eq (confinement-read c) :all) (confinement-deny-read c)) (push :deny-read need))
    (when (confinement-cpu-limit c) (push :cpu-limit need))
    (when (confinement-memory-limit c) (push :memory-limit need))
    (when (confinement-file-size-limit c) (push :file-size-limit need))
    (when (confinement-process-limit c) (push :process-limit need))
    (remove-if-not (lambda (feature) (member feature need)) +confinement-features+)))

(defun check-confinement (backend confinement)
  "→ the confinement BACKEND will run: CONFINEMENT, or the one a USE-VALUE restart gave
\(checked again). Unavailable backend → CONFINEMENT-UNAVAILABLE. A requirement the
backend lacks → CONFINEMENT-UNSUPPORTED (MISSING in feature order), restart USE-VALUE."
  (multiple-value-bind (available reason) (confinement-available-p backend)
    (unless available
      (error 'confinement-unavailable
             :backend backend
             :reason (if (stringp reason) reason "the backend cannot confine here"))))
  (loop
    (check-type confinement confinement)
    (let* ((features (confinement-features backend))
           (missing (remove-if (lambda (feature) (member feature features))
                               (confinement-requirements confinement))))
      (when (null missing)
        (return confinement))
      (restart-case (error 'confinement-unsupported :backend backend :missing missing)
        (use-value (other)
          :report "Use another confinement (it is checked again)."
          :interactive (lambda ()
                         (format *query-io* "Confinement (evaluated): ")
                         (force-output *query-io*)
                         (list (eval (read *query-io*))))
          (setf confinement other))))))

;;; Physical paths. Unix: a walk over native namestrings from /, each existing
;;; component replaced by its truename (symlinks resolved), .. taken from the
;;; physical parent, and the first missing component and everything after it
;;; appended lexically (nothing below a missing name exists, so a lexical ..
;;; there is exact).

(defun %ns (pathname)
  (uiop:native-namestring pathname))

(defun %dir-ns-p (ns)
  "NS names a directory: it ends in / (or \\ on Windows, where native namestrings use it)."
  (and (plusp (length ns))
       (let ((c (char ns (1- (length ns)))))
         (or (char= c #\/) (and (char= c #\\) (uiop:os-windows-p))))))

(defun %join-ns (acc part)
  (concatenate 'string acc (if (%dir-ns-p acc) "" "/") part))

(defun %parent-ns (acc)
  "The parent directory namestring of the physical namestring ACC."
  (let* ((s (string-right-trim "/" acc))
         (i (position #\/ s :from-end t)))
    (if (or (null i) (zerop i)) "/" (subseq s 0 (1+ i)))))

(defun %existing-physical (ns)
  "The truename namestring of NS (directory form for a directory), or NIL when NS does
not exist or cannot be examined."
  (ignore-errors
   (let ((p (uiop:parse-native-namestring ns)))
     (cond ((uiop:directory-exists-p (uiop:ensure-directory-pathname p))
            (%ns (uiop:ensure-directory-pathname (truename (uiop:ensure-directory-pathname p)))))
           ((uiop:file-exists-p p)
            (%ns (truename p)))))))

(defun %physical-unix (ns)
  (let* ((ns (if (and (plusp (length ns)) (char= #\/ (char ns 0)))
                 ns
                 (%join-ns (%ns (uiop:getcwd)) ns)))
         (acc (or (%existing-physical "/") "/"))
         (tail '())
         (last-part nil))
    (dolist (part (rest (uiop:split-string ns :separator "/")))
      (setf last-part part)
      (cond ((or (string= part "") (string= part ".")))
            ((string= part "..")
             (if tail (pop tail) (setf acc (%parent-ns acc))))
            (tail (push part tail))
            (t (let ((next (%existing-physical (%join-ns acc part))))
                 (if next (setf acc next) (push part tail))))))
    (let* ((out (if tail
                    (format nil "~a~{~a~^/~}" (%join-ns acc "") (reverse tail))
                    acc))
           (p (uiop:parse-native-namestring out)))
      (if (if tail
              (member last-part '("" "." "..") :test #'string=)
              (%dir-ns-p acc))
          (uiop:ensure-directory-pathname p)
          p))))

(defun physical-path (path)
  "PATH (absolute) with every symlink of its longest existing prefix resolved, . and ..
collapsed after resolution, the rest appended as written. An existing directory comes
back in directory form. (/tmp/x on macOS → /private/tmp/x.)"
  (let ((ns (etypecase path
              (pathname (%ns path))
              (string path))))
    (if (uiop:os-windows-p)
        (let ((p (uiop:parse-native-namestring ns)))
          (or (ignore-errors (truename p)) p))
        (%physical-unix ns))))

(defun %physical-directory (path)
  (uiop:ensure-directory-pathname (physical-path path)))

(defun resolve-confinement (confinement)
  "A new CONFINEMENT with WRITABLE, READABLE and DENY-READ physical (PHYSICAL-PATH).
A WRITABLE entry that is not an existing directory → INVALID-CONFINEMENT :WRITABLE.
Other fields are copied. Resolving twice changes nothing."
  (let ((c confinement))
    (make-confinement
     :writable (mapcar (lambda (w)
                         (let ((p (physical-path w)))
                           (unless (uiop:directory-exists-p p)
                             (%invalid :writable w "not an existing directory"))
                           (uiop:ensure-directory-pathname p)))
                       (confinement-writable c))
     :readable (mapcar #'physical-path (confinement-readable c))
     :read (confinement-read c)
     :deny-read (mapcar #'physical-path (confinement-deny-read c))
     :network (confinement-network c)
     :env-mode (confinement-env-mode c)
     :env-allow (confinement-env-allow c)
     :env (confinement-env c)
     :tmp (confinement-tmp c)
     :cpu-limit (confinement-cpu-limit c)
     :memory-limit (confinement-memory-limit c)
     :file-size-limit (confinement-file-size-limit c)
     :process-limit (confinement-process-limit c)
     :wall-clock (confinement-wall-clock c))))

(defun %lisp-directories ()
  "The running Lisp's runtime, core and home directories (pathnames)."
  (remove nil
          (list #+sbcl (uiop:pathname-directory-pathname sb-ext:*runtime-pathname*)
                #+sbcl (uiop:pathname-directory-pathname sb-ext:*core-pathname*)
                ;; SBCL_HOME only names this image's home on SBCL (elsewhere it may be
                ;; inherited from whatever started us).
                #+sbcl (let ((home (uiop:getenv "SBCL_HOME")))
                         (and home (plusp (length home))
                              (uiop:ensure-directory-pathname (uiop:parse-native-namestring home))))
                (let ((f (find-symbol "LISP-IMPLEMENTATION-DIRECTORY" '#:uiop)))
                  (and f (fboundp f) (ignore-errors (funcall f)))))))

(defun %system-candidate (candidate)
  "CANDIDATE (namestring or pathname, maybe logical) as a physical directory pathname,
or NIL when it is not an absolute existing directory other than the root."
  (ignore-errors
   (let* ((p (if (stringp candidate) (uiop:parse-native-namestring candidate) candidate))
          (p (if (typep p 'logical-pathname) (translate-logical-pathname p) p)))
     (when (uiop:absolute-pathname-p p)
       (let ((d (%physical-directory p)))
         (when (and (uiop:directory-exists-p d)
                    (string/= "/" (%ns d)))
           d))))))

(defun system-read-paths ()
  "Physical directories READ :SYSTEM keeps readable on this OS (executables, shared
libraries, system configuration, devices), plus the running Lisp's runtime and core
directories (and SBCL_HOME), so the image itself can be re-spawned confined."
  (let ((candidates
          (append (when (uiop:os-unix-p) '("/usr/" "/bin/" "/sbin/" "/etc/" "/dev/"))
                  (when (uiop:os-macosx-p)
                    '("/System/" "/Library/" "/private/etc/" "/private/var/db/" "/opt/homebrew/"))
                  (when (and (uiop:os-unix-p) (not (uiop:os-macosx-p)))
                    '("/lib/" "/lib64/" "/opt/"))
                  (when (uiop:os-windows-p)
                    (let ((root (uiop:getenv "SYSTEMROOT")))
                      (when (and root (plusp (length root)))
                        (list (uiop:ensure-directory-pathname
                               (uiop:parse-native-namestring root))))))
                  (%lisp-directories)))
        (seen '()))
    (dolist (candidate candidates (nreverse seen))
      (let ((p (%system-candidate candidate)))
        (when p
          (pushnew p seen :test #'string= :key #'%ns))))))

(defun %under-p (target entry)
  "TARGET and ENTRY physical native namestrings: TARGET is ENTRY or below it (a directory
entry ends in /, or \\ on Windows), or equals a file entry. Case-insensitive on Windows."
  (let ((same (if (uiop:os-windows-p) #'string-equal #'string=)))
    (if (%dir-ns-p entry)
        (let ((n (1- (length entry))))
          (or (and (>= (length target) (length entry))
                   (funcall same entry target :end2 (length entry)))
              (and (= (length target) n)
                   (funcall same target entry :end2 n))))
        (funcall same target entry))))

(defun %physical-ns (path)
  (%ns (physical-path path)))

(defun %device-namestrings ()
  (unless (uiop:os-windows-p)
    (mapcar (lambda (d) (or (ignore-errors (%physical-ns d)) d)) +device-paths+)))

(defun %write-namestrings (confinement tmp)
  "Where CONFINEMENT lets a launch with private temp directory TMP write."
  (append (mapcar (lambda (w) (%ns (%physical-directory w))) (confinement-writable confinement))
          (when tmp (list (%ns (%physical-directory tmp))))
          (when (eq (confinement-tmp confinement) :shared)
            (list (%ns (%physical-directory (uiop:temporary-directory)))))
          (%device-namestrings)))

(defun %decide-connect (network host port)
  (cond ((eq network :none) :deny)
        ((eq network :allow) :allow)
        ((some (lambda (rule)
                 (and (eql port (egress-rule-port rule))
                      (or (string= "*" (egress-rule-host rule))
                          (string-equal host (egress-rule-host rule)))))
               (sandbox-network-policy-egress network))
         :allow)
        (t :deny)))

(defun confinement-decide (confinement operation target &key tmp)
  "The reference decision: :ALLOW or :DENY. OPERATION :READ or :WRITE with TARGET a
path (resolved with PHYSICAL-PATH, so symlinks and .. cannot escape), or :CONNECT with
TARGET (host . port). TMP: the launch's private temp directory (writable). Rules:
under DENY-READ → :DENY for read and write; :WRITE → allowed under WRITABLE, TMP, the
system temp directory when TMP is :SHARED, or on +DEVICE-PATHS+; :READ → READ :ALL
allows, READ :SYSTEM allows under WRITABLE, READABLE (the path or below),
SYSTEM-READ-PATHS, TMP and +DEVICE-PATHS+; :CONNECT → :NONE denies, :ALLOW allows, a
policy allows when a rule's port is PORT and its host is \"*\" or HOST (case-insensitive).
\"Under\" means equal to or below a directory entry, or equal to a file entry."
  (ecase operation
    (:connect
     (%decide-connect (confinement-network confinement) (car target) (cdr target)))
    ((:read :write)
     (let ((ns (%physical-ns target)))
       (flet ((under-any (entries) (some (lambda (entry) (%under-p ns entry)) entries)))
         (cond ((under-any (mapcar #'%physical-ns (confinement-deny-read confinement))) :deny)
               ((under-any (%write-namestrings confinement tmp)) :allow)
               ((eq operation :write) :deny)
               ((eq (confinement-read confinement) :all) :allow)
               ((under-any (mapcar #'%physical-ns (confinement-readable confinement))) :allow)
               ((under-any (mapcar #'%ns (system-read-paths))) :allow)
               (t :deny)))))))

;;; The environment

(defun %split-env-entry (entry)
  (let ((i (position #\= entry :start (min 1 (length entry)))))
    (if i
        (cons (subseq entry 0 i) (subseq entry (1+ i)))
        (cons entry ""))))

(defun image-environment ()
  "This image's environment as an alist ((name . value) …): the full environ on SBCL;
elsewhere the +DEFAULT-ENV-ALLOW+ names that are set (prefix entries match nothing)."
  #+sbcl (mapcar #'%split-env-entry (sb-ext:posix-environ))
  #-sbcl (loop for name in +default-env-allow+
               for value = (and (not (find #\* name)) (uiop:getenv name))
               when value collect (cons name value)))

(defun %env-test ()
  (if (uiop:os-windows-p) #'string-equal #'string=))

(defun %env-allowed-p (name allow test)
  (some (lambda (pattern)
          (let ((n (length pattern)))
            (if (and (plusp n) (char= #\* (char pattern (1- n))))
                (and (>= (length name) (1- n))
                     (funcall test pattern name :end1 (1- n) :end2 (1- n)))
                (funcall test pattern name))))
        allow))

(defun %env-put (env entry test)
  "ENV with ENTRY (name . value) applied: replaced by name, a NIL value removes."
  (let ((rest (remove (car entry) env :key #'car :test test)))
    (if (cdr entry)
        (cons (cons (car entry) (cdr entry)) rest)
        rest)))

(defun %env-sorted (env)
  (stable-sort (copy-list env) #'string< :key #'car))

(defun confinement-environment (confinement &key (base (image-environment)) extra tmp)
  "The child's complete environment (an alist sorted by name, STRING<). :INHERIT starts
from BASE; :SCRUB keeps the BASE entries ENV-ALLOW names (case-insensitive on
Windows). Then CONFINEMENT-ENV, then
EXTRA (both alists, NIL value unsets), then TMPDIR = TMP's native namestring when TMP."
  (let ((test (%env-test))
        (inherit (eq (confinement-env-mode confinement) :inherit))
        (allow (confinement-env-allow confinement))
        (env '()))
    (dolist (entry base)
      (when (or inherit (%env-allowed-p (car entry) allow test))
        (setf env (%env-put env entry test))))
    (dolist (entry (confinement-env confinement))
      (setf env (%env-put env entry test)))
    (dolist (entry extra)
      (setf env (%env-put env entry test)))
    (when tmp
      (setf env (%env-put env (cons "TMPDIR" (%ns tmp)) test)))
    (%env-sorted env)))

(defun confinement-summary (confinement)
  "A printable plist for unit files and logs: (:writable (\"/…/\" …) :readable (…)
:read :all :deny-read (…) :network :none|:allow|:policy :env-mode :scrub :tmp :private
:limits (:cpu-limit n …)) — native namestrings, limits only when set (WALL-CLOCK too)."
  (let ((c confinement)
        (network (confinement-network confinement)))
    (list :writable (mapcar #'%ns (confinement-writable c))
          :readable (mapcar #'%ns (confinement-readable c))
          :read (confinement-read c)
          :deny-read (mapcar #'%ns (confinement-deny-read c))
          :network (if (keywordp network) network :policy)
          :env-mode (confinement-env-mode c)
          :tmp (confinement-tmp c)
          :limits (loop for (key reader) in '((:cpu-limit confinement-cpu-limit)
                                              (:memory-limit confinement-memory-limit)
                                              (:file-size-limit confinement-file-size-limit)
                                              (:process-limit confinement-process-limit)
                                              (:wall-clock confinement-wall-clock))
                        for value = (funcall reader c)
                        when value append (list key value)))))

;;; Launches

(defclass confined-launch ()
  ((backend :initarg :backend :reader confined-launch-backend)
   (confinement :initarg :confinement :reader confined-launch-confinement
                :documentation "The resolved confinement that was checked.")
   (argv :initarg :argv :reader confined-launch-argv)
   (env :initarg :env :reader confined-launch-env
        :documentation "The complete environment (alist): launch with :ENV-MODE :REPLACE.")
   (directory :initarg :directory :reader confined-launch-directory)
   (tmp :initarg :tmp :reader confined-launch-tmp :initform nil
        :documentation "The private temp directory (physical), or NIL.")
   (cleanups :initarg :cleanups :initform nil :accessor %launch-cleanups)
   (released :initform nil :accessor %launch-released))
  (:documentation "What to exec: ARGV with exactly ENV in DIRECTORY. Release it after the
process (and its tree) ended: RELEASE-CONFINED-LAUNCH."))

(defun confined-launch-p (object)
  (typep object 'confined-launch))

(defun confined-launch-released-p (launch)
  (and (%launch-released launch) t))

(defun %start-directory (resolved directory)
  "The launch's physical start directory, or :TMP for the private temp directory (not
created yet). Refuses with INVALID-CONFINEMENT :DIRECTORY; creates nothing."
  (flet ((readable (d given)
           (unless (uiop:directory-exists-p d)
             (%invalid :directory given "not an existing directory"))
           (when (eq :deny (confinement-decide resolved :read d))
             (%invalid :directory given "not readable under the confinement"))
           (uiop:ensure-directory-pathname d)))
    (cond (directory
           (readable (physical-path (%absolute-pathname :directory directory :directory t))
                     directory))
          ((confinement-writable resolved)
           (readable (first (confinement-writable resolved)) nil))
          ((eq (confinement-tmp resolved) :private) :tmp)
          (t (readable (%physical-directory (uiop:getcwd)) nil)))))

(defun %private-tmp-p (pathname)
  (let ((name (car (last (pathname-directory pathname)))))
    (and (stringp name) (uiop:string-prefix-p "stack-compute-" name))))

(defun %make-private-tmp ()
  "A fresh stack-compute-<16 lowercase hex>/ under the physical system temp directory."
  (let ((base (%physical-directory (uiop:temporary-directory)))
        (state (make-random-state t)))
    (loop
      (let ((dir (merge-pathnames
                  (format nil "stack-compute-~(~16,'0x~)/" (random (expt 16 16) state))
                  base)))
        (unless (uiop:directory-exists-p dir)
          (multiple-value-bind (path created)
              #+sbcl (ensure-directories-exist dir :mode #o700)
              #-sbcl (ensure-directories-exist dir)
            (declare (ignore path))
            (when created
              (return (uiop:ensure-directory-pathname (truename dir))))))))))

(defun %delete-private-tmp (tmp)
  (when tmp
    (uiop:delete-directory-tree tmp :validate #'%private-tmp-p :if-does-not-exist :ignore)))

(defun confine-command (backend confinement argv &key directory env)
  "CHECK-CONFINEMENT, RESOLVE-CONFINEMENT, make the private temp directory (TMP
:PRIVATE: stack-compute-<16 lowercase hex>/ under the system temp directory,
physical), pick DIRECTORY (default: the
first WRITABLE, else the temp directory, else the current directory; it must be
readable under the confinement, else INVALID-CONFINEMENT :DIRECTORY), build the
environment (CONFINEMENT-ENVIRONMENT with ENV as EXTRA and the temp directory), call
BACKEND-CONFINE-ARGV and add its extra env. → a CONFINED-LAUNCH. A refusal happens
before anything is created on disk."
  (let* ((resolved (resolve-confinement (check-confinement backend confinement)))
         (start (%start-directory resolved directory))
         ;; Every refusal is above this line: from here on things exist on disk.
         (tmp (when (eq (confinement-tmp resolved) :private) (%make-private-tmp)))
         (cleanups '())
         (launch nil))
    (unwind-protect
         (let* ((dir (if (eq start :tmp) tmp start))
                (base-env (confinement-environment resolved :extra env :tmp tmp)))
           (multiple-value-bind (argv2 extra-env backend-cleanups)
               (backend-confine-argv backend resolved (copy-list argv) dir tmp)
             (setf cleanups backend-cleanups)
             (let ((test (%env-test))
                   (full base-env))
               (dolist (entry extra-env)
                 (setf full (%env-put full entry test)))
               (setf launch (make-instance 'confined-launch
                                           :backend backend :confinement resolved
                                           :argv argv2 :env (%env-sorted full)
                                           :directory dir :tmp tmp
                                           :cleanups backend-cleanups)))))
      (unless launch
        ;; A late failure: undo what exists, then let the error propagate.
        (dolist (f cleanups)
          (ignore-errors (funcall f)))
        (ignore-errors (%delete-private-tmp tmp))))
    launch))

(defun release-confined-launch (launch)
  "Run the backend's cleanups and delete the private temp directory tree. → T the first
time, NIL after (idempotent). A failing cleanup does not stop the others."
  (unless (%launch-released launch)
    (setf (%launch-released launch) t)
    (dolist (f (%launch-cleanups launch))
      (ignore-errors (funcall f)))
    (%delete-private-tmp (confined-launch-tmp launch))
    t))

(defmacro with-confined-launch ((var backend confinement argv &rest keys) &body body)
  "Bind VAR to (CONFINE-COMMAND BACKEND CONFINEMENT ARGV . KEYS); release it however BODY exits."
  `(let ((,var (confine-command ,backend ,confinement ,argv ,@keys)))
     (unwind-protect (progn ,@body)
       (release-confined-launch ,var))))

(defun %process-group-p ()
  "T when the process backend can start a process group (and so kill the whole tree)."
  (let ((backend process-protocol:*process-backend*))
    (and backend (process-protocol:backend-supports-p backend :process-group) t)))

(defun run-confined (backend confinement argv &key directory env input wall-clock)
  "Run ARGV confined, to the end, through PROCESS-PROTOCOL:RUN (:ENV-MODE :REPLACE,
:PROCESS-GROUP T where the process backend supports it, output and error output as
strings, INPUT a string or NIL) → SANDBOX-RESULT. WALL-CLOCK (default the
confinement's) exceeded → the process tree is killed and SANDBOX-TIMEOUT is signalled
\(restart ABORT-EXECUTION → NIL). The launch is always released."
  (let ((limit (or wall-clock (confinement-wall-clock confinement))))
    (with-confined-launch (launch backend confinement argv :directory directory :env env)
      (multiple-value-bind (code out err)
          (handler-case
              (process-protocol:run (confined-launch-argv launch)
                                    :env (confined-launch-env launch)
                                    :env-mode :replace
                                    :directory (confined-launch-directory launch)
                                    :process-group (%process-group-p)
                                    :input input
                                    :output :string
                                    :error-output :string
                                    :timeout limit)
            ;; Unwinding out of RUN killed the process (tree).
            (process-protocol:process-timeout-error () :timeout))
        (if (eq code :timeout)
            (restart-case (error 'sandbox-timeout
                                 :limit limit
                                 :message "wall-clock limit exceeded; the process tree was killed")
              (abort-execution ()
                :report "Abort the confined command (RUN-CONFINED returns NIL)."
                nil))
            (make-sandbox-result :exit-code code :stdout out :stderr err))))))

(defmethod run-sandboxed ((backend confining-backend) spec)
  "The spec's :COMMAND under its :CONFINEMENT (RUN-CONFINED, spec :ENV as extra env,
spec :WALL-CLOCK). No confinement → INVALID-CONFINEMENT :CONFINEMENT; :CODE →
SANDBOX-DENIED."
  (let* ((spec (coerce-sandbox-spec spec))
         (confinement (sandbox-spec-confinement spec)))
    (when (sandbox-spec-code spec)
      (error 'sandbox-denied :spec spec :policy :lisp
                             :message "a confining backend runs :command only"))
    (unless confinement
      (error 'invalid-confinement :spec spec :field :confinement :value nil
                                  :message "a confining backend needs a :confinement"))
    (unless (sandbox-spec-command spec)
      (error 'compute-error :spec spec :message "sandbox-spec needs :command"))
    (run-confined backend confinement (%string-list (sandbox-spec-command spec))
                  :env (mapcar (lambda (entry)
                                 (cons (%env-name (car entry))
                                       (and (cdr entry) (princ-to-string (cdr entry)))))
                               (sandbox-spec-env spec))
                  :wall-clock (sandbox-spec-wall-clock spec))))
