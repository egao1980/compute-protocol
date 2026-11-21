(in-package #:compute-protocol/tests)

;;; R4d-0: the CONFINEMENT value, its requirements, capability checks, path
;;; resolution, the reference decision model and the environment.

;;; The value (given code)

(deftest confinement-defaults
  (let ((c (compute-protocol:make-confinement :writable '("/tmp/r4d-area"))))
    (ok (compute-protocol:confinement-p c))
    (ok (equal (list (uiop:ensure-directory-pathname "/tmp/r4d-area"))
               (compute-protocol:confinement-writable c))
        "writable entries are directory pathnames")
    (ok (null (compute-protocol:confinement-readable c)))
    (ok (eq :all (compute-protocol:confinement-read c)))
    (ok (equal (compute-protocol:default-deny-read) (compute-protocol:confinement-deny-read c))
        "deny-read :default = default-deny-read")
    (ok (eq :none (compute-protocol:confinement-network c)) "network is off by default")
    (ok (eq :scrub (compute-protocol:confinement-env-mode c)) "the environment is scrubbed by default")
    (ok (equal compute-protocol:+default-env-allow+ (compute-protocol:confinement-env-allow c)))
    (ok (null (compute-protocol:confinement-env c)))
    (ok (eq :private (compute-protocol:confinement-tmp c)))
    (ok (null (compute-protocol:confinement-cpu-limit c)))
    (ok (null (compute-protocol:confinement-memory-limit c)))
    (ok (null (compute-protocol:confinement-file-size-limit c)))
    (ok (null (compute-protocol:confinement-process-limit c)))
    (ok (null (compute-protocol:confinement-wall-clock c)))))

(deftest confinement-constants
  (ok (equal '(:filesystem :read-system :deny-read :network-none :network-allow :network-ports
               :network-hosts :cpu-limit :memory-limit :file-size-limit :process-limit)
             compute-protocol:+confinement-features+))
  (ok (member "PATH" compute-protocol:+default-env-allow+ :test #'string=))
  (ok (member "LC_*" compute-protocol:+default-env-allow+ :test #'string=))
  (ok (member ".ssh/" compute-protocol:+default-deny-read+ :test #'string=))
  (ok (member "/dev/null" compute-protocol:+device-paths+ :test #'string=))
  (let* ((d (compute-protocol:default-deny-read #p"/home/u/"))
         (names (mapcar #'uiop:native-namestring d)))
    ;; Native namestrings: \home\u\.ssh\ on Windows.
    (ok (member (%ns #p"/home/u/.ssh/") names :test #'string=))
    (ok (member (%ns #p"/home/u/.netrc") names :test #'string=))
    (ok (every #'uiop:absolute-pathname-p d))))

(deftest-parametrize confinement-rejects
    ((field args)
     (:writable '(:writable ("relative/dir")))
     (:writable '(:writable "/not/a/list"))
     (:readable '(:readable (42)))
     (:deny-read '(:deny-read ("")))
     (:read '(:read :wifi))
     (:network '(:network :wifi))
     (:env-mode '(:env-mode :clean))
     (:env-allow '(:env-allow (path)))
     (:env '(:env (("A" . 1))))
     (:tmp '(:tmp :ramdisk))
     (:cpu-limit '(:cpu-limit 0))
     (:memory-limit '(:memory-limit -1))
     (:file-size-limit '(:file-size-limit 1.5))
     (:process-limit '(:process-limit "8"))
     (:wall-clock '(:wall-clock 0)))
  (let ((c (handler-case (progn (apply #'compute-protocol:make-confinement args) nil)
             (compute-protocol:invalid-confinement (e) e))))
    (ok c "invalid-confinement")
    (ok (and c (eq field (compute-protocol:invalid-confinement-field c))) "names the field")
    (ok (typep c 'compute-protocol:compute-error))))

(deftest confinement-accepts-policy-and-limits
  (let* ((policy (compute-protocol:make-sandbox-network-policy
                  :egress (list (compute-protocol:make-egress-rule :host "*" :port 443))))
         (c (compute-protocol:make-confinement :writable '("/w/") :network policy
                                               :cpu-limit 10 :memory-limit 1000000
                                               :file-size-limit 4096 :process-limit 64
                                               :wall-clock 2.5 :deny-read nil :tmp :none)))
    (ok (eq policy (compute-protocol:confinement-network c)))
    (ok (= 10 (compute-protocol:confinement-cpu-limit c)))
    (ok (= 2.5 (compute-protocol:confinement-wall-clock c)))
    (ok (null (compute-protocol:confinement-deny-read c)))
    (ok (eq :none (compute-protocol:confinement-tmp c)))))

(deftest sandbox-spec-carries-confinement
  (let* ((c (compute-protocol:make-confinement :writable '("/w/")))
         (s (compute-protocol:make-sandbox-spec :command '("true") :confinement c)))
    (ok (eq c (compute-protocol:sandbox-spec-confinement s)))
    (ok (null (compute-protocol:sandbox-spec-confinement
               (compute-protocol:make-sandbox-spec :command '("true")))))))

;;; Backends and capabilities (given code)

(deftest confinement-capabilities
  (let ((model (compute-protocol:make-model-confinement-backend))
        (small (compute-protocol:make-model-confinement-backend :features '(:filesystem :network-none)))
        (native (compute-protocol:make-native-process-backend)))
    (ok (typep model 'compute-protocol:confining-backend))
    (ok (equal compute-protocol:+confinement-features+ (compute-protocol:confinement-features model)))
    (ok (compute-protocol:confinement-supports-p small :network-none))
    (ng (compute-protocol:confinement-supports-p small :deny-read))
    (ok (null (compute-protocol:confinement-features native)) "native is trusted-only: no features")
    (ok (compute-protocol:confinement-available-p model))
    (multiple-value-bind (ok reason) (compute-protocol:confinement-available-p native)
      (ng ok)
      (ok (stringp reason)))))

;;; Requirements

(defun %policy (&rest host-ports)
  (compute-protocol:make-sandbox-network-policy
   :egress (loop for (h p) on host-ports by #'cddr
                 collect (compute-protocol:make-egress-rule :host h :port p))))

(deftest-parametrize confinement-requirements
    ((args expected)
     ('() '(:filesystem :deny-read :network-none))
     ('(:deny-read nil) '(:filesystem :network-none))
     ('(:read :system) '(:filesystem :read-system :network-none))
     ('(:network :allow :deny-read nil) '(:filesystem :network-allow))
     ('(:network (:policy "*" 443) :deny-read nil) '(:filesystem :network-ports))
     ('(:network (:policy "example.com" 443) :deny-read nil) '(:filesystem :network-hosts))
     ('(:network (:policy "*" 80 "example.com" 443) :deny-read nil) '(:filesystem :network-hosts))
     ('(:deny-read nil :cpu-limit 1 :memory-limit 2 :file-size-limit 3 :process-limit 4 :wall-clock 5)
      '(:filesystem :network-none :cpu-limit :memory-limit :file-size-limit :process-limit)))
  (let* ((args (loop for (k v) on args by #'cddr
                     append (list k (if (and (consp v) (eq (car v) :policy))
                                        (apply #'%policy (cdr v))
                                        v))))
         (c (apply #'compute-protocol:make-confinement :writable '("/w/") args)))
    (ok (equal expected (compute-protocol:confinement-requirements c)))))

;;; Checks

(deftest check-confinement-accepts
  (let ((c (compute-protocol:make-confinement :writable '("/w/"))))
    (ok (eq c (compute-protocol:check-confinement (compute-protocol:make-model-confinement-backend) c)))))

(deftest check-confinement-unsupported
  (let* ((backend (compute-protocol:make-model-confinement-backend :features '(:filesystem :network-none)))
         (c (compute-protocol:make-confinement :writable '("/w/") :cpu-limit 5))
         (e (handler-case (progn (compute-protocol:check-confinement backend c) nil)
              (compute-protocol:confinement-unsupported (e) e))))
    (ok e "confinement-unsupported")
    (ok (typep e 'compute-protocol:sandbox-denied) "it is a sandbox-denied")
    (ok (and e (equal '(:deny-read :cpu-limit) (compute-protocol:confinement-unsupported-missing e)))
        "missing features in +confinement-features+ order")
    (ok (and e (eq backend (compute-protocol:confinement-unsupported-backend e))))))

(deftest check-confinement-use-value
  (let* ((backend (compute-protocol:make-model-confinement-backend :features '(:filesystem :network-none)))
         (bad (compute-protocol:make-confinement :writable '("/w/")))
         (good (compute-protocol:make-confinement :writable '("/w/") :deny-read nil))
         (offered nil)
         (got (handler-bind ((compute-protocol:confinement-unsupported
                               (lambda (c)
                                 (setf offered (and (find-restart 'use-value c) t))
                                 (use-value good c))))
                (compute-protocol:check-confinement backend bad))))
    (ok offered "use-value is offered")
    (ok (eq good got) "the replacement is checked and returned")))

(deftest check-confinement-use-value-rechecked
  ;; A replacement that is still unsupported signals again.
  (let* ((backend (compute-protocol:make-model-confinement-backend :features '(:filesystem :network-none)))
         (bad (compute-protocol:make-confinement :writable '("/w/")))
         (count 0)
         (final (handler-case
                    (handler-bind ((compute-protocol:confinement-unsupported
                                     (lambda (c)
                                       (when (< (incf count) 2) (use-value bad c)))))
                      (compute-protocol:check-confinement backend bad))
                  (compute-protocol:confinement-unsupported () :refused))))
    (ok (eq :refused final))
    (ok (= 2 count))))

(deftest-parametrize check-confinement-unavailable
    ((backend-fn reason)
     ((lambda () (compute-protocol:make-native-process-backend)) nil)
     ((lambda () (make-instance 'absent-backend)) "absent on purpose"))
  (let* ((backend (funcall backend-fn))
         (e (handler-case
                (progn (compute-protocol:check-confinement
                        backend (compute-protocol:make-confinement :writable '("/w/")))
                       nil)
              (compute-protocol:confinement-unavailable (e) e))))
    (ok e "confinement-unavailable")
    (ok (and e (eq backend (compute-protocol:confinement-unavailable-backend e))))
    (ok (and e (stringp (compute-protocol:confinement-unavailable-reason e))))
    (when reason
      (ok (and e (equal reason (compute-protocol:confinement-unavailable-reason e)))))))

;;; Paths

(defun %ln-s (target link)
  (uiop:run-program (list "ln" "-s" (uiop:native-namestring target) (uiop:native-namestring link))))

(defun %ns (p) (uiop:native-namestring p))

(deftest physical-path-resolves
  (if (not (unix-p))
      (skip "symlinks via ln -s (Unix)")
      (with-temp-tree (root "area/" "outside/inner/" "ro/")
        (write-text (sub root "outside/victim") "original")
        (%ln-s (sub root "outside/") (sub root "area/link"))
        (%ln-s (sub root "outside/inner/") (sub root "area/deep-link"))
        (flet ((pp* (rel) (%ns (compute-protocol:physical-path (concatenate 'string (%ns root) rel)))))
          (ok (equal (%ns (sub root "outside/victim")) (pp* "area/link/victim")) "a symlinked directory")
          (ok (equal (%ns (sub root "outside/")) (pp* "area/../outside")) ".. collapsed; an existing dir in directory form")
          (ok (equal (%ns (sub root "outside/victim")) (pp* "area/deep-link/../victim"))
              ".. after the symlink is resolved, not lexically")
          (ok (equal (%ns (sub root "area/no/such/file.txt")) (pp* "area/no/such/file.txt"))
              "a missing tail is appended as written")
          (ok (equal (%ns (sub root "ro/")) (pp* "./ro/.")))
          (ok (pathnamep (compute-protocol:physical-path (sub root "area/"))) "accepts pathnames")))))

(deftest physical-path-macos-tmp
  (if (not (uiop:os-macosx-p))
      (skip "macOS /tmp → /private/tmp")
      (ok (equal "/private/tmp/" (%ns (compute-protocol:physical-path "/tmp/"))))))

(deftest resolve-confinement-physical
  (if (not (unix-p))
      (skip "symlinks via ln -s (Unix)")
      (with-temp-tree (root "real-area/" "ro/")
        (%ln-s (sub root "real-area/") (sub root "area"))
        (let* ((c (compute-protocol:make-confinement
                   :writable (list (concatenate 'string (%ns root) "area"))
                   :readable (list (sub root "ro/"))
                   :deny-read (list (sub root "secrets/"))
                   :network :allow :cpu-limit 3))
               (r (compute-protocol:resolve-confinement c)))
          (ok (equal (list (%ns (sub root "real-area/")))
                     (mapcar #'%ns (compute-protocol:confinement-writable r))))
          (ok (equal (list (%ns (sub root "ro/"))) (mapcar #'%ns (compute-protocol:confinement-readable r))))
          (ok (equal (list (%ns (sub root "secrets/"))) (mapcar #'%ns (compute-protocol:confinement-deny-read r)))
              "a missing deny-read path stays, under the physical parent")
          (ok (eq :allow (compute-protocol:confinement-network r)))
          (ok (= 3 (compute-protocol:confinement-cpu-limit r)))
          (ok (not (eq c r)) "a new value")
          (ok (equal (mapcar #'%ns (compute-protocol:confinement-writable r))
                     (mapcar #'%ns (compute-protocol:confinement-writable
                                    (compute-protocol:resolve-confinement r))))
              "idempotent")))))

(deftest-parametrize resolve-confinement-bad-writable
    ((what)
     (:missing)
     (:file))
  (with-temp-tree (root)
    (let* ((path (ecase what
                   (:missing (sub root "nope/"))
                   (:file (write-text (sub root "plain") "x"))))
           (e (handler-case
                  (progn (compute-protocol:resolve-confinement
                          (compute-protocol:make-confinement :writable (list path)))
                         nil)
                (compute-protocol:invalid-confinement (e) e))))
      (ok e)
      (ok (and e (eq :writable (compute-protocol:invalid-confinement-field e)))))))

(deftest system-read-paths-shape
  (let ((paths (compute-protocol:system-read-paths)))
    (ok (consp paths))
    (ok (every #'uiop:absolute-pathname-p paths))
    (ok (every #'uiop:directory-pathname-p paths) "directories")
    (when (unix-p)
      (ok (member "/usr/" (mapcar #'%ns paths) :test #'string=)))
    (when (uiop:os-macosx-p)
      (ok (member "/System/" (mapcar #'%ns paths) :test #'string=)))
    #+sbcl
    (let ((runtime-dir (%ns (compute-protocol:physical-path
                             (uiop:pathname-directory-pathname sb-ext:*runtime-pathname*)))))
      (ok (some (lambda (p) (uiop:string-prefix-p (%ns p) runtime-dir)) paths)
          "the running Lisp's runtime directory is readable"))))

;;; The reference decision

(defun %decide-tree ()
  "root/{area/f, area/secret-in-area/, ro/r, ro/r2, outside/victim, outside/inner/, secrets/token}
plus area/link → outside/ (when ln -s works)."
  (let ((root (make-temp-tree "area/secret-in-area/" "ro/" "outside/inner/" "secrets/")))
    (write-text (sub root "area/f") "area")
    (write-text (sub root "ro/r") "ro")
    (write-text (sub root "ro/r2") "ro2")
    (write-text (sub root "outside/victim") "original")
    (write-text (sub root "secrets/token") "secret")
    (when (unix-p) (%ln-s (sub root "outside/") (sub root "area/link")))
    root))

(defun %decide-confinement (root read)
  (compute-protocol:make-confinement
   :writable (list (sub root "area/"))
   :readable (list (sub root "ro/r"))
   :read read
   :deny-read (list (sub root "secrets/") (sub root "area/secret-in-area/"))))

(deftest-parametrize confinement-decide-paths
    ((operation rel read expected)
     :ids ("write-area" "write-area-new-tail" "write-outside" "write-readable" "write-dotdot"
           "write-symlink" "write-denied-inside-area" "read-outside-all" "read-outside-system"
           "read-readable-system" "read-area-system" "read-secret-all" "read-secret-in-area"
           "read-symlink-system" "read-unlisted-sibling-system")
     (:write "area/new" :all :allow)
     (:write "area/sub/deep/new" :all :allow)
     (:write "outside/victim" :all :deny)
     (:write "ro/r" :all :deny)
     (:write "area/../outside/x" :all :deny)
     (:write "area/link/x" :all :deny)
     (:write "area/secret-in-area/x" :all :deny)
     (:read "outside/victim" :all :allow)
     (:read "outside/victim" :system :deny)
     (:read "ro/r" :system :allow)
     (:read "area/f" :system :allow)
     (:read "secrets/token" :all :deny)
     (:read "area/secret-in-area/x" :all :deny)
     (:read "area/link/victim" :system :deny)
     (:read "ro/r2" :system :deny))
  (if (and (search "link" rel) (not (unix-p)))
      (skip "symlinks (Unix)")
      (let ((root (%decide-tree)))
        (unwind-protect
             (ok (eq expected
                     (compute-protocol:confinement-decide
                      (%decide-confinement root read) operation
                      (concatenate 'string (%ns root) rel))))
          (uiop:delete-directory-tree root :validate t)))))

(deftest confinement-decide-tmp-and-devices
  (let ((root (%decide-tree)))
    (unwind-protect
         (let ((c (%decide-confinement root :system))
               (tmp (sub root "tmp/")))
           (ensure-directories-exist tmp)
           (ok (eq :deny (compute-protocol:confinement-decide c :write (sub root "tmp/x"))) "no tmp given")
           (ok (eq :allow (compute-protocol:confinement-decide c :write (sub root "tmp/x") :tmp tmp)))
           (ok (eq :allow (compute-protocol:confinement-decide c :read (sub root "tmp/x") :tmp tmp)))
           (when (unix-p)
             (ok (eq :allow (compute-protocol:confinement-decide c :write "/dev/null")))
             (ok (eq :allow (compute-protocol:confinement-decide c :read "/dev/urandom")))
             (ok (eq :allow (compute-protocol:confinement-decide c :read "/usr/")) "system read paths")
             (ok (eq :deny (compute-protocol:confinement-decide c :write "/usr/x")))))
      (uiop:delete-directory-tree root :validate t))))

(deftest-parametrize confinement-decide-connect
    ((network target expected)
     (:none '("127.0.0.1" . 80) :deny)
     (:allow '("127.0.0.1" . 80) :allow)
     ('(:policy "*" 443) '("example.com" . 443) :allow)
     ('(:policy "*" 443) '("example.com" . 80) :deny)
     ('(:policy "example.com" 443) '("EXAMPLE.com" . 443) :allow)
     ('(:policy "example.com" 443) '("other.org" . 443) :deny))
  (let ((c (compute-protocol:make-confinement
            :writable '("/w/")
            :network (if (consp network) (apply #'%policy (cdr network)) network))))
    (ok (eq expected (compute-protocol:confinement-decide c :connect target)))))

;;; Environment

(defparameter *base-env*
  '(("PATH" . "/bin") ("HOME" . "/h") ("LC_ALL" . "C") ("LC_CTYPE" . "UTF-8")
    ("SECRET" . "x") ("AWS_KEY" . "k")))

(deftest-parametrize confinement-environment
    ((args extra tmp expected)
     :ids ("scrub" "inherit" "overrides" "extra-last" "tmpdir" "custom-allow")
     ('() nil nil
      '(("HOME" . "/h") ("LC_ALL" . "C") ("LC_CTYPE" . "UTF-8") ("PATH" . "/bin")))
     ('(:env-mode :inherit) nil nil
      '(("AWS_KEY" . "k") ("HOME" . "/h") ("LC_ALL" . "C") ("LC_CTYPE" . "UTF-8") ("PATH" . "/bin")
        ("SECRET" . "x")))
     ('(:env (("FOO" . "1") ("PATH" . "/x") ("HOME"))) nil nil
      '(("FOO" . "1") ("LC_ALL" . "C") ("LC_CTYPE" . "UTF-8") ("PATH" . "/x")))
     ('(:env (("FOO" . "1"))) '(("FOO" . "2") ("BAR" . "3")) nil
      '(("BAR" . "3") ("FOO" . "2") ("HOME" . "/h") ("LC_ALL" . "C") ("LC_CTYPE" . "UTF-8")
        ("PATH" . "/bin")))
     ('(:env-allow ("PATH")) nil #p"/t/x/"
      `(("PATH" . "/bin") ("TMPDIR" . ,(%ns #p"/t/x/"))))
     ('(:env-allow ("AWS_*")) nil nil
      '(("AWS_KEY" . "k"))))
  (let ((c (apply #'compute-protocol:make-confinement :writable '("/w/") args)))
    (ok (equal expected
               (compute-protocol:confinement-environment c :base *base-env* :extra extra :tmp tmp)))))

(deftest image-environment-shape
  (let ((env (compute-protocol:image-environment)))
    (ok (every (lambda (e) (and (consp e) (stringp (car e)) (stringp (cdr e)))) env))
    (when (uiop:getenv "PATH")
      (ok (equal (uiop:getenv "PATH") (cdr (assoc "PATH" env :test #'string=)))))))

(deftest confinement-summary-plist
  (let* ((c (compute-protocol:make-confinement :writable '("/w/") :readable '("/r/f")
                                               :deny-read nil :cpu-limit 7))
         (s (compute-protocol:confinement-summary c)))
    (ok (equal (list (%ns #p"/w/")) (getf s :writable)) "native namestrings")
    (ok (equal (list (%ns #p"/r/f")) (getf s :readable)))
    (ok (eq :all (getf s :read)))
    (ok (eq :none (getf s :network)))
    (ok (eq :scrub (getf s :env-mode)))
    (ok (eq :private (getf s :tmp)))
    (ok (equal '(:cpu-limit 7) (getf s :limits)))
    (ok (equal s (read-from-string (with-standard-io-syntax (prin1-to-string s))))
        "prints and reads back")
    (ok (eq :policy (getf (compute-protocol:confinement-summary
                           (compute-protocol:make-confinement :writable '("/w/")
                                                              :network (%policy "*" 1)))
                          :network)))))
