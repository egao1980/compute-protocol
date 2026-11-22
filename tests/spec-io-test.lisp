(in-package #:compute-protocol/tests)

;;; 0.4.0 (egao1980/compute-protocol#10): sandbox-spec :directory / :input,
;;; mount modes, and the optional copy generic functions.

(defun %native () (compute-protocol:make-native-process-backend))

(defun %tmp-dir ()
  (let ((dir (uiop:ensure-directory-pathname
              (merge-pathnames (format nil "compute-spec-io-~36r/" (random (expt 36 8)))
                               (uiop:temporary-directory)))))
    (ensure-directories-exist dir)
    dir))

(deftest spec-directory-and-input-readers
  (let ((spec (compute-protocol:make-sandbox-spec :command '("cat")
                                                  :directory "/tmp"
                                                  :input "hi")))
    (ok (equal "/tmp" (compute-protocol:sandbox-spec-directory spec)))
    (ok (equal "hi" (compute-protocol:sandbox-spec-input spec))))
  (let ((spec (compute-protocol:make-sandbox-spec :command '("true"))))
    (ok (null (compute-protocol:sandbox-spec-directory spec)))
    (ok (null (compute-protocol:sandbox-spec-input spec))))
  (ok (compute-protocol:sandbox-spec-input
       (compute-protocol:coerce-sandbox-spec
        (list :command '("cat")
              :input (make-array 2 :element-type '(unsigned-byte 8)
                                   :initial-contents '(104 105)))))))

(deftest spec-rejects-bad-directory-and-input
  (ok (signals (compute-protocol:make-sandbox-spec :command '("true") :directory 42)
               'compute-protocol:compute-error))
  (ok (signals (compute-protocol:make-sandbox-spec :command '("true") :input 42)
               'compute-protocol:compute-error))
  (ok (signals (compute-protocol:make-sandbox-spec :command '("true") :input #(1 300))
               'compute-protocol:compute-error)))

(deftest parse-mount-designators
  (flet ((parts (m) (multiple-value-list (compute-protocol:parse-mount m))))
    (ok (equal '("/a" "/a" :ro) (parts "/a")))
    (ok (equal (list #p"/a/" #p"/a/" :ro) (parts #p"/a/")))
    (ok (equal '("/a" "/b" :ro) (parts '("/a" "/b"))))
    (ok (equal '("/a" "/b" :ro) (parts '("/a" . "/b"))))
    (ok (equal '("/a" "/b" :rw) (parts '("/a" "/b" :rw))))
    (ok (equal '("/a" "/b" :ro) (parts '("/a" "/b" :ro)))))
  (ok (eq :rw (compute-protocol:mount-mode '("/a" "/b" :rw))))
  (ok (eq :ro (compute-protocol:mount-mode "/a")))
  (ok (equal '(:ro :rw) compute-protocol:+mount-modes+))
  (ok (signals (compute-protocol:parse-mount '("/a" "/b" :wx))
               'compute-protocol:compute-error))
  (ok (signals (compute-protocol:parse-mount 42) 'compute-protocol:compute-error))
  (ok (signals (compute-protocol:make-sandbox-spec :mounts '(("/a" "/b" :exec)))
               'compute-protocol:compute-error)))

(deftest native-directory-sets-cwd
  (if (not (%unix-p))
      (skip "unix pwd")
      (let* ((dir (%tmp-dir))
             (native (string-right-trim "/" (uiop:native-namestring dir))))
        (unwind-protect
             (dolist (limit '(nil 10))
               (testing (format nil "wall-clock ~a" limit)
                 (let ((result (compute-protocol:run-sandboxed
                                (%native)
                                (compute-protocol:make-sandbox-spec
                                 :command '("sh" "-c" "pwd -P")
                                 :directory native
                                 :wall-clock limit))))
                   (ok (zerop (compute-protocol:sandbox-result-exit-code result)))
                   (ok (search (uiop:native-namestring
                                (truename dir))
                               (format nil "~a/"
                                       (string-trim '(#\Newline)
                                                    (compute-protocol:sandbox-result-stdout result))))))))
          (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(deftest native-input-feeds-stdin
  (if (not (%unix-p))
      (skip "unix cat")
      (dolist (limit '(nil 10))
        (testing (format nil "string, wall-clock ~a" limit)
          (let ((result (compute-protocol:run-sandboxed
                         (%native)
                         (compute-protocol:make-sandbox-spec
                          :command '("cat") :input (format nil "héllo~%") :wall-clock limit))))
            (ok (eql 0 (compute-protocol:sandbox-result-exit-code result)))
            (ok (search "llo" (compute-protocol:sandbox-result-stdout result)))))
        (testing (format nil "octets, wall-clock ~a" limit)
          (let ((result (compute-protocol:run-sandboxed
                         (%native)
                         (compute-protocol:make-sandbox-spec
                          :command '("wc" "-c")
                          :input (make-array 3 :element-type '(unsigned-byte 8)
                                               :initial-contents '(1 2 3))
                          :wall-clock limit))))
            (ok (search "3" (compute-protocol:sandbox-result-stdout result))))))))

(deftest native-no-input-sees-eof
  (if (not (%unix-p))
      (skip "unix cat")
      (let ((result (compute-protocol:run-sandboxed
                     (%native)
                     (compute-protocol:make-sandbox-spec :command '("cat") :wall-clock 10))))
        (ok (eql 0 (compute-protocol:sandbox-result-exit-code result)))
        (ok (equal "" (compute-protocol:sandbox-result-stdout result))))))

(deftest copy-defaults-signal-unsupported
  (compute-protocol:with-sandbox (session (%native) '("true"))
    (let ((c (handler-case (compute-protocol:sandbox-copy-to session "/tmp/a" "/b")
               (compute-protocol:sandbox-unsupported (c) c))))
      (ok (typep c 'compute-protocol:sandbox-unsupported))
      (ok (typep c 'compute-protocol:compute-error))
      (ok (eq :copy-to (compute-protocol:sandbox-unsupported-operation c)))
      (ok (typep (compute-protocol:sandbox-unsupported-backend c)
                 'compute-protocol:native-process-backend))
      (ok (search "copy-to" (princ-to-string c))))
    (ok (signals (compute-protocol:sandbox-copy-from session "/b" "/tmp/a")
                 'compute-protocol:sandbox-unsupported))))

(deftest native-directory-and-input-through-process-protocol
  (if (not (%unix-p))
      (skip "unix sh")
      (let ((process-protocol:*process-backend*
              (process-backend-uiop:make-uiop-process-backend))
            (dir (%tmp-dir)))
        (unwind-protect
             (let ((result (compute-protocol:run-sandboxed
                            (%native)
                            (compute-protocol:make-sandbox-spec
                             :command '("sh" "-c" "cat > in.txt && cat in.txt")
                             :directory dir
                             :input "héllo"))))
               (ok (eql 0 (compute-protocol:sandbox-result-exit-code result)))
               (ok (equal "héllo" (compute-protocol:sandbox-result-stdout result)))
               (ok (probe-file (merge-pathnames "in.txt" dir))))
          (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))
