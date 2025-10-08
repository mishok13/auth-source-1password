;;; auth-source-1password.el --- 1password integration for auth-source -*- lexical-binding: t; -*-

;; Copyright (C) 2023 Dominick LoBraico
;; SPDX-License-Identifier: GPL-3.0-or-later

;; Author: Dominick LoBraico <auth-source-1password@lobrai.co>
;; Created: 2023-04-09
;; URL: https://github.com/dlobraico

;; Package-Requires: ((emacs "24.4"))

;; Version: 0.0.1

;;; Commentary:
;; This package adds 1password support to auth-source by calling the op CLI.
;; Heavily inspired by the auth-source-gopass package
;; (https://github.com/triplem/auth-source-gopass)

;;; Code:
(require 'auth-source)

(defgroup auth-source-1password nil
  "1password auth source settings."
  :group 'auth-source
  :tag "auth-source-1password"
  :prefix "1password-")

(defcustom auth-source-1password-vault "Personal"
  "1Password vault to use when searching for secrets."
  :type 'string
  :group 'auth-source-1password)

(defcustom auth-source-1password-executable "op"
  "Executable used for 1password."
  :type 'string
  :group 'auth-source-1password)

(defcustom auth-source-1password-construct-secret-reference 'auth-source-1password--1password-construct-query-path
  "Function to construct the query path in the 1password store."
  :type 'function
  :group 'auth-source-1password)

(defun auth-source-1password--sanitize-component (component)
  "Sanitize COMPONENT for 1Password CLI secret reference.

Replace invalid characters with underscore and warn if modified.

Supported characters are listed here
https://developer.1password.com/docs/cli/secret-reference-syntax/#supported-characters"
  (let* ((sanitized (replace-regexp-in-string "[^-. a-zA-Z0-9]" "_" component)))
    (if (string-match "^[0-9]" sanitized)
        (concat "_" sanitized)
      sanitized)))

(defun auth-source-1password--1password-construct-query-path (_backend _type host user _port)
  "Construct the full entry-path for the 1password entry for HOST and USER.
Usually starting with the `auth-source-1password-vault', followed
by host and user."
  (string-join
   (list (auth-source-1password--sanitize-component auth-source-1password-vault)
         (auth-source-1password--sanitize-component host)
         (auth-source-1password--sanitize-component user))
   "/"))

(cl-defun auth-source-1password-search (&rest spec
                                              &key backend type host user port
                                              &allow-other-keys)
  "Search 1password for the specified user and host.
SPEC, BACKEND, TYPE, HOST, USER and PORT are required by auth-source."
  (if (executable-find auth-source-1password-executable)
      (let* ((reference (funcall auth-source-1password-construct-secret-reference backend type host user port))
             (got-secret
              (string-trim
               (shell-command-to-string
                (format "%s read op://%s"
                        auth-source-1password-executable
                        (shell-quote-argument reference))))))
        (warn "Reference used '%s'" reference)
        (list (list :user user
                    :secret got-secret)))
    (warn "`auth-source-1password': Could not find executable '%s' to query 1password" auth-source-1password-executable)))

;;;###autoload
(defun auth-source-1password-enable ()
  "Enable the 1password auth source."
  (add-to-list 'auth-sources '1password)
  (auth-source-forget-all-cached))

(defvar auth-source-1password-backend
  (auth-source-backend
   :source "."
   :type 'password-store
   :search-function #'auth-source-1password-search))

(defun auth-source-1password-backend-parse (entry)
  "Create a 1password auth-source backend from ENTRY."
  (when (eq entry '1password)
    (auth-source-backend-parse-parameters entry auth-source-1password-backend)))

(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions #'auth-source-1password-backend-parse)
  (advice-add 'auth-source-backend-parse :before-until #'auth-source-1password-backend-parse))

(provide 'auth-source-1password)

;;; Tests
(eval-when-compile
  (require 'ert))

(ert-deftest auth-source-1password--sanitize-component-valid ()
  "Test sanitization with valid characters."
  (should (string= "example.com" (auth-source-1password--sanitize-component "example.com")))
  (should (string= "user-name" (auth-source-1password--sanitize-component "user-name")))
  (should (string= "host with spaces" (auth-source-1password--sanitize-component "host with spaces")))
  (should (string= "vault123" (auth-source-1password--sanitize-component "vault123"))))

(ert-deftest auth-source-1password--sanitize-component-invalid ()
  "Test sanitization with invalid characters."

  (should (string= "user_name" (auth-source-1password--sanitize-component "user@name")))
  (should (string= "special___chars" (auth-source-1password--sanitize-component "special!@#chars"))))

(ert-deftest auth-source-1password--sanitize-component-leading-number ()
  "Test sanitization with leading numbers."
  (should (string= "_123host" (auth-source-1password--sanitize-component "123host")))
  (should (string= "_456user" (auth-source-1password--sanitize-component "456user"))))

(ert-deftest auth-source-1password--sanitize-component-empty ()
  "Test sanitization with empty string."
  (should (string= "" (auth-source-1password--sanitize-component ""))))

(ert-deftest auth-source-1password--construct-query-path-valid ()
  "Test path construction with valid components."
  (let ((auth-source-1password-vault "Personal"))
    (should (string= "Personal/example.com/user name"
                     (auth-source-1password--1password-construct-query-path nil nil "example.com" "user name" nil)))))

(ert-deftest auth-source-1password--construct-query-path-sanitized ()
  "Test path construction with components needing sanitization."
  (let ((auth-source-1password-vault "Personal%Vault"))
    (should (string= "Personal_Vault/host_with_symbols/user_name"
                     (auth-source-1password--1password-construct-query-path nil nil "host&with#symbols" "user@name" nil)))))

;;; auth-source-1password.el ends here
