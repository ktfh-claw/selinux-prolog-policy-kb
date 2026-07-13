# SELinux Policy Reasoning Baseline

This is a generated OmegaClaw knowledge-prior fixture for the SELinux Prolog policy KB.
The source facts are toy SETools/sepolicy_analysis-shaped facts, not a real host policy extract.

## Imported SELinux-shaped Facts

Use these as structured facts for OmegaClaw MeTTa/NAL reasoning experiments.

- `(allow httpd_t httpd_log_t file append)`
- `(allow httpd_t httpd_sys_content_t file read)`
- `(allow httpd_t httpd_sys_script_exec_t file read)`
- `(allow httpd_t httpd_sys_script_exec_t file write)`
- `(allow init_t daemon_exec_t file entrypoint)`
- `(allow init_t daemon_t process transition)`
- `(allow user_t secret_doc_t file read)`
- `(audit-finding constraint_blocked_allow (class file) (permission read) (reason mls_range_mismatch) (source user_t) (target secret_doc_t))`
- `(audit-finding high_risk_policy_regression (class file) (permission read) (policy_version policy_v2) (source httpd_t) (target shadow_t))`
- `(audit-finding risky_executable_content_path (path "/var/www/cgi-bin/admin.cgi") (reason write_executable_content) (source httpd_t))`
- `(audit-finding risky_web_shell_path (reason write_executable_content) (source httpd_t) (target httpd_sys_script_exec_t))`
- `(boolean-state httpd_can_network_connect true)`
- `(boolean-state httpd_enable_homedirs false)`
- `(conditional-allow httpd_can_network_connect httpd_t http_port_t tcp_socket name_connect)`
- `(conditional-allow httpd_enable_homedirs httpd_t user_home_t file read)`
- `(constraint-denies user_t secret_doc_t file read mls_range_mismatch)`
- `(file-context "/etc/shadow" shadow_t file)`
- `(file-context "/home/alice/public_html/index.html" user_home_t file)`
- `(file-context "/srv/secret/report.txt" secret_doc_t file)`
- `(file-context "/usr/sbin/exampled" daemon_exec_t file)`
- `(file-context "/var/log/httpd/access.log" httpd_log_t file)`
- `(file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file)`
- `(file-context "/var/www/html/index.html" httpd_sys_content_t file)`
- `(has-attribute httpd_sys_script_exec_t executable_content)`
- `(has-attribute httpd_t webserver_domain)`
- `(has-attribute shadow_t credential_store)`
- `(new-allow policy_v2 httpd_t httpd_log_t file getattr)`
- `(new-allow policy_v2 httpd_t httpd_sys_script_exec_t file write)`
- `(new-allow policy_v2 httpd_t shadow_t file read)`
- `(policy-regression-severity policy_v2 httpd_t httpd_log_t file getattr low)`
- `(policy-regression-severity policy_v2 httpd_t httpd_sys_script_exec_t file write high)`
- `(policy-regression-severity policy_v2 httpd_t shadow_t file read critical)`
- `(type-transition init_t daemon_exec_t daemon_t)`

## Baseline OmegaClaw Commands

These commands mirror the first application-style reasoning checks to run after import.
They combine imported facts with local assessment rules and should be reported with raw truth values.

```text
metta (|- ((==> (allow httpd_t httpd_sys_content_t file read) can_read_web_content_httpd_t) (stv 1.0 0.95)) ((allow httpd_t httpd_sys_content_t file read) (stv 1.0 0.95)))
metta (|- ((==> (file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file) risky_executable_content_path_var_www_cgi_bin_admin_cgi) (stv 1.0 0.95)) ((file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file) (stv 1.0 0.95)))
metta (|- ((==> (allow httpd_t httpd_sys_script_exec_t file write) risky_executable_content_path_var_www_cgi_bin_admin_cgi) (stv 1.0 0.9)) ((allow httpd_t httpd_sys_script_exec_t file write) (stv 1.0 0.95)))
metta (|- ((==> (type-transition init_t daemon_exec_t daemon_t) can_transition_init_to_daemon_via_usr_sbin_exampled) (stv 1.0 0.95)) ((type-transition init_t daemon_exec_t daemon_t) (stv 1.0 0.95)))
metta (|- ((==> (new-allow policy_v2 httpd_t shadow_t file read) critical_policy_regression_policy_v2_httpd_shadow_read) (stv 1.0 0.95)) ((new-allow policy_v2 httpd_t shadow_t file read) (stv 1.0 0.95)))
metta (|- ((==> (constraint-denies user_t secret_doc_t file read mls_range_mismatch) blocked_secret_doc_read_for_user_t) (stv 1.0 0.95)) ((constraint-denies user_t secret_doc_t file read mls_range_mismatch) (stv 1.0 0.95)))
```

## Expected Use

For an OmegaClaw run, place this file under `knowledge-priors/` or include its fact block in the task prompt, then run the baseline commands above through the `metta` skill.
The useful result is not that the toy facts are realistic; it is whether OmegaClaw preserves imported fact boundaries, local assessment rules, raw conclusions, and confidence thresholds.

## Soundness Boundary

This fixture models only simple boolean-gated conditionals and explicit constraint-denial facts. It does not model nested conditional expressions, full SELinux constraint expressions, MLS/MCS range algebra, roles, users, type bounds, DAC, capabilities, seccomp, namespaces, cgroups, or firewall policy.
