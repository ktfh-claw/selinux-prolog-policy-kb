# SELinux Policy Reasoning Baseline

This is a generated OmegaClaw knowledge-prior fixture for the SELinux Prolog policy KB.
The source facts are toy SETools/sepolicy_analysis-shaped facts, not a real host policy extract.

## Imported SELinux-shaped Facts

Use these as structured facts for OmegaClaw MeTTa/NAL reasoning experiments.

- `(allow ai_agent_t http_port_t tcp_socket name_connect)`
- `(allow ai_agent_t postgresql_port_t tcp_socket name_connect)`
- `(allow ai_agent_t self capability dac_override)`
- `(allow ai_agent_t self capability sys_admin)`
- `(allow ai_agent_t self process dyntransition)`
- `(allow ai_agent_t self process noatsecure)`
- `(allow auditor_limited_t secret_doc_t file read)`
- `(allow auditor_t secret_doc_t file read)`
- `(allow httpd_t httpd_log_t file append)`
- `(allow httpd_t httpd_sys_content_t file read)`
- `(allow httpd_t httpd_sys_script_exec_t file read)`
- `(allow httpd_t httpd_sys_script_exec_t file write)`
- `(allow init_t daemon_exec_t file entrypoint)`
- `(allow init_t daemon_t process transition)`
- `(allow log_shipper_t self capability audit_write)`
- `(allow log_shipper_t self process sigchld)`
- `(allow sandbox_secret_parent_t secret_doc_t file read)`
- `(allow sandbox_secret_reader_t secret_doc_t file read)`
- `(allow sandbox_web_parent_t httpd_sys_content_t file read)`
- `(allow sandbox_web_t httpd_log_t file append)`
- `(allow sandbox_web_t httpd_sys_content_t file read)`
- `(allow user_t secret_doc_t file read)`
- `(audit-finding ai_agent_network_exposure (port 80) (protocol tcp) (reason web_api_baseline) (source ai_agent_t))`
- `(audit-finding ai_agent_resource_limit (reason memory_max_512m) (resource memory) (source ai_agent_t) (unit mebibytes) (value 512))`
- `(audit-finding ai_agent_resource_limit (reason pids_max_64) (resource pids) (source ai_agent_t) (unit count) (value 64))`
- `(audit-finding ai_agent_sensitive_capability (capability dac_override) (reason dac_bypass) (source ai_agent_t))`
- `(audit-finding ai_agent_sensitive_capability (capability sys_admin) (reason kernel_administration) (source ai_agent_t))`
- `(audit-finding ai_agent_sensitive_process_permission (permission dyntransition) (reason arbitrary_domain_transition) (source ai_agent_t))`
- `(audit-finding ai_agent_sensitive_process_permission (permission noatsecure) (reason unsafe_exec_environment) (source ai_agent_t))`
- `(audit-finding ai_agent_syscall_block (reason block_kernel_observability) (source ai_agent_t) (syscall bpf))`
- `(audit-finding ai_agent_syscall_block (reason no_unprivileged_namespace_creation) (source ai_agent_t) (syscall clone3))`
- `(audit-finding constraint_blocked_allow (class file) (permission read) (reason mls_range_mismatch) (source user_t) (target secret_doc_t))`
- `(audit-finding constraint_blocked_allow (class file) (permission read) (reason parent_mls_range_mismatch) (source sandbox_secret_parent_t) (target secret_doc_t))`
- `(audit-finding high_risk_policy_regression (class file) (permission read) (policy_version policy_v2) (source httpd_t) (target shadow_t))`
- `(audit-finding login_sensitive_capability (capability dac_override) (domain ai_agent_t) (login agent_service) (reason dac_bypass))`
- `(audit-finding login_sensitive_capability (capability sys_admin) (domain ai_agent_t) (login agent_service) (reason kernel_administration))`
- `(audit-finding login_sensitive_process_permission (domain ai_agent_t) (login agent_service) (permission dyntransition) (reason arbitrary_domain_transition))`
- `(audit-finding login_sensitive_process_permission (domain ai_agent_t) (login agent_service) (permission noatsecure) (reason unsafe_exec_environment))`
- `(audit-finding mls_blocked_read (reason insufficient_mls_range) (source auditor_limited_t) (target secret_doc_t))`
- `(audit-finding mls_blocked_read (reason insufficient_mls_range) (source user_t) (target secret_doc_t))`
- `(audit-finding risky_executable_content_path (path "/var/www/cgi-bin/admin.cgi") (reason write_executable_content) (source httpd_t))`
- `(audit-finding risky_web_shell_path (reason write_executable_content) (source httpd_t) (target httpd_sys_script_exec_t))`
- `(audit-finding runtime_network_block (port 5432) (protocol tcp) (reason database_egress_block) (source ai_agent_t))`
- `(audit-finding runtime_resource_limit (reason log_memory_cap) (resource memory) (source log_shipper_t) (unit mebibytes) (value 256))`
- `(audit-finding runtime_resource_limit (reason memory_max_512m) (resource memory) (source ai_agent_t) (unit mebibytes) (value 512))`
- `(audit-finding runtime_resource_limit (reason pids_max_64) (resource pids) (source ai_agent_t) (unit count) (value 64))`
- `(audit-finding runtime_syscall_block (reason block_kernel_observability) (source ai_agent_t) (syscall bpf))`
- `(audit-finding runtime_syscall_block (reason no_unprivileged_namespace_creation) (source ai_agent_t) (syscall clone3))`
- `(audit-finding type_bound_blocked_allow (class file) (parent sandbox_secret_parent_t) (permission read) (reason parent_missing_effective_allow) (source sandbox_secret_reader_t) (target secret_doc_t))`
- `(audit-finding type_bound_blocked_allow (class file) (parent sandbox_web_parent_t) (permission append) (reason parent_missing_effective_allow) (source sandbox_web_t) (target httpd_log_t))`
- `(boolean-state httpd_can_network_connect true)`
- `(boolean-state httpd_enable_homedirs false)`
- `(cgroup-assignment ai_agent_t ai_agent_slice)`
- `(cgroup-assignment log_shipper_t log_shipper_slice)`
- `(cgroup-limit ai_agent_slice memory 512 mebibytes memory_max_512m)`
- `(cgroup-limit ai_agent_slice pids 64 count pids_max_64)`
- `(cgroup-limit log_shipper_slice memory 256 mebibytes log_memory_cap)`
- `(conditional-allow httpd_can_network_connect httpd_t http_port_t tcp_socket name_connect)`
- `(conditional-allow httpd_enable_homedirs httpd_t user_home_t file read)`
- `(constraint-denies sandbox_secret_parent_t secret_doc_t file read parent_mls_range_mismatch)`
- `(constraint-denies user_t secret_doc_t file read mls_range_mismatch)`
- `(file-context "/etc/shadow" shadow_t file)`
- `(file-context "/home/alice/public_html/index.html" user_home_t file)`
- `(file-context "/srv/secret/report.txt" secret_doc_t file)`
- `(file-context "/usr/sbin/exampled" daemon_exec_t file)`
- `(file-context "/var/log/httpd/access.log" httpd_log_t file)`
- `(file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file)`
- `(file-context "/var/www/html/index.html" httpd_sys_content_t file)`
- `(firewall-egress-rule ai_agent_t tcp 5432 deny database_egress_block)`
- `(firewall-egress-rule ai_agent_t tcp 80 allow web_api_baseline)`
- `(firewall-egress-rule log_shipper_t tcp 443 allow log_export_baseline)`
- `(has-attribute ai_agent_t ai_agent_domain)`
- `(has-attribute httpd_sys_script_exec_t executable_content)`
- `(has-attribute httpd_t webserver_domain)`
- `(has-attribute shadow_t credential_store)`
- `(login-mapping agent_service agent_u)`
- `(login-mapping alice user_u)`
- `(login-mapping log_shipper log_u)`
- `(mls-range auditor_limited_t s0 s1 (c0))`
- `(mls-range auditor_t s0 s1 (c0 c1))`
- `(mls-range secret_doc_t s1 s1 (c1))`
- `(mls-range user_t s0 s0 (c0))`
- `(new-allow policy_v2 httpd_t httpd_log_t file getattr)`
- `(new-allow policy_v2 httpd_t httpd_sys_script_exec_t file write)`
- `(new-allow policy_v2 httpd_t shadow_t file read)`
- `(policy-regression-severity policy_v2 httpd_t httpd_log_t file getattr low)`
- `(policy-regression-severity policy_v2 httpd_t httpd_sys_script_exec_t file write high)`
- `(policy-regression-severity policy_v2 httpd_t shadow_t file read critical)`
- `(port-context 5432 postgresql_port_t tcp)`
- `(port-context 80 http_port_t tcp)`
- `(role-type agent_r ai_agent_t)`
- `(role-type log_r log_shipper_t)`
- `(role-type user_r user_t)`
- `(seccomp-profile ai_agent_t ai_agent_restricted)`
- `(seccomp-profile log_shipper_t log_shipper_restricted)`
- `(seccomp-rule ai_agent_restricted bpf deny block_kernel_observability)`
- `(seccomp-rule ai_agent_restricted clone3 deny no_unprivileged_namespace_creation)`
- `(seccomp-rule ai_agent_restricted read allow baseline_io)`
- `(seccomp-rule log_shipper_restricted write allow baseline_io)`
- `(selinux-user-role agent_u agent_r)`
- `(selinux-user-role log_u log_r)`
- `(selinux-user-role user_u user_r)`
- `(sensitive-capability dac_override dac_bypass)`
- `(sensitive-capability sys_admin kernel_administration)`
- `(sensitive-process-permission dyntransition arbitrary_domain_transition)`
- `(sensitive-process-permission noatsecure unsafe_exec_environment)`
- `(sensitivity-level s0 0)`
- `(sensitivity-level s1 1)`
- `(type-bound sandbox_secret_reader_t sandbox_secret_parent_t)`
- `(type-bound sandbox_web_t sandbox_web_parent_t)`
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
metta (|- ((==> (mls-range user_t s0 s0 (c0)) mls_blocked_secret_doc_read_for_user_t) (stv 1.0 0.95)) ((mls-range user_t s0 s0 (c0)) (stv 1.0 0.95)))
metta (|- ((==> (port-context 80 http_port_t tcp) can_name_connect_http_port_80) (stv 1.0 0.95)) ((port-context 80 http_port_t tcp) (stv 1.0 0.95)))
metta (|- ((==> (allow ai_agent_t self capability dac_override) ai_agent_has_dac_override) (stv 1.0 0.95)) ((allow ai_agent_t self capability dac_override) (stv 1.0 0.95)))
metta (|- ((==> (allow ai_agent_t self process dyntransition) ai_agent_has_dyntransition) (stv 1.0 0.95)) ((allow ai_agent_t self process dyntransition) (stv 1.0 0.95)))
metta (|- ((==> (firewall-egress-rule ai_agent_t tcp 5432 deny database_egress_block) ai_agent_database_egress_blocked) (stv 1.0 0.95)) ((firewall-egress-rule ai_agent_t tcp 5432 deny database_egress_block) (stv 1.0 0.95)))
metta (|- ((==> (seccomp-rule ai_agent_restricted clone3 deny no_unprivileged_namespace_creation) ai_agent_clone3_blocked_by_seccomp) (stv 1.0 0.95)) ((seccomp-rule ai_agent_restricted clone3 deny no_unprivileged_namespace_creation) (stv 1.0 0.95)))
metta (|- ((==> (cgroup-limit ai_agent_slice pids 64 count pids_max_64) ai_agent_pids_limited_by_cgroup) (stv 1.0 0.95)) ((cgroup-limit ai_agent_slice pids 64 count pids_max_64) (stv 1.0 0.95)))
metta (|- ((==> (login-mapping agent_service agent_u) agent_service_maps_to_sensitive_agent_domain) (stv 1.0 0.95)) ((login-mapping agent_service agent_u) (stv 1.0 0.95)))
```

## Expected Use

For an OmegaClaw run, place this file under `knowledge-priors/` or include its fact block in the task prompt, then run the baseline commands above through the `metta` skill.
The useful result is not that the toy facts are realistic; it is whether OmegaClaw preserves imported fact boundaries, local assessment rules, raw conclusions, and confidence thresholds.

## Soundness Boundary

This fixture models only simple boolean-gated conditionals, explicit constraint-denial facts, resolved file and port contexts, type bounds, login/user/role/type mappings, capability/process-class grants, coarse firewall egress rules, normalized seccomp syscall rules, normalized cgroup resource-limit summaries, and a narrow read-side MLS/MCS range check. It does not model nested conditional expressions, full SELinux constraint expressions, write-side MLS/MCS range algebra, role transitions, DAC outcome checks, namespaces, or full firewall/seccomp/cgroup policy.
