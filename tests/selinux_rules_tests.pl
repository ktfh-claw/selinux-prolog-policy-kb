:- begin_tests(selinux_rules).

:- use_module('../src/selinux_rules').

test(direct_allow_read_web_content) :-
    can_access(httpd_t, httpd_sys_content_t, file, read).

test(negative_write_web_content, [fail]) :-
    can_access(httpd_t, httpd_sys_content_t, file, write).

test(derived_read_web_content) :-
    can_read_web_content(httpd_t).

test(risky_web_shell_path) :-
    risky_web_shell_path(httpd_t, httpd_sys_script_exec_t, write_executable_content).

test(domain_transition) :-
    can_domain_transition(init_t, daemon_exec_t, daemon_t).

test(high_risk_policy_regression) :-
    high_risk_policy_regression(policy_v2, httpd_t, shadow_t, file, read).

test(audit_finding_web_shell_shape) :-
    audit_finding(risky_web_shell_path, Finding),
    assertion(Finding.source == httpd_t),
    assertion(Finding.target == httpd_sys_script_exec_t).

test(audit_finding_policy_regression_shape) :-
    audit_finding(high_risk_policy_regression, Finding),
    assertion(Finding.policy_version == policy_v2),
    assertion(Finding.target == shadow_t).

:- end_tests(selinux_rules).
